#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════╗
# ║              NetPyINT – Scoring Engine                           ║
# ║    Weighted multi-platform threat scoring and level mapping      ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# Owns the single source of truth for how raw OSINT data is translated
# into a composite threat score and a human-readable threat level.
#
# Public surface (imported by netpyint_main.py):
#     compute_threat_level(row) → (str, float)

from config import KEY_PLATFORMS, PLATFORM_TO_FLAG
from utils import parse_json_list

# ── Scoring weights (M6) ─────────────────────────────────────────
_W_ABUSE        = 0.35   # AbuseIPDB — crowd-sourced reports (35%)
_W_VT           = 0.25   # VirusTotal — multi-engine malware scan (25%)
_W_VULN_PTS     = 3      # points per unique CVE (Shodan + InternetDB)
_W_VULN_CAP     = 10     # maximum points from vulnerability component
_W_TAG_PTS      = 2      # points per matching InternetDB threat tag
_W_TAG_CAP      = 5      # maximum points from tag component
_W_GN_MALICIOUS = 10     # GreyNoise: malicious classification bonus
_W_GN_BENIGN    = -5     # GreyNoise: benign classification penalty
_W_OTX_PTS      = 2      # points per OTX pulse
_W_OTX_CAP      = 10     # maximum points from OTX component
_W_PC_TOR       = 5      # ProxyCheck: Tor detection bonus
_W_PC_PROXY_VPN = 3      # ProxyCheck: proxy/VPN detection bonus
_W_PC_SCRAPER   = 2      # ProxyCheck: scraper detection bonus
_W_PC_CAP       = 5      # maximum points from ProxyCheck component

# Score → threat-level boundaries (descending; first match wins).
_LEVEL_THRESHOLDS = [
    ("Critical",  80),
    ("High",      60),
    ("Medium",    40),
    ("Low",       20),
    ("Optional",   5),
    ("No Threat",  0),
]


def compute_threat_level(row):
    # Aggregate OSINT scores from all platforms into a single threat level.
    #
    # This is the core intelligence function. It combines data from multiple
    # sources using a weighted scoring algorithm, then maps the composite
    # score to a human-readable threat category.
    #
    # IMPORTANT — Three-state classification:
    #   1. PENDING:  No platform has successfully scanned this IP yet.
    #                All scanned_* flags are 0 and all data fields are at
    #                their defaults (-1, "", etc.). Freshly loaded IPs from
    #                log parsing start here. IPs where every scan attempt
    #                errored also stay here (errors don't set flags).
    #   2. PARTIAL:  At least one platform has reported data, but not all
    #                KEY platforms (AbuseIPDB, VirusTotal) have.
    #                The score is computed but may be unreliable.
    #   3. FINAL:    All KEY platforms have reported. The composite score
    #                is mapped to a threat category (Critical → No Threat).
    #
    # This prevents freshly loaded IPs from being mislabeled as "Partial"
    # when recalculate runs, and prevents all-errored scans from promoting.
    #
    # Inputs:
    #     row (dict): A dictionary containing the scoring-relevant fields
    #                 from the database. Expected keys:
    #         - abuseipdb_score      (float): 0-100 confidence; -1 if unqueried
    #         - vt_score             (float): 0-100 malicious %; -1 if unqueried
    #         - shodan_vulns         (str):   JSON array of CVE strings, or ""
    #         - internetdb_vulns     (str):   JSON array of CVE strings from InternetDB, or ""
    #         - internetdb_tags      (str):   JSON array of tag strings from InternetDB, or ""
    #         - greynoise_class      (str):   "malicious", "benign", or "unknown"
    #         - otx_pulses           (int):   Pulse count; -1 if unqueried
    #         - total_hits           (int):   Total log hits for this IP
    #         - scanned_abuseipdb    (int):   1 if AbuseIPDB queried successfully (KEY platform)
    #         - scanned_virustotal   (int):   1 if VirusTotal queried successfully (KEY platform)
    #         - scanned_greynoise    (int):   1 if GreyNoise queried successfully
    #
    # Returns:
    #     tuple (str, float):
    #         [0] threat_level (str):  One of "Pending", "Partial", "Critical",
    #                                  "High", "Medium", "Low", "Optional",
    #                                  "No Threat"
    #         [1] score        (float): Composite score 0-100 (computed even
    #                                   for Partial, for informational display)
    #
    # Weighting rationale:
    #     AbuseIPDB (35%) – Highest weight because it reflects real-world
    #         abuse reports from sysadmins, not just automated detection.
    #     VirusTotal (25%) – Strong second signal from 70+ scanning engines.
    #     Shodan (10%) – Presence of known CVEs on attacker infrastructure.
    #     GreyNoise (10%) – Distinguishes targeted attacks from mass-scanning.
    #     OTX (10%) – Links IP to known threat campaigns.
    #     Hit frequency (10%) – Local context: IPs hitting us repeatedly
    #         are more concerning than one-off probes.
    #
    # Score → Level mapping (only applied when all key platforms have reported):
    #     >=80  → Critical   (immediate block recommended)
    #     >=60  → High       (strong evidence of malicious activity)
    #     >=40  → Medium     (moderate suspicion, worth blocking)
    #     >=20  → Low        (minor flags, monitor but don't auto-block)
    #     >=5   → Optional   (negligible risk)
    #     <5    → No Threat  (benign or insufficient data to flag)
    #
    # Usage:
    #     Called from _scan_worker() after all platform queries complete
    #     for an IP, and also from refresh_table() and _on_select() to
    #     display scores in the UI.

    # ── Step 1: Check if ANY platform has reported data ──
    # If no platform has successfully scanned this IP, it stays "Pending".
    # This prevents freshly loaded IPs from being mislabeled as "Partial"
    # when recalculate runs, and prevents all-errored scans from promoting.
    #
    # We check both scan flags AND data fields, because:
    #   - Scan flags are the primary indicator (set only on success)
    #   - Data fields catch cases where a platform returned valid data
    #     that was stored (e.g. OTX with otx_pulses=0 is a real result,
    #     distinct from the -1 default meaning "never queried")
    all_scan_flags = [
        row.get("scanned_abuseipdb", 0),
        row.get("scanned_virustotal", 0),
        row.get("scanned_greynoise", 0),
        row.get("scanned_shodan", 0),
        row.get("scanned_internetdb", 0),
        row.get("scanned_otx", 0),
        row.get("scanned_proxycheck", 0),
        row.get("scanned_ipinfo", 0),
        row.get("scanned_ipapi", 0),
        row.get("scanned_dns", 0),
    ]
    has_any_scan = any(all_scan_flags)  # True if at least one flag == 1

    # Also check data fields for evidence of scanning — some callers may
    # not pass all scanned_* flags but still have scan data present
    if not has_any_scan:
        has_any_scan = (
            row.get("abuseipdb_score", -1) >= 0
            or row.get("vt_score", -1) >= 0
            or row.get("otx_pulses", -1) >= 0
            or row.get("greynoise_class", "") != ""
            or (row.get("shodan_vulns", "") not in ("", "[]"))
            or (row.get("internetdb_vulns", "") not in ("", "[]"))
            or (row.get("internetdb_tags", "") not in ("", "[]"))
            or (row.get("proxycheck_type", "") not in ("", "none"))
        )

    # ── Step 2: Check key platform completeness ──
    # Derive from config so adding a new KEY_PLATFORM requires no change here.
    # Dict of {platform_name: scanned_flag_value} for KEY platforms only
    key_flags = {
        p: row.get(PLATFORM_TO_FLAG[p], 0)
        for p in KEY_PLATFORMS
        if p in PLATFORM_TO_FLAG
    }
    missing_key = [name for name, flag in key_flags.items() if not flag]  # flag == 0 → not scanned
    has_all_key_data = len(missing_key) == 0

    score = 0.0

    # ── AbuseIPDB component ──
    abuse = row.get("abuseipdb_score", -1)
    if abuse >= 0:
        score += abuse * _W_ABUSE

    # ── VirusTotal component ──
    vt = row.get("vt_score", -1)
    if vt >= 0:
        score += vt * _W_VT

    # ── Vulnerability component ──
    # Use the pre-computed deduplicated count when available (stored by
    # update_threat_level after each scan to avoid json.loads() here).
    # Fall back to full JSON parsing for legacy rows (vuln_count == -1).
    vuln_count_cached = row.get("vuln_count", -1)
    if vuln_count_cached is not None and vuln_count_cached >= 0:
        unique_cve_count = vuln_count_cached
    else:
        all_vulns = set()
        for vuln_field in ["shodan_vulns", "internetdb_vulns"]:
            raw = row.get(vuln_field) or ""
            parsed = parse_json_list(raw)
            if not parsed and raw and not raw.startswith("["):
                # Legacy format: comma-separated CVE strings pre-dating JSON storage.
                parsed = [v.strip() for v in raw.split(",") if v.strip()]
            all_vulns.update(v for v in parsed if isinstance(v, str) and v.strip())
        unique_cve_count = len(all_vulns)
    if unique_cve_count:
        score += min(unique_cve_count * _W_VULN_PTS, _W_VULN_CAP)

    # ── InternetDB tags component ──
    tag_count_cached = row.get("tag_count", -1)
    if tag_count_cached is not None and tag_count_cached >= 0:
        matching_tag_count = tag_count_cached
    else:
        threat_tags = {"malware", "c2", "tor", "eol-os", "eol-product"}
        idb_tags = set(parse_json_list(row.get("internetdb_tags")))
        matching_tag_count = len(idb_tags & threat_tags)
    if matching_tag_count:
        score += min(matching_tag_count * _W_TAG_PTS, _W_TAG_CAP)

    # ── GreyNoise classification component ──
    gn_class = row.get("greynoise_class", "")
    if gn_class == "malicious":
        score += _W_GN_MALICIOUS
    elif gn_class == "benign":
        score += _W_GN_BENIGN

    # ── AlienVault OTX pulse component ──
    otx = row.get("otx_pulses", -1)
    if otx > 0:
        score += min(otx * _W_OTX_PTS, _W_OTX_CAP)

    # ── ProxyCheck component ──
    # Purely additive; detects anonymising services. Capped at _W_PC_CAP.
    pc_type = row.get("proxycheck_type", "")
    if pc_type and pc_type != "none":
        pc_types = set(t.strip() for t in pc_type.split(",") if t.strip())
        pc_pts = 0
        if "tor" in pc_types:
            pc_pts += _W_PC_TOR
        if pc_types & {"proxy", "vpn"}:
            pc_pts += _W_PC_PROXY_VPN
        if "scraper" in pc_types:
            pc_pts += _W_PC_SCRAPER
        score += min(pc_pts, _W_PC_CAP)

    # ── Local hit frequency component ──
    hits = row.get("total_hits", 0)
    if hits >= 100:
        score += 10
    elif hits >= 50:
        score += 7
    elif hits >= 20:
        score += 5
    elif hits >= 5:
        score += 3

    # Clamp final score to 0-100 range
    score = max(0, min(100, score))

    # ── Return Pending if no platform has scanned this IP at all ──
    if not has_any_scan:
        return "Pending", score

    # ── Return Partial if key platforms haven't reported yet ──
    if not has_all_key_data:
        return "Partial", score

    # Map composite score to threat category using _LEVEL_THRESHOLDS.
    for level, threshold in _LEVEL_THRESHOLDS:
        if score >= threshold:
            return level, score
    return "No Threat", score


def compute_vuln_tag_counts(row):
    # Extract the deduplicated vuln count and matching tag count from a scoring
    # row so they can be persisted alongside the threat level after each scan.
    # Storing these avoids repeated json.loads() calls during startup loops.
    all_vulns = set()
    for vuln_field in ["shodan_vulns", "internetdb_vulns"]:
        raw = row.get(vuln_field) or ""
        parsed = parse_json_list(raw)
        if not parsed and raw and not raw.startswith("["):
            parsed = [v.strip() for v in raw.split(",") if v.strip()]
        all_vulns.update(v for v in parsed if isinstance(v, str) and v.strip())
    threat_tags = {"malware", "c2", "tor", "eol-os", "eol-product"}
    matching = set(parse_json_list(row.get("internetdb_tags"))) & threat_tags
    return len(all_vulns), len(matching)
