#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════╗
# ║              NetPyINT – Data Insights Engine                     ║
# ║    Pure-computation analytics for the Data Insights tab          ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# Owns all data aggregation and text rendering for the Data Insights tab.
# No Tkinter or DB access — all functions receive list[dict] records
# returned by IPRepository.get_insights_records() and operate purely
# on Python primitives, making them independently testable.
#
# Public surface (imported by netpyint_main.py):
#     build_insights_report(records) → dict
#     render_insights_text(report, filter_label) → str

import itertools
import math
from collections import Counter
from datetime import datetime, timedelta

from config import PLATFORM_TO_FLAG
from utils import parse_json_list, parse_ctime

# Alias so existing internal code reads naturally; single source of truth in config.py.
PLATFORM_SCAN_FLAGS = PLATFORM_TO_FLAG

# Backward-compatible aliases — tests and external callers that used the old private names.
_parse_json_list = parse_json_list
_parse_ctime = parse_ctime

# Threat levels in display/severity order. Used to sort the breakdown section
# so levels always appear Critical → Pending regardless of which are present.
THREAT_ORDER = [
    "Critical", "High", "Medium", "Low",
    "Optional", "No Threat", "Partial", "Pending",
]


# ── Compute functions ──────────────────────────────────────────────────────────

def compute_score_stats(records):
    # Compute descriptive statistics over full_score for the filtered IP set.
    #
    # Inputs:
    #     records (list[dict]): full record dicts from get_insights_records().
    #
    # Returns:
    #     dict with keys:
    #         count_scored  (int):   IPs with a real score (full_score >= 0)
    #         count_unscored(int):   IPs with full_score == -1 (Pending/unscored)
    #         avg           (float|None): mean score of scored IPs
    #         median        (float|None): median score of scored IPs
    #         min           (float|None): lowest score
    #         max           (float|None): highest score
    #         stddev        (float|None): population standard deviation
    #         pct_high_risk (float):  % of scored IPs with score >= 75
    #
    # IPs with full_score == -1 are excluded from all calculations — -1 is the
    # sentinel value meaning "not yet scored", not a real threat score of zero.
    scored = [r["full_score"] for r in records
              if isinstance(r.get("full_score"), (int, float)) and r["full_score"] >= 0]
    total = len(records)
    n = len(scored)
    if n == 0:
        return {
            "count_scored": 0,
            "count_unscored": total,
            "avg": None, "median": None,
            "min": None, "max": None,
            "stddev": None,
            "count_high_risk": 0,
            "pct_high_risk": 0.0,
        }
    avg = sum(scored) / n
    sorted_s = sorted(scored)
    mid = n // 2
    median = sorted_s[mid] if n % 2 else (sorted_s[mid - 1] + sorted_s[mid]) / 2
    # Population std dev — no external lib needed, keeps the module stdlib-only
    stddev = math.sqrt(sum((x - avg) ** 2 for x in scored) / n)
    high_risk = sum(1 for s in scored if s >= 75)
    return {
        "count_scored": n,
        "count_unscored": total - n,
        "avg": round(avg, 1),
        "median": round(median, 1),
        "min": round(min(scored), 1),
        "max": round(max(scored), 1),
        "stddev": round(stddev, 1),
        "count_high_risk": high_risk,
        "pct_high_risk": round(high_risk / max(n, 1) * 100, 1),
    }


def compute_threat_breakdown(records):
    # Count IPs per threat level and compute their percentage of the total set.
    #
    # Inputs:
    #     records (list[dict]): full record dicts from get_insights_records().
    #
    # Returns:
    #     list[dict]: one entry per present threat level, in THREAT_ORDER order.
    #         Each dict has keys: level (str), count (int), pct (float).
    #         Levels with a count of 0 are omitted entirely.
    counts = Counter(r.get("threat_level", "Pending") for r in records)
    total = max(len(records), 1)
    result = []
    for level in THREAT_ORDER:
        c = counts.get(level, 0)
        if c:
            result.append({"level": level, "count": c, "pct": round(c / total * 100, 1)})
    return result


def compute_country_distribution(records, top_n=10):
    # Rank IPs by country and return the top N plus an "others" aggregate.
    #
    # Inputs:
    #     records (list[dict]): full record dicts from get_insights_records().
    #     top_n   (int):        max number of individual countries to return.
    #
    # Returns:
    #     dict with keys:
    #         top          (list[dict]): up to top_n entries, each with
    #                                    country (str), count (int), pct (float).
    #         others_count (int):  total IPs in countries beyond the top N.
    #         others_pct   (float): % those IPs represent of the total.
    #         total        (int):  total IPs that have a non-empty country value.
    #
    # IPs with an empty or None country are excluded from all calculations.
    counts = Counter(r.get("country", "") for r in records if r.get("country"))
    total = sum(counts.values())
    top = counts.most_common(top_n)
    others = total - sum(c for _, c in top)
    return {
        "top": [{"country": cc, "count": c, "pct": round(c / max(total, 1) * 100, 1)}
                for cc, c in top],
        "others_count": others,
        "others_pct": round(others / max(total, 1) * 100, 1),
        "total": total,
    }



def compute_tag_frequency(records):
    # Count how many IPs carry each InternetDB tag across the filtered set.
    #
    # Inputs:
    #     records (list[dict]): full record dicts from get_insights_records().
    #
    # Returns:
    #     list[tuple[str, int]]: (tag, count) pairs in descending count order,
    #         as returned by Counter.most_common().
    #
    # internetdb_tags is a JSON array of strings such as "malware", "c2",
    # "tor", "eol-os", "vpn", "proxy", "cdn", "cloud", "self-signed", etc.
    # Each unique tag occurrence per IP is counted once (not deduplicated within
    # a record, but each IP contributes at most one count per tag).
    counter = Counter()
    for r in records:
        for tag in parse_json_list(r.get("internetdb_tags")):
            if isinstance(tag, str) and tag.strip():
                counter[tag.strip()] += 1
    return counter.most_common()


def compute_proxycheck_types(records):
    # Count how many IPs carry each ProxyCheck classification type.
    #
    # Inputs:
    #     records (list[dict]): full record dicts from get_insights_records().
    #
    # Returns:
    #     list[tuple[str, int]]: (type, count) pairs in descending count order.
    #
    # proxycheck_type is a comma-separated string (not JSON), e.g. "vpn, hosting".
    # Each token is stripped and counted independently across all records.
    counter = Counter()
    for r in records:
        raw = r.get("proxycheck_type", "") or ""
        for t in raw.split(","):
            t = t.strip()
            if t:
                counter[t] += 1
    return counter.most_common()


def compute_platform_coverage(records):
    # Calculate how many IPs have been successfully scanned by each platform.
    #
    # Inputs:
    #     records (list[dict]): full record dicts from get_insights_records().
    #
    # Returns:
    #     list[dict]: one entry per platform in PLATFORM_SCAN_FLAGS order, each with:
    #         platform (str):  display name (e.g. "AbuseIPDB")
    #         scanned  (int):  IPs where the scanned_* flag is 1
    #         total    (int):  total IPs in the filtered set
    #         pct      (float): scanned / total * 100
    #         missing  (int):  total - scanned
    #
    # A scanned_* flag of 1 means the platform was queried and returned a
    # successful response for that IP. 0 means not queried or the query failed.
    #
    # Counts for all 10 platforms are accumulated in a single O(N) pass through
    # records instead of one independent sum() call per platform (10 × O(N) → O(N)).
    total = len(records)
    flags = list(PLATFORM_SCAN_FLAGS.values())
    counts = {f: 0 for f in flags}
    for r in records:
        for f in flags:
            if r.get(f) == 1:
                counts[f] += 1
    result = []
    for platform, flag in PLATFORM_SCAN_FLAGS.items():
        scanned = counts[flag]
        result.append({
            "platform": platform,
            "scanned": scanned,
            "total": total,
            "pct": round(scanned / max(total, 1) * 100, 1),
            "missing": total - scanned,
        })
    return result


def compute_greynoise_summary(records):
    # Summarise GreyNoise classification results across the filtered IP set.
    #
    # Inputs:
    #     records (list[dict]): full record dicts from get_insights_records().
    #
    # Returns:
    #     dict with keys:
    #         malicious    (int): IPs classified as malicious by GreyNoise
    #         benign       (int): IPs classified as benign (known-good scanners)
    #         unknown      (int): IPs queried but not in GreyNoise's dataset
    #         noise_flagged(int): IPs where greynoise_noise == 1 (mass-scanning observed)
    #         riot_flagged (int): IPs where greynoise_riot == 1 (known-good infrastructure)
    #         unqueried    (int): IPs where scanned_greynoise != 1 (not yet queried)
    #
    # Note: noise_flagged and riot_flagged are independent of the class bucket —
    # a benign IP can still be noise_flagged (e.g. a well-known research scanner).
    malicious = benign = unknown = noise = riot = unqueried = 0
    for r in records:
        cls = r.get("greynoise_class", "") or ""
        if r.get("scanned_greynoise") != 1:
            unqueried += 1
        elif cls == "malicious":
            malicious += 1
        elif cls == "benign":
            benign += 1
        else:
            unknown += 1
        if r.get("greynoise_noise") == 1:
            noise += 1
        if r.get("greynoise_riot") == 1:
            riot += 1
    return {
        "malicious": malicious,
        "benign": benign,
        "unknown": unknown,
        "noise_flagged": noise,
        "riot_flagged": riot,
        "unqueried": unqueried,
    }


def _parse_vuln_field(raw):
    # parse_json_list with a legacy comma-separated fallback.
    # Mirrors the fallback in scoring.py so analytics and threat scores
    # agree on CVE counts for DB rows written before JSON encoding was adopted.
    parsed = parse_json_list(raw)
    if not parsed and raw and not raw.startswith("["):
        parsed = [v.strip() for v in raw.split(",") if v.strip()]
    return {v for v in parsed if isinstance(v, str) and v.strip()}


def compute_vulnerability_summary(records):
    # Aggregate CVE and open-port exposure across the filtered IP set.
    #
    # Inputs:
    #     records (list[dict]): full record dicts from get_insights_records().
    #
    # Returns:
    #     dict with keys:
    #         ips_with_vulns     (int): IPs that have at least one CVE
    #         total_cve_instances(int): total CVE occurrences across all IPs
    #                                   (one CVE on 10 IPs counts as 10)
    #         top_cves           (list[tuple[str,int]]): top 10 most common CVE IDs
    #         ips_with_open_ports(int): IPs with at least one port in InternetDB/Shodan
    #         most_common_ports  (list[tuple[int,int]]): top 10 ports by IP count
    #
    # CVEs from internetdb_vulns and shodan_vulns are deduplicated per IP to avoid
    # double-counting the same CVE seen by both Shodan and InternetDB on the same host.
    # Port data from both sources is similarly deduplicated per IP.
    cve_counter = Counter()
    port_counter = Counter()
    ips_with_vulns = 0
    ips_with_ports = 0
    for r in records:
        vulns = (_parse_vuln_field(r.get("internetdb_vulns"))
                 | _parse_vuln_field(r.get("shodan_vulns")))
        if vulns:
            ips_with_vulns += 1
            for v in vulns:
                cve_counter[v] += 1
        ports = (set(parse_json_list(r.get("internetdb_ports")))
                 | set(parse_json_list(r.get("shodan_ports"))))
        if ports:
            ips_with_ports += 1
            for p in ports:
                try:
                    port_counter[int(p)] += 1
                except (TypeError, ValueError):
                    pass
    return {
        "ips_with_vulns": ips_with_vulns,
        "total_cve_instances": sum(cve_counter.values()),
        "top_cves": cve_counter.most_common(10),
        "ips_with_open_ports": ips_with_ports,
        "most_common_ports": port_counter.most_common(10),
    }


def compute_recidivism_metrics(records):
    # Classify IPs by hit frequency to distinguish repeat offenders from probes.
    #
    # Inputs:
    #     records (list[dict]): full record dicts from get_insights_records().
    #
    # Returns:
    #     dict with keys:
    #         high_hit_ips  (int):   IPs with total_hits >= 100 (persistent bots)
    #         medium_hit_ips(int):   IPs with 10 <= total_hits < 100
    #         low_hit_ips   (int):   IPs with total_hits < 10 (one-off probes)
    #         max_hits      (int):   highest hit count in the set
    #         avg_hits      (float): mean hit count across all IPs
    #         avg_new_hits  (float): mean new_hits (hits added since last import)
    #
    # "Recidivism" here refers to IPs that repeatedly hit the firewall — a high
    # total_hits count signals an automated persistent attacker rather than a
    # one-time scan, and warrants higher-priority blocking action.
    if not records:
        return {"high_hit_ips": 0, "medium_hit_ips": 0, "low_hit_ips": 0,
                "max_hits": 0, "avg_hits": 0.0, "avg_new_hits": 0.0}
    hits = [r.get("total_hits", 0) or 0 for r in records]
    new_hits = [r.get("new_hits", 0) or 0 for r in records]
    n = len(records)
    return {
        "high_hit_ips": sum(1 for h in hits if h >= 100),
        "medium_hit_ips": sum(1 for h in hits if 10 <= h < 100),
        "low_hit_ips": sum(1 for h in hits if h < 10),
        "max_hits": max(hits),
        "avg_hits": round(sum(hits) / n, 1),
        "avg_new_hits": round(sum(new_hits) / n, 1),
    }


def compute_protocol_dst_port_summary(records):
    # Aggregate the protocols, destination ports, and firewall rules seen
    # across all log entries associated with the filtered IP set.
    #
    # Inputs:
    #     records (list[dict]): full record dicts from get_insights_records().
    #
    # Returns:
    #     dict with keys:
    #         top_protocols (list[tuple[str,int]]): top 10 protocols by occurrence
    #         top_dst_ports (list[tuple[int,int]]): top 10 destination ports by occurrence
    #         top_log_rules (list[tuple[str,int]]): top 10 firewall rule names by occurrence
    #
    # These columns (protocols, dst_ports, log_rules) are JSON arrays aggregated
    # by the log parser at import time — each IP's list reflects all unique values
    # seen across all firewall log entries for that IP. The counters here sum
    # across all IPs in the filtered set to reveal attack surface patterns.
    proto_counter = Counter()
    dst_counter = Counter()
    rule_counter = Counter()
    for r in records:
        for t in (r.get("protocols") or "").split(","):
            p = t.strip().upper()
            if p:
                proto_counter[p] += 1
        for t in (r.get("dst_ports") or "").split(","):
            port = t.strip()
            if port:
                try:
                    dst_counter[int(port)] += 1
                except (TypeError, ValueError):
                    pass
        for t in (r.get("log_rules") or "").split(","):
            rule = t.strip()
            if rule:
                rule_counter[rule] += 1
    return {
        "top_protocols": proto_counter.most_common(10),
        "top_dst_ports": dst_counter.most_common(10),
        "top_log_rules": rule_counter.most_common(10),
    }


def compute_asn_isp_summary(records, top_n=10):
    # Rank ASNs and ISPs by how many IPs in the filtered set belong to each.
    #
    # Inputs:
    #     records (list[dict]): full record dicts from get_insights_records().
    #     top_n   (int):        max number of ASNs/ISPs to return each.
    #
    # Returns:
    #     dict with keys:
    #         top_asns (list[tuple[str,int]]): (ASN string, count) pairs
    #         top_isps (list[tuple[str,int]]): (ISP name, count) pairs
    #
    # A high concentration of offenders in a single ASN or ISP indicates
    # abuse-tolerant hosting infrastructure and may support block-by-ASN rules.
    # Records with an empty asn or isp value are excluded.
    asn_counter = Counter()
    isp_counter = Counter()
    for r in records:
        asn = (r.get("asn") or "").strip()
        isp = (r.get("isp") or "").strip()
        if asn:
            asn_counter[asn] += 1
        if isp:
            isp_counter[isp] += 1
    return {
        "top_asns": asn_counter.most_common(top_n),
        "top_isps": isp_counter.most_common(top_n),
    }


# ── New compute functions ──────────────────────────────────────────────────────

def compute_platform_correlation(records):
    # Measure agreement and disagreement between the two key OSINT platforms.
    #
    # Inputs:
    #     records (list[dict]): full record dicts from get_insights_records().
    #
    # Returns:
    #     dict with keys:
    #         both_key   (int): IPs where both AbuseIPDB and VirusTotal have been scanned
    #         agree_high (int): IPs where both scores are >= 50 (high-confidence threat)
    #         disagree   (int): IPs where one key score >= 50 and the other <= 10
    #                           (platforms strongly disagree — warrants manual review)
    #         multi3plus (int): IPs scanned by 3 or more platforms in total
    #
    # Platform disagreement is a useful triage signal: an IP flagged heavily by
    # AbuseIPDB but clean on VirusTotal may be a novel attack not yet in AV feeds,
    # while the reverse may indicate automated malware with no human reporting yet.
    both_key = sum(
        1 for r in records
        if r.get("scanned_abuseipdb") == 1 and r.get("scanned_virustotal") == 1
    )
    agree_high = sum(
        1 for r in records
        if r.get("scanned_abuseipdb") == 1 and r.get("scanned_virustotal") == 1
        and (r.get("abuseipdb_score") or -1) >= 50
        and (r.get("vt_score") or -1) >= 50
    )
    disagree = sum(
        1 for r in records
        if ((r.get("abuseipdb_score") or -1) >= 50 and (r.get("vt_score") or -1) <= 10)
        or ((r.get("vt_score") or -1) >= 50 and (r.get("abuseipdb_score") or -1) <= 10)
    )
    multi3plus = sum(
        1 for r in records
        if sum(1 for f in PLATFORM_SCAN_FLAGS.values() if r.get(f) == 1) >= 3
    )
    return {
        "both_key":   both_key,
        "agree_high": agree_high,
        "disagree":   disagree,
        "multi3plus": multi3plus,
    }


def compute_temporal_activity(records):
    # Analyse first_seen and last_seen timestamps to characterise activity age.
    #
    # Inputs:
    #     records (list[dict]): full record dicts from get_insights_records().
    #
    # Returns:
    #     dict with keys:
    #         new_today         (int):        IPs first seen within the last 24 h
    #         new_week          (int):        IPs first seen within the last 7 days
    #         new_month         (int):        IPs first seen within the last 30 days
    #         dwell_avg_days    (float|None): mean(last_seen − first_seen) in days
    #         dwell_max_days    (float|None): longest dwell time seen in the set
    #         oldest_ip         (str|None):   IP address with the earliest first_seen
    #         oldest_first_seen (str|None):   its raw first_seen string
    #         total_with_dates  (int):        IPs where both dates parsed successfully
    #
    # IPs with blank, None, or unparseable timestamps are silently skipped.
    # "today / week / month" windows are relative to datetime.now() at call time.
    now = datetime.now()
    cutoff_day   = now - timedelta(days=1)
    cutoff_week  = now - timedelta(days=7)
    cutoff_month = now - timedelta(days=30)

    new_today = new_week = new_month = 0
    dwell_days = []
    # Collect (ls, fs, ip, raw_first_seen_str) for all records with both dates valid.
    dated = []

    for r in records:
        fs = parse_ctime(r.get("first_seen"))
        ls = parse_ctime(r.get("last_seen"))

        if fs is not None:
            if fs >= cutoff_day:
                new_today += 1
            if fs >= cutoff_week:
                new_week += 1
            if fs >= cutoff_month:
                new_month += 1

        if fs is not None and ls is not None:
            dated.append((ls, fs, r.get("ip"), r.get("first_seen")))
            if ls >= fs:
                dwell_days.append((ls - fs).total_seconds() / 86400)

    # Longest-active: the IP with the most recent last_seen; ties broken by the
    # oldest first_seen.  Single max() with a compound key replaces the previous
    # three-pass approach (max → filter group → min on subset).
    oldest_ip = None
    oldest_first_seen_str = None
    if dated:
        # Primary sort: largest last_seen (most recent). Tie-break: smallest first_seen
        # (oldest start date). Negating the timestamp turns "min first_seen" into a max.
        winner = max(dated, key=lambda e: (e[0], -e[1].timestamp()))
        oldest_ip = winner[2]
        oldest_first_seen_str = winner[3]

    return {
        "new_today":         new_today,
        "new_week":          new_week,
        "new_month":         new_month,
        "dwell_avg_days":    round(sum(dwell_days) / len(dwell_days), 1) if dwell_days else None,
        "dwell_max_days":    round(max(dwell_days), 1) if dwell_days else None,
        "oldest_ip":         oldest_ip,
        "oldest_first_seen": oldest_first_seen_str,
        "total_with_dates":  len(dated),
    }


def compute_src_port_summary(records):
    # Count occurrences of each source port across all records in the filtered set.
    #
    # Inputs:
    #     records (list[dict]): full record dicts from get_insights_records().
    #
    # Returns:
    #     dict with keys:
    #         top_src_ports (list[tuple[int,int]]): top 10 (port, count) pairs
    #
    # src_ports is a JSON array of integers aggregated by the log parser at
    # import time — each IP's list reflects all unique source ports observed
    # across its firewall log entries.
    counter = Counter()
    for r in records:
        for t in (r.get("src_ports") or "").split(","):
            port = t.strip()
            if port:
                try:
                    counter[int(port)] += 1
                except (TypeError, ValueError):
                    pass
    return {"top_src_ports": counter.most_common(10)}


def compute_proxycheck_risk_distribution(records):
    # Bucket IPs by their ProxyCheck risk score (0–100 integer; -1 = unqueried).
    #
    # Inputs:
    #     records (list[dict]): full record dicts from get_insights_records().
    #
    # Returns:
    #     dict with keys:
    #         low       (int):        IPs with proxycheck_risk 0–24
    #         medium    (int):        IPs with proxycheck_risk 25–49
    #         high      (int):        IPs with proxycheck_risk 50–74
    #         critical  (int):        IPs with proxycheck_risk 75–100
    #         unqueried (int):        IPs with proxycheck_risk == -1
    #         avg       (float|None): mean score among queried IPs
    #         median    (float|None): median score among queried IPs
    low = medium = high = critical = unqueried = 0
    scored = []
    for r in records:
        risk = r.get("proxycheck_risk", -1)
        if risk is None or risk < 0:
            unqueried += 1
        elif risk < 25:
            low += 1
            scored.append(risk)
        elif risk < 50:
            medium += 1
            scored.append(risk)
        elif risk < 75:
            high += 1
            scored.append(risk)
        else:
            critical += 1
            scored.append(risk)

    n = len(scored)
    avg = round(sum(scored) / n, 1) if n else None
    median = None
    if n:
        s = sorted(scored)
        mid = n // 2
        median = s[mid] if n % 2 else round((s[mid - 1] + s[mid]) / 2, 1)

    return {
        "low": low, "medium": medium, "high": high, "critical": critical,
        "unqueried": unqueried, "avg": avg, "median": median,
    }


def compute_otx_distribution(records):
    # Bucket IPs by AlienVault OTX pulse count and identify the highest-pulse IPs.
    #
    # Inputs:
    #     records (list[dict]): full record dicts from get_insights_records().
    #
    # Returns:
    #     dict with keys:
    #         zero      (int):       IPs queried with 0 pulses (no known threat intel)
    #         low       (int):       IPs with 1–5 pulses
    #         medium    (int):       IPs with 6–10 pulses
    #         high      (int):       IPs with 10+ pulses
    #         unqueried (int):       IPs where otx_pulses == -1
    #         max_pulses(int):       highest pulse count in the set
    #         top_otx   (list[dict]): top 5 IPs by pulse count, each with
    #                                 {ip, pulses, threat_level, country}
    #
    # A high OTX pulse count means the IP appears in many threat-intelligence
    # campaigns, making it a high-confidence indicator of compromise.
    zero = low = medium = high_ = unqueried = 0
    max_pulses = 0
    candidates = []

    for r in records:
        otx = r.get("otx_pulses", -1)
        if otx is None or otx < 0:
            unqueried += 1
        elif otx == 0:
            zero += 1
        elif otx <= 5:
            low += 1
        elif otx <= 10:
            medium += 1
        else:
            high_ += 1

        if isinstance(otx, int) and otx > 0:
            if otx > max_pulses:
                max_pulses = otx
            candidates.append({"ip": r["ip"], "pulses": otx,
                                "threat_level": r.get("threat_level", ""),
                                "country": r.get("country", "")})

    candidates.sort(key=lambda x: x["pulses"], reverse=True)
    return {
        "zero": zero, "low": low, "medium": medium, "high": high_,
        "unqueried": unqueried, "max_pulses": max_pulses,
        "top_otx": candidates[:5],
    }


def compute_scan_gaps(records, top_n=10):
    # Identify high-hit IPs that are missing scans from the two key platforms.
    #
    # Inputs:
    #     records (list[dict]): full record dicts from get_insights_records().
    #     top_n   (int):        max IPs to return per missing-platform list.
    #
    # Returns:
    #     dict with keys:
    #         missing_abuseipdb     (list[dict]): top_n highest-hit IPs not yet
    #                                            scanned by AbuseIPDB
    #         missing_virustotal    (list[dict]): same for VirusTotal
    #         total_unscanned_any_key (int):      IPs missing at least one key scan
    #
    # Each dict in the lists: {ip, total_hits, threat_level, country}.
    # Sorted by total_hits descending so the most-active unscanned IPs appear first.
    # This section helps prioritise which IPs to scan next for the biggest coverage gain.
    def _gap_list(flag):
        candidates = [
            {"ip": r["ip"], "total_hits": r.get("total_hits", 0) or 0,
             "threat_level": r.get("threat_level", ""), "country": r.get("country", "")}
            for r in records if r.get(flag) != 1
        ]
        candidates.sort(key=lambda x: x["total_hits"], reverse=True)
        return candidates[:top_n]

    missing_abuse = _gap_list("scanned_abuseipdb")
    missing_vt    = _gap_list("scanned_virustotal")
    unscanned_any = sum(
        1 for r in records
        if r.get("scanned_abuseipdb") != 1 or r.get("scanned_virustotal") != 1
    )
    return {
        "missing_abuseipdb":       missing_abuse,
        "missing_virustotal":      missing_vt,
        "total_unscanned_any_key": unscanned_any,
    }


def compute_tag_cooccurrence(records):
    # Analyse which InternetDB tags appear together most frequently on the same IP.
    #
    # Inputs:
    #     records (list[dict]): full record dicts from get_insights_records().
    #
    # Returns:
    #     dict with keys:
    #         multi_tag_ips  (int):                IPs carrying 2 or more tags
    #         top_pairs      (list[tuple[str,int]]): top 10 most common 2-tag combos
    #                                               as "(tag_a, tag_b): count" — tags
    #                                               within each pair are sorted
    #                                               alphabetically for deduplication
    #         max_tags_ip    (str|None):            IP with the most distinct tags
    #         max_tags_count (int):                 number of tags on that IP
    #
    # Tag co-occurrence reveals compound threats: an IP tagged "malware + c2 + tor"
    # is far more dangerous than one tagged with a single low-severity tag.
    pair_counter = Counter()
    multi_tag_ips = 0
    max_tags_count = 0
    max_tags_ip = None

    for r in records:
        tags = [t for t in parse_json_list(r.get("internetdb_tags"))
                if isinstance(t, str) and t.strip()]
        if len(tags) >= 2:
            multi_tag_ips += 1
            # combinations produces every unique 2-tag pair; sorted(set(...)) deduplicates
            # tags and sorts them so ("c2","malware") and ("malware","c2") map to one key.
            for pair in itertools.combinations(sorted(set(tags)), 2):
                pair_counter[pair] += 1
        if len(tags) > max_tags_count:
            max_tags_count = len(tags)
            max_tags_ip = r.get("ip")

    return {
        "multi_tag_ips":  multi_tag_ips,
        "top_pairs":      pair_counter.most_common(10),
        "max_tags_ip":    max_tags_ip,
        "max_tags_count": max_tags_count,
    }


# Known destination port → (service name, risk level) mapping.
# Used by compute_port_service_risk() to classify attacker targeting intent.
_PORT_RISK = {
    3389: ("RDP",         "Critical"),
    445:  ("SMB",         "Critical"),
    1433: ("MSSQL",       "Critical"),
    3306: ("MySQL",       "Critical"),
    5432: ("PostgreSQL",  "Critical"),
    23:   ("Telnet",      "Critical"),
    22:   ("SSH",         "High"),
    21:   ("FTP",         "High"),
    25:   ("SMTP",        "High"),
    110:  ("POP3",        "High"),
    143:  ("IMAP",        "High"),
    80:   ("HTTP",        "Medium"),
    443:  ("HTTPS",       "Medium"),
    8080: ("HTTP-alt",    "Medium"),
    8443: ("HTTPS-alt",   "Medium"),
}


def compute_port_service_risk(records):
    # Map destination ports to known service risk buckets to reveal attack intent.
    #
    # Inputs:
    #     records (list[dict]): full record dicts from get_insights_records().
    #
    # Returns:
    #     dict with keys:
    #         critical_port_ips (int): IPs that targeted at least one Critical-risk port
    #         high_port_ips     (int): IPs that targeted at least one High-risk port
    #         medium_port_ips   (int): IPs that targeted at least one Medium-risk port
    #         top_risky_ports   (list[tuple[str,int]]): top 10 known-service ports
    #                           by IP count, labelled as "3389 (RDP)" etc.
    #
    # Port risk levels (Critical = ransomware/lateral-movement targets,
    # High = remote access/mail, Medium = web). IPs that hit multiple risk levels
    # are counted in each applicable bucket.
    critical_ips = set()
    high_ips = set()
    medium_ips = set()
    risky_counter = Counter()

    for r in records:
        ip = r.get("ip")
        for port in parse_json_list(r.get("dst_ports")):
            try:
                p = int(port)
            except (TypeError, ValueError):
                continue
            if p in _PORT_RISK:
                svc, level = _PORT_RISK[p]
                label = f"{p} ({svc})"
                risky_counter[label] += 1
                if level == "Critical":
                    critical_ips.add(ip)
                elif level == "High":
                    high_ips.add(ip)
                else:
                    medium_ips.add(ip)

    return {
        "critical_port_ips": len(critical_ips),
        "high_port_ips":     len(high_ips),
        "medium_port_ips":   len(medium_ips),
        "top_risky_ports":   risky_counter.most_common(10),
    }


def compute_new_hits_surge(records, top_n=5):
    # Identify IPs whose recent activity makes up a large share of their total hits.
    #
    # Inputs:
    #     records (list[dict]): full record dicts from get_insights_records().
    #     top_n   (int):        max entries in top_new_hits list.
    #
    # Returns:
    #     dict with keys:
    #         surging_ips  (list[dict]): IPs where new_hits / total_hits >= 50%,
    #                                   sorted by new_hits descending. Each dict:
    #                                   {ip, new_hits, total_hits, surge_pct,
    #                                    threat_level, country}
    #         top_new_hits (list[dict]): top_n IPs by raw new_hits count.
    #                                   Each dict: {ip, new_hits, total_hits,
    #                                               threat_level, country}
    #
    # "Surging" IPs have accumulated most of their hits since the last log import,
    # indicating a recently active or escalating attacker rather than a dormant entry.
    surging = []
    all_with_new = []

    for r in records:
        total = r.get("total_hits", 0) or 0
        new   = r.get("new_hits",   0) or 0
        if new <= 0:
            continue
        entry = {
            "ip":           r["ip"],
            "new_hits":     new,
            "total_hits":   total,
            "surge_pct":    round(new / max(total, 1) * 100, 1),
            "threat_level": r.get("threat_level", ""),
            "country":      r.get("country", ""),
        }
        all_with_new.append(entry)
        if total > 0 and new / total >= 0.5:
            surging.append(entry)

    surging.sort(key=lambda x: x["new_hits"], reverse=True)
    all_with_new.sort(key=lambda x: x["new_hits"], reverse=True)
    return {
        "surging_ips":  surging,
        "top_new_hits": all_with_new[:top_n],
    }


def compute_dataset_health(records):
    # Score the overall completeness of OSINT scan coverage for the filtered set.
    #
    # Inputs:
    #     records (list[dict]): full record dicts from get_insights_records().
    #
    # Returns:
    #     dict with keys:
    #         coverage_pct    (float): sum of all scanned_* flags across all IPs,
    #                                  divided by (total IPs × 10 platforms) × 100.
    #                                  100% means every IP has been scanned by all 10.
    #         zero_scan_ips   (int):   IPs with all 10 scanned_* flags == 0
    #                                  (pure log entries, never OSINT-enriched)
    #         fully_scanned   (int):   IPs where all 10 scanned_* flags == 1
    #         partial_scanned (int):   IPs with at least one scan but not all 10
    #
    # A low coverage_pct means the threat scores and insights may be incomplete.
    # zero_scan_ips represent the raw log population that has never been enriched.
    flags = list(PLATFORM_SCAN_FLAGS.values())
    n_flags = len(flags)
    total = len(records)
    if total == 0:
        return {"coverage_pct": 0.0, "zero_scan_ips": 0,
                "fully_scanned": 0, "partial_scanned": 0}

    # Single O(N) pass: accumulates total_flags, zero_scan, and fully at once.
    # Previous implementation had three separate generator scans (N×10 + N + N).
    total_flags = 0
    zero_scan   = 0
    fully       = 0
    for r in records:
        row_flags = sum(1 for f in flags if r.get(f) == 1)
        total_flags += row_flags
        if row_flags == 0:
            zero_scan += 1
        elif row_flags == n_flags:
            fully += 1
    partial = total - zero_scan - fully

    return {
        "coverage_pct":    round(total_flags / (total * n_flags) * 100, 1),
        "zero_scan_ips":   zero_scan,
        "fully_scanned":   fully,
        "partial_scanned": partial,
    }


def compute_blocklist_capture(records):
    # Classify IPs by which firewall rule first caught them.
    #
    # Inputs:
    #     records (list[dict]): full record dicts from get_insights_records().
    #
    # Returns:
    #     dict with keys:
    #         blocklist_v4 (int): IPs caught by banIP/inbound/drop/blocklist.v4
    #         country_v4   (int): IPs caught by banIP/inbound/drop/country.v4
    #         default_only (int): IPs with no blocklist rule — caught only by the
    #                             default "reject wan in" or similar catch-all rule
    #
    # Buckets are mutually exclusive; priority is blocklist.v4 > country.v4 > default.
    # An IP with all three rules is counted only under blocklist.v4.
    _BL_V4   = "banIP/inbound/drop/blocklist.v4"
    _CTRY_V4 = "banIP/inbound/drop/country.v4"

    blocklist_v4 = country_v4 = default_only = 0
    for r in records:
        raw = r.get("log_rules") or ""
        rules = {s for t in raw.split(",") if (s := t.strip())}  # walrus: strip once, skip if empty
        has_bl   = _BL_V4   in rules
        has_ctry = _CTRY_V4 in rules
        if has_bl:
            blocklist_v4 += 1
        elif has_ctry:
            country_v4 += 1
        else:
            default_only += 1
    return {
        "blocklist_v4": blocklist_v4,
        "country_v4":   country_v4,
        "default_only": default_only,
    }


def compute_cpe_summary(records, top_n=15):
    # Aggregate Common Platform Enumeration (CPE) strings from InternetDB across
    # the filtered IP set to identify what software attacker IPs are running.
    #
    # Inputs:
    #     records (list[dict]): full record dicts from get_insights_records().
    #     top_n   (int):        max CPE entries to return.
    #
    # Returns:
    #     dict with keys:
    #         ips_with_cpes (int):                IPs that have at least one CPE
    #         top_cpes      (list[tuple[str,int]]): top_n (cpe_string, ip_count) pairs
    #
    # CPE strings follow the format "cpe:/type:vendor:product:version",
    # e.g. "cpe:/a:openbsd:openssh:7.4" or "cpe:/o:linux:linux_kernel".
    # Each CPE is deduplicated per IP before counting, so the count represents
    # "number of IPs running this software" not "total occurrences".
    cpe_counter = Counter()
    ips_with_cpes = 0

    for r in records:
        cpes = set(parse_json_list(r.get("internetdb_cpes")))
        if cpes:
            ips_with_cpes += 1
            for cpe in cpes:
                if isinstance(cpe, str) and cpe.strip():
                    cpe_counter[cpe.strip()] += 1

    return {
        "ips_with_cpes": ips_with_cpes,
        "top_cpes":      cpe_counter.most_common(top_n),
    }


# ── Entry point ────────────────────────────────────────────────────────────────

def build_insights_report(records):
    # Aggregate all analytics metrics for the filtered IP set into a single dict.
    #
    # Inputs:
    #     records (list[dict]): full record dicts from IPRepository.get_insights_records().
    #                           Each dict is keyed by the columns in _INSIGHTS_COLS.
    #
    # Returns:
    #     dict: keyed report ready for render_insights_text(). Keys:
    #         total           (int):   total IPs in the filtered set
    #         score_stats     (dict):  from compute_score_stats()
    #         threat_breakdown(list):  from compute_threat_breakdown()
    #         country_dist    (dict):  from compute_country_distribution()
    #         tags            (list):  from compute_tag_frequency()
    #         proxy_types     (list):  from compute_proxycheck_types()
    #         coverage        (list):  from compute_platform_coverage()
    #         greynoise       (dict):  from compute_greynoise_summary()
    #         vulns           (dict):  from compute_vulnerability_summary()
    #         recidivism      (dict):  from compute_recidivism_metrics()
    #         protocols       (dict):  from compute_protocol_dst_port_summary()
    #         asn_isp         (dict):  from compute_asn_isp_summary()
    #         temporal        (dict):  from compute_temporal_activity()
    #         src_ports       (dict):  from compute_src_port_summary()
    #         pc_risk         (dict):  from compute_proxycheck_risk_distribution()
    #         otx_dist        (dict):  from compute_otx_distribution()
    #         scan_gaps       (dict):  from compute_scan_gaps()
    #         tag_cooccur     (dict):  from compute_tag_cooccurrence()
    #         port_risk       (dict):  from compute_port_service_risk()
    #         surge           (dict):  from compute_new_hits_surge()
    #         health          (dict):  from compute_dataset_health()
    #         cpes            (dict):  from compute_cpe_summary()
    #
    #     Returns {"total": 0} when records is empty so the renderer can
    #     display an appropriate empty-state message without crashing.
    if not records:
        return {"total": 0}
    return {
        "total":          len(records),
        "score_stats":    compute_score_stats(records),
        "threat_breakdown": compute_threat_breakdown(records),
        "country_dist":   compute_country_distribution(records),
        "tags":           compute_tag_frequency(records),
        "proxy_types":    compute_proxycheck_types(records),
        "coverage":       compute_platform_coverage(records),
        "greynoise":      compute_greynoise_summary(records),
        "vulns":          compute_vulnerability_summary(records),
        "recidivism":     compute_recidivism_metrics(records),
        "protocols":      compute_protocol_dst_port_summary(records),
        "asn_isp":        compute_asn_isp_summary(records),
        "temporal":       compute_temporal_activity(records),
        "src_ports":      compute_src_port_summary(records),
        "pc_risk":        compute_proxycheck_risk_distribution(records),
        "otx_dist":       compute_otx_distribution(records),
        "scan_gaps":      compute_scan_gaps(records),
        "tag_cooccur":    compute_tag_cooccurrence(records),
        "port_risk":      compute_port_service_risk(records),
        "surge":          compute_new_hits_surge(records),
        "health":             compute_dataset_health(records),
        "cpes":               compute_cpe_summary(records),
        "correlation":        compute_platform_correlation(records),
        "blocklist_capture":  compute_blocklist_capture(records),
    }


# ── Renderer ───────────────────────────────────────────────────────────────────
#
# render_insights_text() converts the dict from build_insights_report() into a
# plain-text string for insertion into the Data Insights ScrolledText widget.
# All formatting logic lives here — the compute functions above are kept free of
# any display concerns so they remain independently testable.

# Total number of Unicode block characters in each bar.
_BAR_WIDTH = 20

# Width of the section header separator lines (═ characters).
_LINE_WIDTH = 62

# Fixed character width of the label column in every bar row. All labels are
# padded or truncated to this width so bars start at the same visual column
# across every section. Set to 20 to accommodate the longest platform name
# ("DNS Reverse Lookup" = 18 chars) with a small margin.
_LABEL_W = 20


def _section(title):
    # Return a formatted section header string with leading and trailing blank lines.
    #
    # The two leading newlines create two blank lines between the previous section's
    # last data row and this header (visually separating sections). The two trailing
    # newlines create one blank line between the header and the first data row.
    #
    # Example output:
    #     \n\n══ SCORE SUMMARY ══════════════════════════════════════\n\n
    pad = _LINE_WIDTH - len(title) - 4
    return f"\n\n══ {title} {'═' * max(pad, 2)}\n\n"


def _bar(pct):
    # Build a 20-character Unicode block bar representing pct% fullness.
    #
    # Inputs:
    #     pct (float): percentage value 0–100. Values outside this range are clamped.
    #
    # Returns:
    #     str: exactly _BAR_WIDTH characters of █ (filled) followed by ░ (empty).
    #
    # The bar reflects absolute percentage — pct=50 fills exactly 10 of 20 blocks.
    # All sections use this same scale so bars are visually comparable across sections.
    filled = round(pct / 100 * _BAR_WIDTH)
    filled = max(0, min(_BAR_WIDTH, filled))
    return "█" * filled + "░" * (_BAR_WIDTH - filled)


def _fmt_label(text):
    # Pad or truncate text to exactly _LABEL_W characters.
    #
    # Inputs:
    #     text (str): label string (tag name, country code, platform name, etc.)
    #
    # Returns:
    #     str: exactly _LABEL_W characters — truncated with a trailing ellipsis (…)
    #          if text exceeds _LABEL_W, otherwise left-justified and space-padded.
    #
    # Consistent label width is what keeps all bar characters in the same visual
    # column across every section in the output.
    if len(text) > _LABEL_W:
        return text[:_LABEL_W - 1] + "…"
    return text.ljust(_LABEL_W)


def _bar_row(label, bar, count, pct):
    # Format a single data row with a label, bar, count, and percentage.
    #
    # Inputs:
    #     label (str):  raw label text (will be passed through _fmt_label)
    #     bar   (str):  20-char bar string from _bar()
    #     count (int):  raw count value
    #     pct   (float): percentage value for the trailing column
    #
    # Returns:
    #     str: one formatted line, e.g.:
    #          "  Critical               ██░░░░░░░░░░░░░░░░░░     42  ( 33.3%)\n"
    #
    # Used by every bar section in the report for consistent column alignment.
    return f"  {_fmt_label(label)}  {bar}  {count:>5}  ({pct:>5.1f}%)\n"



def render_insights_text(report, filter_label="All IPs"):
    # Convert a build_insights_report() dict into a formatted plain-text string.
    #
    # Inputs:
    #     report       (dict): output of build_insights_report().
    #     filter_label (str):  human-readable description of the active filter,
    #                          shown in the Score Summary section header line.
    #                          Defaults to "All IPs".
    #
    # Returns:
    #     str: multi-section formatted report ready for insertion into the
    #          Data Insights ScrolledText widget. Each section begins with a
    #          header line (═══ TITLE ═══), one blank line, data rows, and
    #          two blank lines before the next section.
    #
    # Empty state: if report["total"] == 0, returns a short message instead
    # of an empty report with blank sections.
    if report.get("total", 0) == 0:
        return (
            "\n══ DATA INSIGHTS " + "═" * 45 + "\n\n"
            "  No IPs match the current filter.\n"
            "  Adjust the filter or load a log file to populate the database.\n"
        )

    total = report["total"]
    lines = []

    # ── Score Summary ──────────────────────────────────────────────────────────
    # Includes threat score stats, temporal activity, and hit frequency inline.
    lines.append(_section("SCORE SUMMARY"))
    ss = report["score_stats"]
    lines.append(f"  Filter: {filter_label}\n")
    if ss["count_scored"] == 0:
        lines.append("  No scored IPs in current filter (all Pending or unscored).\n")
    else:
        lines.append(f"  Scored IPs:      {ss['count_scored']} / {total}  "
                     f"({ss['count_unscored']} unscored / Pending)\n")
        lines.append(f"  Average Score:   {ss['avg']:<8}  Median: {ss['median']}\n")
        lines.append(f"  Min / Max:       {ss['min']} / {ss['max']}\n")
        lines.append(f"  Std Deviation:   {ss['stddev']}\n")
        lines.append(f"  High-Risk (≥75): {ss['count_high_risk']} ({ss['pct_high_risk']}%)\n")

    tm = report["temporal"]
    if tm["total_with_dates"] > 0:
        lines.append(f"\n  New Today      (≤24 h):  {tm['new_today']:>5}\n")
        lines.append(f"  New This Week  (≤7 d):   {tm['new_week']:>5}\n")
        lines.append(f"  New This Month (≤30 d):  {tm['new_month']:>5}\n")
        if tm["dwell_avg_days"] is not None:
            lines.append(f"\n  Avg Dwell Time:  {tm['dwell_avg_days']} days"
                         f"   Max: {tm['dwell_max_days']} days\n")
        if tm["oldest_ip"]:
            lines.append(f"  Longest Active: {tm['oldest_ip']}  "
                         f"(first seen: {tm['oldest_first_seen']})\n")

    rec = report["recidivism"]
    high_pct = round(rec["high_hit_ips"]  / max(total, 1) * 100, 1)
    med_pct  = round(rec["medium_hit_ips"] / max(total, 1) * 100, 1)
    low_pct  = round(rec["low_hit_ips"]   / max(total, 1) * 100, 1)
    lines.append(f"\n  Hit Frequency:\n\n")
    lines.append(f"    High  (≥100 hits):  {rec['high_hit_ips']:>5}  IPs  ({high_pct}%)\n")
    lines.append(f"    Med   (10–99 hits): {rec['medium_hit_ips']:>5}  IPs  ({med_pct}%)\n")
    lines.append(f"    Low   (<10 hits):   {rec['low_hit_ips']:>5}  IPs  ({low_pct}%)\n")
    lines.append(f"    Max Hits: {rec['max_hits']:>6}   "
                 f"Avg hits: {rec['avg_hits']:>6}   "
                 f"Avg new hits: {rec['avg_new_hits']}\n")

    surge = report["surge"]
    if surge["top_new_hits"]:
        lines.append("\n  Top IPs by new hits since last import:\n\n")
        for o in surge["top_new_hits"]:
            lines.append(f"    {o['ip']:<18}  new={o['new_hits']:>5}"
                         f"  total={o['total_hits']:>6}"
                         f"  [{o['threat_level']:<9}]  {o['country']}\n")

    bl = report["blocklist_capture"]
    lines.append("\n  Blocklist Capture Rate:\n\n")
    for label, count in (
        ("  blocklist.v4",  bl["blocklist_v4"]),
        ("  country.v4",    bl["country_v4"]),
        ("  Default FW only", bl["default_only"]),
    ):
        pct = round(count / max(total, 1) * 100, 1)
        lines.append(_bar_row(label, _bar(pct), count, pct))

    # ── Threat Level Breakdown ─────────────────────────────────────────────────
    lines.append(_section("THREAT LEVEL BREAKDOWN"))
    breakdown = report["threat_breakdown"]
    if breakdown:
        for b in breakdown:
            lines.append(_bar_row(b["level"], _bar(b["pct"]), b["count"], b["pct"]))
    else:
        lines.append("  No data.\n")

    # ── Country Distribution ───────────────────────────────────────────────────
    # Bars are scaled to absolute percentage of all IPs in the filter set.
    # The "+ other countries" row aggregates all countries beyond the top 10.
    lines.append(_section("COUNTRY DISTRIBUTION  (top 10)"))
    cd = report["country_dist"]
    if cd["top"]:
        for i, c in enumerate(cd["top"], 1):
            lines.append(_bar_row(f"{i:>2}. {c['country']}", _bar(c["pct"]), c["count"], c["pct"]))
        if cd["others_count"]:
            lines.append(_bar_row("+ other countries", _bar(cd["others_pct"]),
                                  cd["others_count"], cd["others_pct"]))
    else:
        lines.append("  No country data available.\n")

    # ── InternetDB Tags ────────────────────────────────────────────────────────
    # Bars reflect what percentage of total IPs carry each tag (absolute scale).
    lines.append(_section("MOST COMMON INTERNETDB TAGS"))
    tags = report["tags"]
    if tags:
        for tag, cnt in tags:
            pct = round(cnt / total * 100, 1)
            lines.append(_bar_row(tag, _bar(pct), cnt, pct))
    else:
        lines.append("  No InternetDB tag data available.\n")

    tc = report["tag_cooccur"]
    if tc["multi_tag_ips"] > 0:
        lines.append(f"\n  IPs with 2+ tags (compound threats): {tc['multi_tag_ips']:>5}\n")
        if tc["max_tags_ip"]:
            lines.append(f"  Most-Tagged IP: {tc['max_tags_ip']}  ({tc['max_tags_count']} tags)\n\n")
        if tc["top_pairs"]:
            lines.append("  Most Common Tag Pairs:\n\n")
            for pair, cnt in tc["top_pairs"][:5]:
                label = f"{pair[0]} + {pair[1]}:"
                lines.append(f"    {label:<28}  {cnt:>5}\n")

    # ── ProxyCheck Types and Risk Scores ──────────────────────────────────────
    lines.append(_section("PROXYCHECK"))
    ptypes = report["proxy_types"]
    pc = report["pc_risk"]
    pc_queried = total - pc["unqueried"]
    if not ptypes and pc_queried == 0:
        lines.append("  Not queried for any IP in this filter set.\n")
    else:
        if ptypes:
            lines.append("  Types:\n")
            for ptype, cnt in ptypes:
                pct = round(cnt / total * 100, 1)
                lines.append(_bar_row(ptype, _bar(pct), cnt, pct))
        if pc_queried > 0:
            lines.append("\n  Risk score buckets:\n")
            for label, count in (
                ("Low      (0–24)",  pc["low"]),
                ("Medium  (25–49)",  pc["medium"]),
                ("High    (50–74)",  pc["high"]),
                ("Critical(75–100)", pc["critical"]),
                ("Unqueried",        pc["unqueried"]),
            ):
                pct = round(count / total * 100, 1)
                lines.append(_bar_row(label, _bar(pct), count, pct))
            if pc["avg"] is not None:
                lines.append(f"\n  Avg risk score: {pc['avg']}   Median: {pc['median']}\n")

    # ── Platform Scan Coverage ─────────────────────────────────────────────────
    # 100% scanned platforms show a full bar and a ✓ suffix.
    # Incomplete platforms show the partial bar and a [N missing] count.
    lines.append(_section("PLATFORM SCAN COVERAGE"))
    for cov in report["coverage"]:
        plat = _fmt_label(cov["platform"])
        bar = _bar(cov["pct"])
        if cov["pct"] >= 100.0:
            lines.append(
                f"  {plat}  {bar}  {cov['scanned']:>5}/{cov['total']}"
                f"  (100.0%)  ✓\n"
            )
        else:
            lines.append(
                f"  {plat}  {bar}  {cov['scanned']:>5}/{cov['total']}"
                f"  ({cov['pct']:>5.1f}%)  [{cov['missing']} missing]\n"
            )

    # Platform signal correlation and overall coverage — appended below the bars.
    cor = report["correlation"]
    if cor["both_key"] > 0:
        lines.append(f"\n  Both key platforms scanned:    {cor['both_key']:>5}\n")
        lines.append(f"  Both agree HIGH (≥50 each):    {cor['agree_high']:>5}\n")
        lines.append(f"  Platform disagreement:         {cor['disagree']:>5}\n")
        lines.append(f"  Scanned by 3+ platforms:       {cor['multi3plus']:>5}\n")
    lines.append(f"\n  Overall scan coverage:  {report['health']['coverage_pct']}%\n")

    # ── OTX Pulse Distribution ─────────────────────────────────────────────────
    lines.append(_section("OTX PULSE DISTRIBUTION"))
    od = report["otx_dist"]
    if od["unqueried"] == total:
        lines.append("  Not queried for any IP in this filter set.\n")
    else:
        for label, count in (
            ("0 pulses",  od["zero"]),
            ("1–5",       od["low"]),
            ("6–10",      od["medium"]),
            ("10+",       od["high"]),
            ("Unqueried", od["unqueried"]),
        ):
            pct = round(count / total * 100, 1)
            lines.append(_bar_row(label, _bar(pct), count, pct))
        if od["max_pulses"] > 0:
            lines.append(f"\n  Max Pulses: {od['max_pulses']:>5}\n\n")
        if od["top_otx"]:
            lines.append("  Top IPs by pulse count:\n")
            for i, o in enumerate(od["top_otx"], 1):
                lines.append(f"    {i}. {o['ip']:<18}  pulses={o['pulses']:>3}"
                              f"  [{o['threat_level']:<9}]  {o['country']}\n")

    # ── Scan Gaps — High-Hit Unscanned IPs ────────────────────────────────────
    lines.append(_section("SCAN GAPS"))
    sg = report["scan_gaps"]
    lines.append(f"  IPs missing at least one key platform scan:  {sg['total_unscanned_any_key']:>5}\n")
    if sg["missing_abuseipdb"]:
        lines.append("\n  Highest-hit IPs missing AbuseIPDB scan:\n")
        for o in sg["missing_abuseipdb"]:
            lines.append(f"    {o['ip']:<18}  hits={o['total_hits']:>6}"
                         f"  [{o['threat_level']:<9}]  {o['country']}\n")
    if sg["missing_virustotal"]:
        lines.append("\n  Highest-hit IPs missing VirusTotal scan:\n")
        for o in sg["missing_virustotal"]:
            lines.append(f"    {o['ip']:<18}  hits={o['total_hits']:>6}"
                         f"  [{o['threat_level']:<9}]  {o['country']}\n")

    # ── GreyNoise Classification ───────────────────────────────────────────────
    # Malicious/Benign/Unknown are mutually exclusive classification buckets.
    # Noise flagged and RIOT are independent boolean flags that can overlap with
    # any classification bucket (e.g. a benign IP can still be noise-flagged).
    lines.append(_section("GREYNOISE CLASSIFICATION"))
    gn = report["greynoise"]
    if total - gn["unqueried"] == 0:
        lines.append("  Not queried for any IP in this filter set.\n")
    else:
        for label, count in (
            ("Malicious",          gn["malicious"]),
            ("Benign",             gn["benign"]),
            ("Unknown",            gn["unknown"]),
            ("Unqueried",          gn["unqueried"]),
            ("Noise flagged",      gn["noise_flagged"]),
            ("RIOT (known-good)",  gn["riot_flagged"]),
        ):
            pct = round(count / total * 100, 1)
            lines.append(_bar_row(label, _bar(pct), count, pct))

    # ── Vulnerability Exposure ─────────────────────────────────────────────────
    # CVEs from InternetDB and Shodan are deduplicated per IP before counting.
    # Top CVEs show how many IPs carry each CVE (not total instances).
    lines.append(_section("VULNERABILITY EXPOSURE"))
    v = report["vulns"]
    vuln_pct = round(v["ips_with_vulns"] / max(total, 1) * 100, 1)
    port_pct = round(v["ips_with_open_ports"] / max(total, 1) * 100, 1)
    lines.append(f"  IPs with CVEs:        {v['ips_with_vulns']:>5} / {total}  ({vuln_pct:>5.1f}%)\n")
    lines.append(f"  Total CVE instances:  {v['total_cve_instances']:>5}\n")
    if v["top_cves"]:
        lines.append("\n  Top CVEs:\n")
        for cve, cnt in v["top_cves"]:
            pct_cve = round(cnt / total * 100, 1)
            lines.append(_bar_row(cve, _bar(pct_cve), cnt, pct_cve))
    lines.append(f"\n  IPs with open ports:  {v['ips_with_open_ports']:>5} / {total}  ({port_pct:>5.1f}%)\n")
    if v["most_common_ports"]:
        port_str = "  ".join(f"{p}" for p, _ in v["most_common_ports"])
        lines.append(f"  Attacker IP Open Ports: {port_str}\n")

    pr = report["port_risk"]
    if pr["critical_port_ips"] or pr["high_port_ips"] or pr["medium_port_ips"]:
        lines.append(f"\n  IPs targeting Critical-risk ports:  {pr['critical_port_ips']:>5}"
                     f"  (RDP, SMB, DB, Telnet)\n")
        lines.append(f"  IPs targeting High-risk ports:      {pr['high_port_ips']:>5}"
                     f"  (SSH, FTP, Mail)\n")
        lines.append(f"  IPs targeting Medium-risk ports:    {pr['medium_port_ips']:>5}"
                     f"  (HTTP/S)\n")
        if pr["top_risky_ports"]:
            top_str = "  ".join(f"{p} ({c})" for p, c in pr["top_risky_ports"][:6])
            lines.append(f"  Top known-service ports:  {top_str}\n")

    # ── Network Attack Patterns ────────────────────────────────────────────────
    # Aggregated from the protocols, dst_ports, log_rules, and src_ports CSV
    # columns, which the log parser populates at import time from raw firewall
    # log lines.
    lines.append(_section("NETWORK ATTACK PATTERNS"))
    pat = report["protocols"]
    sp = report["src_ports"]
    if pat["top_protocols"]:
        lines.append("  Top Protocols:\n")
        for p, cnt in pat["top_protocols"]:
            pct = round(cnt / max(total, 1) * 100, 1)
            lines.append(_bar_row(p, _bar(pct), cnt, pct))
    else:
        lines.append("  No protocol data available.\n")
    if pat["top_dst_ports"]:
        lines.append("\n  Top Destination Ports:\n")
        max_dst = pat["top_dst_ports"][0][1]
        for port, cnt in pat["top_dst_ports"]:
            pct = round(cnt / max(total, 1) * 100, 1)
            lines.append(_bar_row(str(port), _bar(cnt / max(max_dst, 1) * 100), cnt, pct))
    else:
        lines.append("\n  No destination port data available.\n")
    if sp["top_src_ports"]:
        lines.append("\n  Top Source Ports:\n")
        max_src = sp["top_src_ports"][0][1]
        for port, cnt in sp["top_src_ports"]:
            pct = round(cnt / max(total, 1) * 100, 1)
            lines.append(_bar_row(str(port), _bar(cnt / max(max_src, 1) * 100), cnt, pct))
    else:
        lines.append("\n  No source port data available.\n")

    # ── Top ASNs and ISPs ──────────────────────────────────────────────────────
    # High concentration in a single ASN/ISP may support block-by-ASN rules or
    # indicate that a specific hosting provider tolerates abusive customers.
    lines.append(_section("TOP ASNs AND ISPs"))
    ai = report["asn_isp"]
    if ai["top_asns"]:
        lines.append("  Top ASNs:\n")
        for asn, cnt in ai["top_asns"]:
            pct_asn = round(cnt / total * 100, 1)
            lines.append(_bar_row(asn, _bar(pct_asn), cnt, pct_asn))
    else:
        lines.append("  No ASN data available.\n")
    if ai["top_isps"]:
        lines.append("\n  Top ISPs:\n")
        for isp, cnt in ai["top_isps"]:
            pct_isp = round(cnt / total * 100, 1)
            lines.append(_bar_row(isp, _bar(pct_isp), cnt, pct_isp))
    else:
        lines.append("  No ISP data available.\n")

    # ── Exposed Software (CPEs) ────────────────────────────────────────────────
    lines.append(_section("EXPOSED SOFTWARE  (CPEs)"))
    cp = report["cpes"]
    cpe_pct = round(cp["ips_with_cpes"] / max(total, 1) * 100, 1)
    lines.append(f"  IPs with CPE data:  {cp['ips_with_cpes']:>5} ({cpe_pct}%)\n")
    if cp["top_cpes"]:
        lines.append("  Most common software on attacker IPs:\n")
        max_cpe_count = cp["top_cpes"][0][1]
        for cpe, cnt in cp["top_cpes"]:
            pct = round(cnt / total * 100, 1)
            lines.append(_bar_row(cpe, _bar(cnt / max(max_cpe_count, 1) * 100), cnt, pct))
    else:
        lines.append("  No CPE data available for this filter set.\n")

    # ── Footer ─────────────────────────────────────────────────────────────────
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines.append("\n" + "═" * _LINE_WIDTH + "\n")
    lines.append(f"\n  Generated: {ts}\n")
    return "".join(lines)
