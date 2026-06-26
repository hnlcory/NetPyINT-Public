#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════╗
# ║              NetPyINT – Configuration Module                     ║
# ║    Application constants, default settings, and config I/O       ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# Owns every value that is either read from or written to
# netpyint_config.json, plus the static constants that define the
# platform list, threat-level taxonomy, and scoring columns.
#
# Public surface (imported by netpyint_main.py):
#     DB_FILE, CONFIG_FILE, VERSION
#     THREAT_LEVELS, THREAT_COLORS, KEY_PLATFORMS
#     PLATFORM_TO_FLAG, RESULT_KEY_TO_PLATFORM, RATE_LIMIT_EXEMPT
#     THREAT_LEVEL_COLUMNS, PLATFORMS, DEFAULT_CONFIG
#     load_config(), save_config()

import contextlib
import json
import os
import time
from pathlib import Path

# ─────────────────────────────────────────────────────────────────
# File paths & version
# ─────────────────────────────────────────────────────────────────

# Database and config files are created in the working directory alongside the script
DB_FILE = "netpyint_threat_intel.db"     # SQLite database file – stores all IP records and scan history
CONFIG_FILE = "netpyint_config.json"     # User preferences – API keys, enabled platforms, scan delay
_CONFIG_PATH      = Path(__file__).parent.parent / CONFIG_FILE
_CONFIG_LOCK_FILE = _CONFIG_PATH.with_suffix(".lock")
VERSION = "1.8.0"                        # Displayed in title bar and About dialog

# ─────────────────────────────────────────────────────────────────
# Threat level taxonomy
# ─────────────────────────────────────────────────────────────────

# Ordered list of threat severity categories (highest → lowest)
# Used by the scoring engine and UI display
THREAT_LEVELS = ["Critical", "High", "Medium", "Low", "Optional", "No Threat"]

# Colour mapping for threat levels – applied to table row text and stats labels
# Colours follow a traffic-light intuition: red → orange → yellow → blue → purple → green
THREAT_COLORS = {
    "Critical":  "#dc2626",   # Red        – immediately block, known malicious
    "High":      "#ea580c",   # Orange     – strong indicators of abuse
    "Medium":    "#d97706",   # Amber      – moderate suspicion, worth blocking
    "Low":       "#2563eb",   # Blue       – minor flags, monitor
    "Optional":  "#7c3aed",   # Purple     – negligible risk, optional block
    "No Threat": "#16a34a",   # Green      – benign / no adverse data found
    "Partial":   "#f59e0b",   # Yellow     – incomplete scan: key platforms missing data
    "Pending":   "#6b7280",   # Grey       – not yet scanned at all
}

# Platforms whose data is considered essential for a reliable threat assessment.
# If ANY of these have not successfully reported, the IP stays at "Partial"
# instead of receiving a final threat level. This prevents low scores from
# incomplete data from prematurely classifying dangerous IPs as safe.
# AbuseIPDB (35% weight) and VirusTotal (25% weight) together represent
# 60% of the scoring algorithm — without both, the score is unreliable.
KEY_PLATFORMS = ["AbuseIPDB", "VirusTotal"]

# ─────────────────────────────────────────────────────────────────
# Platform mappings
# ─────────────────────────────────────────────────────────────────

# Mapping from platform display names → database column flag names
# Each scanned_* column is INTEGER: 0 = not queried, 1 = successfully queried
PLATFORM_TO_FLAG = {
    "AbuseIPDB":          "scanned_abuseipdb",
    "VirusTotal":         "scanned_virustotal",
    "Shodan":             "scanned_shodan",
    "Shodan InternetDB":  "scanned_internetdb",
    "GreyNoise":          "scanned_greynoise",
    "AlienVault OTX":     "scanned_otx",
    "ProxyCheck":         "scanned_proxycheck",
    "IPInfo":             "scanned_ipinfo",
    "ip-api (free)":      "scanned_ipapi",
    "DNS Reverse Lookup": "scanned_dns",
}

# Mapping from raw_results dict keys → platform display names
# Used by rate-limit auto-stop to iterate results without hardcoding platform blocks
RESULT_KEY_TO_PLATFORM = {
    "dns":       "DNS Reverse Lookup",
    "ipapi":     "ip-api (free)",
    "abuseipdb": "AbuseIPDB",
    "virustotal":"VirusTotal",
    "shodan":    "Shodan",
    "internetdb":"Shodan InternetDB",
    "greynoise": "GreyNoise",
    "otx":       "AlienVault OTX",
    "proxycheck":"ProxyCheck",
    "ipinfo":    "IPInfo",
}

# Platforms exempt from rate-limit auto-stop (no rate limit concept)
RATE_LIMIT_EXEMPT = {"DNS Reverse Lookup"}

# Columns needed to compute a threat level for an IP.
# Used by _fetch_threat_row() to build the scoring dict passed to compute_threat_level().
# Defined once here so both _scan_worker and _rescan_worker stay in sync automatically.
THREAT_LEVEL_COLUMNS = [
    "abuseipdb_score", "vt_score",
    "shodan_vulns", "internetdb_vulns",
    "internetdb_tags", "greynoise_class",
    "otx_pulses", "proxycheck_type", "total_hits",
    "scanned_abuseipdb", "scanned_virustotal", "scanned_greynoise",
    "scanned_shodan", "scanned_internetdb", "scanned_otx",
    "scanned_proxycheck", "scanned_ipinfo", "scanned_ipapi", "scanned_dns",
    "vuln_count", "tag_count",
]

# Master list of supported OSINT platforms
# Each entry corresponds to a checkbox in the UI sidebar and a query function
PLATFORMS = [
    "AbuseIPDB",             # Crowd-sourced IP abuse reports (requires API key)
    "VirusTotal",            # Multi-engine malware / URL scanner (requires API key)
    "Shodan",                # Internet-wide port/vuln scanner (requires API key)
    "Shodan InternetDB",     # Free Shodan API – ports, tags, vulns, CPEs (no key, no rate limit)
    "GreyNoise",             # Mass-scanning / noise classifier (free community tier)
    "AlienVault OTX",        # Open threat exchange pulse database (free, no key)
    "ProxyCheck",            # Proxy/VPN/Tor detection via proxycheck.io V3 API (requires API key)
    "IPInfo",                # IP geolocation and ASN data (free tier available)
    "ip-api (free)",         # Free geolocation + ISP + proxy detection (no key, 45 req/min)
    "DNS Reverse Lookup",    # Standard PTR record lookup via socket (no key, instant)
]

# ─────────────────────────────────────────────────────────────────
# Default configuration
# ─────────────────────────────────────────────────────────────────

# Default configuration written to netpyint_config.json on first run
# Users update API keys via Settings → API Keys dialog; all values persist across sessions
DEFAULT_CONFIG = {
    "api_keys": {                               # API keys for platforms that require authentication
        "abuseipdb": "",                        # https://www.abuseipdb.com/account/api
        "virustotal": "",                       # https://www.virustotal.com/gui/my-apikey
        "shodan": "",                           # https://account.shodan.io/
        "greynoise": "",                        # https://viz.greynoise.io/account/api-key
        "proxycheck": "",                       # https://proxycheck.io/dashboard/ (API key)
        "ipinfo": "",                           # https://ipinfo.io/account/token
    },
    "enabled_platforms": {p: True for p in PLATFORMS},  # All platforms on by default
    "scan_delay_ms": 1100,                      # Milliseconds between API calls (rate-limit safety)
    "parallel_workers": 1,                      # Number of IPs scanned simultaneously (1 = serial, max 8)
    "scan_new_only": False,                     # If True, only scan IPs with threat_level='Pending'
    "max_abuseipdb_days": 90,                   # AbuseIPDB lookback window in days
    "auto_stop_rate_limit": True,               # Auto-stop scan when all platforms hit rate limits (5 consecutive)
    "start_advanced_filters_hidden": True,      # Advanced Filter Controls panel starts collapsed at launch
    "auto_scan_enabled": False,                  # Auto-scan visible IPs on a recurring schedule
    "auto_scan_interval_hours": 1,               # Hours between auto-scans (1–24)
    "auto_scan_post_delay": False,               # Add 5-min buffer after scan finishes before next auto-scan
    "cc_highlight_codes": [],                     # Country codes whose CC column cell is highlighted (e.g. ["CN","RU"])
    "filter_presets": {},                        # Saved Advanced Filter Controls combinations, keyed by name
    "scan_log_max_days": 60,                    # Days to retain scan_log rows; 0 = keep forever
    "last_key_platforms": list(KEY_PLATFORMS),  # KEY_PLATFORMS as of the last startup; used to skip
                                                 # _recompute_stale_levels() when unchanged
    "log_helper": {                             # Settings for the standalone Log Helper utility
        "last_ip": "70.200.30.10",              # Most-recently used public IP to redact from WAN logs
        "date_filter_enabled": True,           # Whether to skip logs at/before the last processed date
        "last_log_date": "",                    # ISO-format datetime of the latest log line processed
    },
}

# ─────────────────────────────────────────────────────────────────
# Config I/O
# ─────────────────────────────────────────────────────────────────

@contextlib.contextmanager
def _config_write_lock(lock_path=None, timeout: float = 2.0):
    if lock_path is None:
        lock_path = _CONFIG_LOCK_FILE
    deadline = time.monotonic() + timeout
    while True:
        try:
            # O_CREAT|O_EXCL together make file creation atomic: the call fails
            # with FileExistsError if another process already holds the lock.
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(fd)
            break
        except FileExistsError:
            if time.monotonic() >= deadline:
                try:
                    lock_path.unlink(missing_ok=True)
                except OSError:
                    pass
            else:
                time.sleep(0.05)
    try:
        yield
    finally:
        try:
            lock_path.unlink()
        except OSError:
            pass


def load_config():
    # Load application configuration from the JSON config file on disk.
    #
    # Inputs:
    #     None (reads from the CONFIG_FILE global path).
    #
    # Returns:
    #     dict – Configuration dictionary containing:
    #         - api_keys (dict):           Platform API keys keyed by service name
    #         - enabled_platforms (dict):  Boolean toggles for each OSINT platform
    #         - scan_delay_ms (int):       Delay between API calls in milliseconds
    #         - scan_new_only (bool):      Whether to scan only un-scanned IPs
    #         - max_abuseipdb_days (int):  AbuseIPDB lookback window
    #
    # Behaviour:
    #     - If the config file exists, loads it and backfills any missing keys
    #       from DEFAULT_CONFIG so that new settings added in future versions
    #       are automatically present without losing existing user values.
    #     - If the file is missing or corrupt, returns a fresh deep-copy of
    #       DEFAULT_CONFIG (deep-copied via JSON round-trip to avoid mutation).
    #
    # Usage:
    #     Called once at startup in NetPyINTApp.__init__().
    #     The returned dict is stored as self.config and mutated in-place by
    #     settings dialogs, then persisted via save_config().
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                cfg = json.load(f)
            # Backfill any missing top-level or nested keys from defaults
            # so new config options are always present after an upgrade
            for k, v in DEFAULT_CONFIG.items():
                if k not in cfg:
                    cfg[k] = v
                elif isinstance(v, dict):
                    for sk, sv in v.items():
                        if sk not in cfg[k]:
                            cfg[k][sk] = sv
            return cfg
        except Exception as exc:
            import sys
            print(f"[NetPyINT] WARNING: could not read config ({exc}); using defaults.",
                  file=sys.stderr)
    # JSON round-trip is a simple deep-copy that works for the plain-value dict DEFAULT_CONFIG
    return json.loads(json.dumps(DEFAULT_CONFIG))


def save_config(cfg):
    # Persist the current configuration dictionary to disk as JSON.
    #
    # Uses a cross-process lock file + atomic rename to prevent data loss
    # when log_helper.py writes concurrently.  Reads the current file first
    # and merges so that the "log_helper" section (owned exclusively by
    # log_helper.py) is never overwritten with a stale startup snapshot.
    # Compute paths from CONFIG_FILE at call time so test patches take effect.
    # Path(parent) / absolute_path resolves to absolute_path, so a tmp path
    # patched by tests wins over the __file__-relative default.
    cfg_path  = Path(__file__).parent.parent / CONFIG_FILE
    lock_path = cfg_path.with_suffix(".lock")
    with _config_write_lock(lock_path):
        try:
            on_disk = json.loads(cfg_path.read_text(encoding="utf-8"))
        except Exception:
            on_disk = json.loads(json.dumps(DEFAULT_CONFIG))
        # cfg wins for every key it owns; preserve log_helper (written only by log_helper.py)
        for k, v in cfg.items():
            if k != "log_helper":
                on_disk[k] = v
        tmp = cfg_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(on_disk, indent=2), encoding="utf-8")
        tmp.replace(cfg_path)  # atomic rename — readers never see a partial write
