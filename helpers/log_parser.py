#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════╗
# ║              NetPyINT – Log Parser                               ║
# ║    Firewall log regex, line parsing, and IP aggregation          ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# Owns everything related to reading and structuring raw firewall
# log files before they reach the database or scan worker.
#
# Public surface (imported by netpyint_main.py):
#     LOG_PATTERN
#     parse_log_file(), _parse_log_ts(), aggregate_entries()

import re
from collections import defaultdict

from utils import parse_ctime

# ─────────────────────────────────────────────────────────────────
# Firewall log line regex
# ─────────────────────────────────────────────────────────────────
# This compiled regex extracts structured fields from two firewall log formats:
#
# Format 1 – WAN reject:
#   "Mon Mar 23 13:16:49 2026 kern.warn kernel: [311423.870453] reject wan in: … SRC=x.x.x.x …"
#
# Format 2 – banIP drop:
#   "Mon Mar 23 13:16:46 2026 kern.warn kernel: [311420.900353] banIP/inbound/drop/country.v4: … SRC=x.x.x.x …"
#
# Named capture groups:
#   timestamp – full date/time string (e.g. "Mon Mar 23 13:16:46 2026")
#   rule      – the firewall rule name ("reject wan in" or "banIP/…")
#   src       – source IP address (the potential attacker)
#   dst       – destination IP/label (usually the router's WAN IP)
#   proto     – protocol (TCP, UDP, ICMP, etc.)
#   spt       – source port (optional – absent for ICMP)
#   dpt       – destination port (optional – absent for ICMP)
LOG_PATTERN = re.compile(
    r"(?P<timestamp>\w{3}\s+\w{3}\s+\d{1,2}\s+[\d:]+\s+\d{4})\s+"
    r"kern\.\w+\s+kernel:\s+\[[\d.]+\]\s+"
    r"(?P<rule>(?:reject\s+wan\s+in|banIP/\S+)):\s+"
    r".*?SRC=(?P<src>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r".*?DST=(?P<dst>\S+)\s+"
    r".*?PROTO=(?P<proto>\w+)\s*"
    r".*?(?:SPT=(?P<spt>\d+))?\s*"
    r".*?(?:DPT=(?P<dpt>\d+))?",
    re.IGNORECASE,
)


# ─────────────────────────────────────────────────────────────────
# Log parsing functions
# ─────────────────────────────────────────────────────────────────

def parse_log_file(filepath):
    # Read a firewall log file and extract structured data from each matching line.
    #
    # Inputs:
    #     filepath (str): Absolute or relative path to a plain-text log file
    #                     (.txt or .log). Each line should be a syslog-format
    #                     firewall entry containing "SRC=" fields.
    #
    # Returns:
    #     list[dict] – One dict per matched log line. Each dict contains the
    #                  named capture groups from LOG_PATTERN:
    #         {
    #             "timestamp": "Mon Mar 23 13:16:46 2026",
    #             "rule":      "banIP/inbound/drop/country.v4",
    #             "src":       "118.123.1.39",       # Source IP (potential attacker)
    #             "dst":       "xxx.xxx.xx.xx",       # Destination (our router)
    #             "proto":     "TCP",                 # Protocol
    #             "spt":       "23626",               # Source port (None for ICMP)
    #             "dpt":       "8888",                # Destination port (None for ICMP)
    #         }
    #
    # Behaviour:
    #     - Blank lines are silently skipped.
    #     - Lines that don't match the LOG_PATTERN regex are ignored – this
    #       allows mixed-content log files (e.g. with DHCP or DNS entries).
    #     - File is opened with errors="replace" to tolerate encoding issues
    #       in log files that may contain binary fragments.
    #
    # Usage:
    #     Called from NetPyINTApp.open_log_file() when the user selects a file.
    #     The returned list is then passed to aggregate_entries() for grouping.
    entries = []
    with open(filepath, "r", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Attempt to match the firewall log pattern against this line
            m = LOG_PATTERN.search(line)
            if m:
                # .groupdict() returns all named groups as a dict
                entries.append(m.groupdict())
    return entries


# Backward-compatible alias so existing callers (netpyint_main.py, tests) keep working.
_parse_log_ts = parse_ctime


def aggregate_entries(entries):
    # Group parsed log entries by source IP and collect per-IP metadata.
    #
    # Inputs:
    #     entries (list[dict]): Output from parse_log_file() – one dict per
    #                           matched log line with keys: src, rule, dpt,
    #                           spt, proto, timestamp.
    #
    # Returns:
    #     dict[str, dict] – Keyed by IP address string. Each value dict:
    #         {
    #             "hits":      int,   # Total number of log lines from this IP
    #             "rules":     set,   # Unique firewall rule names that matched
    #             "dst_ports": set,   # Unique destination ports targeted
    #             "src_ports": set,   # Unique source ports observed
    #             "protocols": set,   # Unique protocols used (TCP, UDP, ICMP)
    #             "first_ts":  str,   # Earliest timestamp string seen
    #             "last_ts":   str,   # Latest timestamp string seen
    #         }
    #
    # Behaviour:
    #     - Uses defaultdict so each new IP auto-initialises with zeroed
    #       counters and empty sets.
    #     - Source/destination ports are only added when present (ICMP entries
    #       lack port fields, so those will be None and are skipped).
    #     - Timestamps are compared as datetime objects via _parse_log_ts().
    #       Parsed datetimes are cached in _first_dt/_last_dt alongside the
    #       raw string so _parse_log_ts() is called once per entry instead
    #       of twice (once to parse, once to re-parse the stored string on
    #       every comparison).  The _first_dt/_last_dt keys are internal
    #       accumulators and are not written to the database.
    #
    # Usage:
    #     Called from NetPyINTApp.open_log_file() immediately after parse_log_file().
    #     The aggregated data is then merged into the SQLite database.
    # Auto-initialising dict: each new IP gets a fresh template
    agg = defaultdict(lambda: {
        "hits": 0, "rules": set(), "dst_ports": set(),
        "src_ports": set(), "protocols": set(),
        "first_ts": None, "last_ts": None,
        "_first_dt": None, "_last_dt": None,  # cached parsed datetimes, not written to DB
    })
    for e in entries:
        ip = e["src"]              # The source IP from the log line
        a = agg[ip]
        a["hits"] += 1             # Increment hit counter for this IP

        # Collect the firewall rule that triggered (e.g. "reject wan in")
        a["rules"].add(e.get("rule") or "unknown")

        # Collect destination port if present (absent for ICMP)
        if e.get("dpt"):
            a["dst_ports"].add(e["dpt"])

        # Collect source port if present (absent for ICMP)
        # Source ports can reveal scanning tools or botnet signatures
        if e.get("spt"):
            a["src_ports"].add(e["spt"])

        # Collect protocol (TCP, UDP, ICMP, etc.)
        if e.get("proto"):
            a["protocols"].add(e["proto"])

        # Track earliest and latest timestamps for this IP.
        # _first_dt/_last_dt cache the parsed datetime so _parse_log_ts() is
        # called once per entry instead of twice (old code re-parsed the stored
        # string on every comparison, causing O(2N) strptime calls per IP).
        ts = e.get("timestamp")
        if ts:
            ts_dt = _parse_log_ts(ts)
            if ts_dt is not None:
                if a["_first_dt"] is None or ts_dt < a["_first_dt"]:
                    a["first_ts"] = ts
                    a["_first_dt"] = ts_dt
                if a["_last_dt"] is None or ts_dt > a["_last_dt"]:
                    a["last_ts"] = ts
                    a["_last_dt"] = ts_dt
    return agg
