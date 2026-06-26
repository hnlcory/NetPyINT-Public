#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════╗
# ║              NetPyINT - Cyber Threat Intelligence Tool           ║
# ║      Firewall Log Analysis & OSINT IP Reputation Aggregator      ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# Parses firewall WAN reject / banIP logs, queries multiple OSINT
# platforms, scores and categorises every source IP, and exports a
# daily blocklist ready for router import.
#
# Supported OSINT platforms:
#   • AbuseIPDB         • VirusTotal        • Shodan
#   • GreyNoise         • AlienVault OTX    • IPInfo
#   • ip-api.com (free) • DNS reverse lookup
#
# Author : NetPyINT Project
# License: MIT

# ─────────────────────────────────────────────────────────────────
# Standard library imports
# ─────────────────────────────────────────────────────────────────
import tkinter as tk                           # Core GUI framework for the desktop application
from tkinter import ttk, filedialog, messagebox, scrolledtext  # Themed widgets, file dialogs, popups, scrollable text
import os                                      # File system checks (config existence, etc.)
import sys                                     # Python executable path for subprocess launching
import platform                               # OS detection for font selection
import subprocess                              # Launch companion scripts (log_helper.py) as separate processes
import copy                                     # Deep-copy config snapshot for scan workers
import json                                    # JSON encoding/decoding for API responses and config
import threading                               # Background scan thread so GUI stays responsive
import time                                    # For rate-limiter patching surface (tests patch netpyint_main.time.sleep)
import queue                                   # Thread-safe message queue between scan thread and GUI
import ipaddress                               # Validate IPs and filter out RFC1918 private ranges
from datetime import datetime, timedelta        # Timestamps for logs, scan records, and file naming
from collections import defaultdict            # Auto-initialising dicts for log aggregation
import webbrowser                              # Open URLs in the system default browser

# ─────────────────────────────────────────────────────────────────
# Helpers path — make the helpers/ subdirectory importable by flat name
# ─────────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "helpers"))

# ─────────────────────────────────────────────────────────────────
# Project module imports
# ─────────────────────────────────────────────────────────────────
from config import (
    DB_FILE, VERSION,
    THREAT_LEVELS, THREAT_COLORS, KEY_PLATFORMS,
    PLATFORM_TO_FLAG, RESULT_KEY_TO_PLATFORM, RATE_LIMIT_EXEMPT,
    THREAT_LEVEL_COLUMNS, PLATFORMS, DEFAULT_CONFIG,
    load_config, save_config,
)
from scoring import compute_threat_level
from log_parser import LOG_PATTERN, parse_log_file, _parse_log_ts, aggregate_entries
from api_requests import (
    _api_get,
    query_abuseipdb, query_virustotal, query_shodan,
    query_internetdb, query_greynoise, query_otx,
    query_proxycheck, query_ipinfo, query_ipapi_free,
    query_reverse_dns,
    RATE_LIMIT_THRESHOLD, _is_rate_limit_error,
)
from db_repository import IPRepository, init_db, _TREE_COL_TO_DB_SORT
from data_insights import build_insights_report, render_insights_text
from formatting import format_date, format_detail_date, get_threat_tag, format_score_cols, parse_idb_tags, format_country
from filter_panel import FilterPanel
import scan_engine
import export_import
import settings_dialogs
from scan_engine import _PlatformRateLimiter, _ScanContext, _Platform, _PLATFORM_REGISTRY

# ─────────────────────────────────────────────────────────────────
# Platform registry (defined here so test patches on netpyint_main.query_*
# intercept the lambda call sites; lambdas close over this module's names)
#
# IMPORTANT (M5): This registry intentionally shadows scan_engine._PLATFORM_REGISTRY.
# The two definitions must be kept in sync — any platform added, removed, or
# modified here must also be updated in helpers/scan_engine.py, and vice versa.
# This includes registry ORDER, which controls reverse_dns fallback priority (see below).
#
# Reverse DNS priority system
# ───────────────────────────
# The scan order directly determines which platform fills reverse_dns first.
# Two write tiers enforce the priority:
#
#   Tier 1 — authoritative (direct SET via update_reverse_dns):
#       DNS Reverse Lookup only.  Always overwrites any prior backfilled value,
#       so a live PTR record always takes precedence over a third-party hostname.
#
#   Tier 2 — fallback (COALESCE via backfill_reverse_dns):
#       ip-api, IPInfo, Shodan, InternetDB.  Only writes when the field is
#       currently empty; once any of these fills it, later ones are no-ops.
#
# Priority order (highest → lowest):
#   1. DNS Reverse Lookup   (r["reverse_dns"])
#   2. ip-api (free)        (r["reverse"])
#   3. IPInfo               (r["hostname"])   ← moved to pos 3 for rdns priority;
#                                               geo backfill unaffected (ip-api wins first)
#   4. Shodan               (r["hostnames"][0])
#   5. Shodan InternetDB    (r["hostnames"][0])
# ─────────────────────────────────────────────────────────────────
_PLATFORM_REGISTRY = (
    _Platform(
        name="DNS Reverse Lookup", result_key="dns", flag_col="scanned_dns",
        log_tag="DNS",
        query_fn=lambda ip, cfg: query_reverse_dns(ip),
        update_fn=lambda repo, ip, r: (
            repo.update_reverse_dns(ip, r["reverse_dns"]) if r.get("reverse_dns") else None
        ),
    ),
    _Platform(
        name="ip-api (free)", result_key="ipapi", flag_col="scanned_ipapi",
        log_tag="ip-api",
        query_fn=lambda ip, cfg: query_ipapi_free(ip),
        update_fn=lambda repo, ip, r: (
            repo.update_ipapi(ip, r.get("countryCode", ""), r.get("city", ""),
                              r.get("isp", ""), r.get("as", "")),
            repo.backfill_reverse_dns(ip, r.get("reverse", "")),  # rdns priority 2: "reverse" field
        ),
        min_delay=1.4,
    ),
    _Platform(
        # Positioned here (priority 3) so its hostname backfills before Shodan/InternetDB.
        # Geo fields (city, country) are unaffected — ip-api wins those regardless of order.
        name="IPInfo", result_key="ipinfo", flag_col="scanned_ipinfo",
        log_tag="IPInfo",
        query_fn=lambda ip, cfg: query_ipinfo(
            ip, cfg["api_keys"].get("ipinfo", "")),
        update_fn=lambda repo, ip, r: (
            repo.update_ipinfo(ip, json.dumps(r), r.get("city", ""), r.get("country", "")),
            repo.backfill_reverse_dns(ip, r.get("hostname", "")),  # rdns priority 3: "hostname" field
        ),
    ),
    _Platform(
        name="AbuseIPDB", result_key="abuseipdb", flag_col="scanned_abuseipdb",
        log_tag="AbuseIPDB", needs_key=True, log_name="AbuseIPDB",
        query_fn=lambda ip, cfg: query_abuseipdb(
            ip, cfg["api_keys"].get("abuseipdb", ""),
            cfg.get("max_abuseipdb_days", 90)),
        update_fn=lambda repo, ip, r: repo.update_abuseipdb(
            ip, r.get("abuseConfidenceScore", 0),
            r.get("country", ""), r.get("isp", "")),
    ),
    _Platform(
        name="VirusTotal", result_key="virustotal", flag_col="scanned_virustotal",
        log_tag="VirusTotal", needs_key=True, log_name="VirusTotal",
        query_fn=lambda ip, cfg: query_virustotal(
            ip, cfg["api_keys"].get("virustotal", "")),
        update_fn=lambda repo, ip, r: repo.update_virustotal(
            ip, r.get("score_pct", 0),
            str(r.get("asn", "")), r.get("country", "")),
    ),
    _Platform(
        name="Shodan", result_key="shodan", flag_col="scanned_shodan",
        log_tag="Shodan", needs_key=True, log_name="Shodan",
        query_fn=lambda ip, cfg: query_shodan(
            ip, cfg["api_keys"].get("shodan", "")),
        update_fn=lambda repo, ip, r: (
            repo.update_shodan(ip, json.dumps(r.get("ports", [])), json.dumps(r.get("vulns", [])),
                               r.get("city", ""), r.get("isp", ""), r.get("asn", "")),
            # rdns priority 4: "hostnames" is a list; use first entry if present
            repo.backfill_reverse_dns(ip, next(iter(r.get("hostnames") or []), "")),
        ),
    ),
    _Platform(
        name="Shodan InternetDB", result_key="internetdb", flag_col="scanned_internetdb",
        log_tag="InternetDB", log_name="InternetDB",
        query_fn=lambda ip, cfg: query_internetdb(ip),
        update_fn=lambda repo, ip, r: (
            repo.update_internetdb(ip, json.dumps(r.get("ports", [])), json.dumps(r.get("vulns", [])),
                                   json.dumps(r.get("tags", [])), json.dumps(r.get("cpes", []))),
            # rdns priority 5: "hostnames" is a list; use first entry if present
            repo.backfill_reverse_dns(ip, next(iter(r.get("hostnames") or []), "")),
        ),
    ),
    _Platform(
        name="GreyNoise", result_key="greynoise", flag_col="scanned_greynoise",
        log_tag="GreyNoise", log_name="GreyNoise",
        query_fn=lambda ip, cfg: query_greynoise(
            ip, cfg["api_keys"].get("greynoise", "")),
        update_fn=lambda repo, ip, r: repo.update_greynoise(
            ip, r.get("classification", ""),
            r.get("noise", False), r.get("riot", False)),
    ),
    _Platform(
        name="AlienVault OTX", result_key="otx", flag_col="scanned_otx",
        log_tag="OTX", log_name="OTX",
        query_fn=lambda ip, cfg: query_otx(ip),
        update_fn=lambda repo, ip, r: repo.update_otx(
            ip, r.get("pulse_count", 0), r.get("country", "")),
    ),
    _Platform(
        name="ProxyCheck", result_key="proxycheck", flag_col="scanned_proxycheck",
        log_tag="ProxyCheck", needs_key=True, log_name="ProxyCheck",
        query_fn=lambda ip, cfg: query_proxycheck(
            ip, cfg["api_keys"].get("proxycheck", "")),
        update_fn=lambda repo, ip, r: repo.update_proxycheck(
            ip, r.get("risk", 0), r.get("type_str", ""), json.dumps(r)),
    ),
)


# Scoring column names used to build compute_threat_level dicts for legacy rows
# (full_score == -1).  Module-level so both refresh_table() and _update_single_ip()
# share the same tuple without redefining it.
_SCORE_KEYS = (
    "abuseipdb_score", "vt_score", "shodan_vulns", "internetdb_vulns",
    "internetdb_tags", "greynoise_class", "otx_pulses", "proxycheck_type",
    "total_hits", "scanned_abuseipdb", "scanned_virustotal",
    "scanned_greynoise", "scanned_shodan", "scanned_internetdb",
    "scanned_otx", "scanned_proxycheck", "scanned_ipinfo",
    "scanned_ipapi", "scanned_dns")


def _extract_ipinfo_hostname(ipinfo_json, raw):
    # Extract IPInfo's hostname for the startup rdns backfill pass.
    # IPInfo's full response is stored in two places: the dedicated ipinfo_data column
    # (written by update_ipinfo) and inside the raw_results JSON blob (written by
    # scan_engine after each IP completes).  Checking ipinfo_data first is more reliable
    # because raw_results may be absent or truncated when a scan was interrupted mid-IP.
    # The fallback to raw["ipinfo"] handles rows where ipinfo_data is unexpectedly empty.
    try:
        d = json.loads(ipinfo_json) if ipinfo_json and ipinfo_json != "{}" else {}
        return d.get("hostname", "") or raw.get("ipinfo", {}).get("hostname", "")
    except Exception:
        return raw.get("ipinfo", {}).get("hostname", "")


def _pick_ts(a, b, use_min):
    # Compare two ctime timestamp strings; return the earlier (use_min=True) or later one.
    # Falls back gracefully if either timestamp fails to parse.
    # Returns the raw string so the DB stores the original ctime format.
    dt_a, dt_b = _parse_log_ts(a), _parse_log_ts(b)
    if dt_a is None and dt_b is None:
        return a or b
    if dt_a is None:
        return b
    if dt_b is None:
        return a
    return a if (dt_a < dt_b) == use_min else b


# ─────────────────────────────────────────────────────────────────
# Main GUI Application
# ─────────────────────────────────────────────────────────────────

class NetPyINTApp(tk.Tk):
    # The main application window and controller for the NetPyINT tool.
    #
    # Inherits from tk.Tk (the root Tkinter window). Manages all UI
    # components, database interactions, background scanning, and
    # file import/export operations.
    #
    # Architecture overview:
    #     - The GUI runs on the main thread (Tkinter is not thread-safe).
    #     - OSINT scanning runs on a background daemon thread (_scan_worker).
    #     - The two threads communicate via a thread-safe Queue (msg_queue).
    #     - A 150ms polling loop (_poll_queue) on the main thread reads
    #       messages from the queue and updates the UI accordingly.
    #
    # Key instance attributes:
    #     self.config        (dict):            Loaded configuration (API keys, prefs)
    #     self.db            (sqlite3.Connection): Database connection (shared across threads)
    #     self.scan_thread   (Thread):          Background scan thread (or None)
    #     self.scan_paused   (threading.Event): Controls pause/resume of scanning
    #     self.scan_stop     (threading.Event): Signals the scan thread to stop
    #     self.msg_queue     (queue.Queue):     Thread-safe message queue for UI updates
    #     self.scan_running  (bool):            True while a scan is in progress
    #     self.loaded_ips    (dict):            Aggregated data from the most recent log parse
    #     self.platform_vars (dict):            BooleanVars for each platform's checkbox toggle
    #     self.tree          (ttk.Treeview):    The main IP data table widget

    def __init__(self):
        # Initialise the application: load config, connect to DB, build UI.
        #
        # Inputs:  None
        # Returns: None (constructs the window and starts the event loop setup)
        #
        # Startup sequence:
        #     1. Load or create configuration file
        #     2. Connect to (or create) SQLite database
        #     3. Initialise threading primitives for background scanning
        #     4. Build all UI components (styles, menu, main layout)
        #     5. Start the queue polling loop for cross-thread communication
        #     6. Populate the IP table from existing database records
        print("[NetPyINT] Starting...", flush=True)
        super().__init__()
        self.title(f"NetPyINT  ─  Cyber Threat Intelligence  v{VERSION}")
        self.geometry("1440x900")          # Default window size
        self.minsize(1100, 700)            # Prevent shrinking below usable size
        self.configure(bg="#0f172a")        # Dark navy background

        # Style the Combobox dropdown list (the popup portion uses Tk's
        # option database, not ttk styles, so we set it here)
        self.option_add("*TCombobox*Listbox*Background", "#1e293b")
        self.option_add("*TCombobox*Listbox*Foreground", "#e2e8f0")
        self.option_add("*TCombobox*Listbox*selectBackground", "#334155")
        self.option_add("*TCombobox*Listbox*selectForeground", "#38bdf8")

        # ── Application state ──
        print("[NetPyINT] Loading configuration...", flush=True)
        self.config = load_config()        # Load API keys and preferences from disk
        self._db_path = DB_FILE            # Stored so _scan_one_ip workers can open their own connections
        print("[NetPyINT] Opening database...", flush=True)
        self.db = init_db(self._db_path)   # Open/create SQLite database
        self.repo = IPRepository(self.db)  # Data access layer — all SQL goes through here
        self.scan_thread = None            # Will hold the background Thread object
        self.scan_paused = threading.Event()
        self.scan_paused.set()             # set = unblocked; clear() = paused (thread blocks on .wait())
        self.scan_stop = threading.Event() # When set, signals the scan thread to exit its loop
        self.msg_queue = queue.Queue()     # Thread-safe queue: scan thread → GUI thread
        self.scan_running = False          # Guard flag to prevent starting duplicate scans
        self.loaded_ips = {}               # ip → aggregated data from the most recent log parse
        self._current_sort = None          # (col, reverse) tuple tracking user's active sort, or None for default
        self._sort_col_reverse = {}        # Per-column sort direction toggle: col → bool (True = reverse)
        self._startup_loading = False      # True only during the initial refresh_table call
        self._auto_scan_after_id = None        # Tkinter after() ID for the scheduled auto-scan timer
        self._auto_scan_post_delay_pending = False  # True when a scan was auto-launched with post-delay on

        # ── Build UI components ──
        print("[NetPyINT] Building interface...", flush=True)
        self._build_styles()               # Configure ttk theme colours and fonts
        self._build_menu()                 # Create the File / Settings / Help menu bar
        self._build_ui()                   # Build the main layout (table, sidebar, tabs)
        self._poll_queue()                 # Start the 150ms polling loop for queue messages
        print("[NetPyINT] Checking threat levels...", flush=True)
        if self.config.get("last_key_platforms") != KEY_PLATFORMS:
            self._recompute_stale_levels()  # Fix IPs stuck at Partial after key platform changes
            self.config["last_key_platforms"] = list(KEY_PLATFORMS)
            save_config(self.config)
        self._populate_missing_scores()     # Cache full_score for any IPs still at -1 so SQL sort is correct
        self._backfill_missing_rdns()       # Fill blank reverse_dns from already-stored platform data
        self._auto_prune_scan_log()        # Remove old scan_log rows if retention is configured
        self._startup_loading = True
        self.refresh_table()               # Load any existing DB records into the table
        self._startup_loading = False
        print(flush=True)                  # newline after the final \r progress line
        if self.config.get("auto_scan_enabled", False):
            self._start_auto_scan_timer()
        self.protocol("WM_DELETE_WINDOW", self._on_close)  # Ensure WAL checkpoint on exit

    # ── Clean shutdown ────────────────────────────────────────
    def _on_close(self):
        # Flush the SQLite WAL file into the main database before exiting.
        #
        # SQLite's WAL (Write-Ahead Logging) mode batches writes into a
        # separate -wal file and only merges them into the main .db file
        # when the WAL grows large (auto-checkpoint) or when explicitly
        # requested.  With small scans the WAL may never reach the
        # auto-checkpoint threshold, leaving new data outside the .db file.
        # Since the -wal/-shm files are not tracked in version control,
        # switching Git branches without checkpointing first silently
        # discards any un-merged scan data.
        #
        # TRUNCATE mode checkpoints all frames and resets the WAL to zero
        # length, so the .db file contains the complete dataset and the
        # stale -wal/-shm files are no longer needed.
        self._cancel_auto_scan_timer()
        try:
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")  # flush -wal file into main .db
            self.db.close()
        except Exception:
            pass
        self.destroy()

    # ── Startup migration ─────────────────────────────────────
    def _recompute_stale_levels(self):
        # Recompute threat levels for IPs that may be stuck at 'Partial'
        # due to changes in KEY_PLATFORMS requirements.
        #
        # Inputs:  None (queries self.db)
        # Returns: None (updates threat_level / full_score for changed rows)
        #
        # Behavior:
        #     - Fetches all Partial IPs including their cached full_score.
        #     - Runs compute_threat_level() against the CURRENT KEY_PLATFORMS list.
        #     - Skips rows where the level remains 'Partial' and the cached
        #       score hasn't changed (avoids unnecessary UPDATE statements).
        #     - Writes only changed rows in a single executemany batch.
        #     - Runs once at startup; a no-op if nothing needs fixing.
        #
        # Handles the scenario where KEY_PLATFORMS was changed (e.g. GreyNoise
        # removed) and existing IPs already have enough data for a final verdict
        # but are stuck at 'Partial' from the old requirement set.
        partials = self.repo.get_partial_scoring_data(THREAT_LEVEL_COLUMNS)

        if not partials:
            return

        n = len(partials)
        print(f"\r[NetPyINT]   -> Recomputing {n:,} partial IPs...", end="", flush=True)

        # Collect only rows that actually need a write (level or score changed).
        # Skipping unchanged rows avoids N UPDATE statements at startup when
        # most Partial IPs have already been scored on a previous session.
        _last_pct = -1
        batch = []
        for i, data in enumerate(partials, 1):
            ip           = data.pop("ip")
            cached_score = data.pop("full_score") or -1.0
            level, score = compute_threat_level(data)
            # Skip if still Partial and the cached score is already correct
            # (within floating-point rounding). Level promotions always write.
            if not (level == "Partial" and abs(score - cached_score) < 0.01):
                batch.append((level, score, ip))
            pct = i * 100 // n
            if pct // 10 > _last_pct // 10:
                _last_pct = pct
                print(f"\r[NetPyINT]   -> Recomputing {n:,} partial IPs: {pct:>3}%",
                      end="", flush=True)

        if batch:
            self.repo.update_threat_levels_batch(batch)
            self.repo.commit()
            promoted = sum(1 for level, _, _ in batch if level != "Partial")
            suffix = f" ({promoted} promoted)" if promoted else ""
            print(f"\r[NetPyINT]   -> Recomputed {n:,} partial IPs{suffix}.{' ' * 20}",
                  flush=True)
            if promoted:
                self._log(f"Startup: recomputed {promoted} IPs from Partial → final level "
                          f"(KEY_PLATFORMS updated to {KEY_PLATFORMS})")
        else:
            print(f"\r[NetPyINT]   -> Recomputed {n:,} partial IPs (no changes).{' ' * 20}",
                  flush=True)

    def _populate_missing_scores(self):
        # Compute and cache full_score for every IP still at the DB sentinel (-1).
        #
        # When IPs are inserted from a log import they get full_score = -1
        # (the column default).  SQL ORDER BY full_score would then place those
        # IPs incorrectly in a score sort even though compute_threat_level()
        # gives them a real score (e.g. from hit frequency alone).
        #
        # This method is called at startup AND immediately after every log import
        # (open_log_file) so full_score is always populated before the table is
        # displayed.  After both paths run the set of -1 IPs is empty and
        # subsequent calls are a near-zero-cost SELECT that returns no rows.
        rows = self.repo.get_ips_with_missing_scores(THREAT_LEVEL_COLUMNS)

        if not rows:
            return

        n = len(rows)
        print(f"\r[NetPyINT]   -> Scoring {n:,} unscored IPs...", end="", flush=True)

        _last_pct = -1
        batch = []
        for i, row in enumerate(rows, 1):
            ip       = row[0]
            # row[1] is threat_level (not used in score calc); scoring data starts at row[2]
            data     = dict(zip(THREAT_LEVEL_COLUMNS, row[2:]))
            level, score = compute_threat_level(data)
            batch.append((level, score, ip))
            pct = i * 100 // n
            if pct // 10 > _last_pct // 10:
                _last_pct = pct
                print(f"\r[NetPyINT]   -> Scoring {n:,} unscored IPs: {pct:>3}%",
                      end="", flush=True)

        self.repo.update_threat_levels_batch(batch, record_history=False)
        self.repo.commit()
        print(f"\r[NetPyINT]   -> Scored {n:,} IPs.{' ' * 30}", flush=True)
        self._log(f"Startup: cached full_score for {len(batch)} unscored IP(s).")

    def _backfill_missing_rdns(self):
        # Retroactively fill blank reverse_dns fields from platform data already in the DB.
        # Runs once at startup — no API calls are made.  scan_engine writes every platform's
        # full API response into the raw_results JSON column at the end of each IP's scan,
        # so hostname data from ip-api, IPInfo, Shodan, and InternetDB is recoverable here
        # without re-querying any external service.
        #
        # Priority applied (mirrors registry order and the per-scan backfill logic):
        #   dns["reverse_dns"] → ipapi["reverse"] → IPInfo hostname → shodan["hostnames"][0]
        #   → internetdb["hostnames"][0]
        #
        # The batch executemany call at the end uses COALESCE so it is safe if any rows
        # already gained a value between the initial SELECT and the final UPDATE.
        rows = self.repo.get_missing_rdns_batch()
        if not rows:
            return
        n = len(rows)
        print(f"\r[NetPyINT]   -> Backfilling rdns for {n:,} IPs...", end="", flush=True)
        changes = []
        for ip, raw_json, ipinfo_json in rows:
            try:
                raw = json.loads(raw_json) if raw_json and raw_json != "{}" else {}
            except Exception:
                raw = {}
            # Walk priority order; Python short-circuits on the first truthy value.
            hostname = (
                raw.get("dns", {}).get("reverse_dns", "")
                or raw.get("ipapi", {}).get("reverse", "")
                or _extract_ipinfo_hostname(ipinfo_json, raw)
                or next(iter(raw.get("shodan", {}).get("hostnames") or []), "")
                or next(iter(raw.get("internetdb", {}).get("hostnames") or []), "")
            )
            if hostname:
                changes.append((ip, hostname))
        if changes:
            self.repo.update_reverse_dns_batch(changes)
            self.repo.commit()
            print(f"\r[NetPyINT]   -> Backfilled rdns for {len(changes):,}/{n:,} IPs.{' ' * 20}",
                  flush=True)
            self._log(f"Startup: backfilled reverse_dns for {len(changes)} IP(s) from stored platform data.")
        else:
            print(f"\r[NetPyINT]   -> Backfilling rdns: none resolved.{' ' * 30}", flush=True)

    # ── Styles ────────────────────────────────────────────────────
    def _build_styles(self):
        # Configure the ttk theme with a custom dark colour palette.
        #
        # Inputs:  None (reads no parameters)
        # Returns: None (modifies the global ttk.Style in-place)
        #
        # Sets up named styles for:
        #     - Default widgets (TFrame, TLabel, TButton, TCheckbutton)
        #     - Accent.TButton (blue highlight for primary actions)
        #     - Stop.TButton (red for the stop scan button)
        #     - Treeview and Treeview.Heading (the IP data table)
        #     - TNotebook and TNotebook.Tab (detail/log/parsed tabs)
        #     - Horizontal.TProgressbar (scan progress bar)
        #     - TLabelframe (grouped settings sections)
        #
        # Colour scheme:
        #     BG   = #0f172a  (dark navy – main background)
        #     BG2  = #1e293b  (slightly lighter – input fields, table rows)
        #     FG   = #e2e8f0  (light grey – primary text)
        #     ACC  = #38bdf8  (sky blue – accent highlights, headings)
        style = ttk.Style(self)
        style.theme_use("clam")

        BG = "#0f172a"
        FG = "#e2e8f0"
        BG2 = "#1e293b"
        ACC = "#38bdf8"
        style.configure(".", background=BG, foreground=FG, fieldbackground=BG2,
                         borderwidth=0, font=("Consolas", 10))
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=FG, font=("Segoe UI", 10))
        style.configure("Title.TLabel", font=("Segoe UI", 13, "bold"), foreground=ACC)
        style.configure("TButton", background="#334155", foreground=FG, padding=(12, 6),
                         font=("Segoe UI", 10, "bold"))
        style.map("TButton",
                   background=[("active", ACC), ("disabled", "#1e293b")],
                   foreground=[("active", "#0f172a"), ("disabled", "#475569")])
        style.configure("Accent.TButton", background=ACC, foreground="#0f172a")
        style.map("Accent.TButton",
                   background=[("active", "#7dd3fc"), ("disabled", "#1e293b")])
        style.configure("Stop.TButton", background="#dc2626", foreground="#fff")
        style.map("Stop.TButton", background=[("active", "#ef4444")])
        # Same look as the default TButton until hovered, then turns the same
        # red as Stop.TButton's hover — used for destructive filter actions
        # (Clear All / Delete / Clear All Advanced Filters) that shouldn't
        # look alarming at rest but should signal "this clears things" on hover.
        style.configure("DangerHover.TButton", background="#334155", foreground=FG,
                         padding=(12, 6), font=("Segoe UI", 10, "bold"))
        style.map("DangerHover.TButton",
                   background=[("active", "#ef4444"), ("disabled", "#1e293b")],
                   foreground=[("active", "#fff"), ("disabled", "#475569")])
        style.configure("TCheckbutton", background=BG, foreground=FG,
                         font=("Segoe UI", 10))

        # Treeview
        style.configure("Treeview",
                         background=BG2, foreground=FG, fieldbackground=BG2,
                         rowheight=26, font=("Consolas", 10))
        style.configure("Treeview.Heading",
                         background="#334155", foreground=ACC,
                         font=("Segoe UI", 10, "bold"))
        style.map("Treeview",
                   background=[("selected", "#334155")],
                   foreground=[("selected", "#fff")])

        # Notebook
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background="#1e293b", foreground=FG,
                         padding=(14, 6), font=("Segoe UI", 10))
        style.map("TNotebook.Tab",
                   background=[("selected", "#334155")],
                   foreground=[("selected", ACC)])

        # Progressbar
        style.configure("Horizontal.TProgressbar",
                         background=ACC, troughcolor=BG2, thickness=8)

        # Labelframe
        style.configure("TLabelframe", background=BG, foreground=ACC)
        style.configure("TLabelframe.Label", background=BG, foreground=ACC,
                         font=("Segoe UI", 10, "bold"))

        # Combobox (used for the filter dropdown in the sidebar)
        style.configure("TCombobox", fieldbackground=BG2, background="#334155",
                         foreground=FG, arrowcolor=ACC,
                         font=("Consolas", 9))
        style.map("TCombobox",
                   fieldbackground=[("readonly", BG2)],
                   foreground=[("readonly", FG)],
                   selectbackground=[("readonly", "#334155")],
                   selectforeground=[("readonly", FG)])

    # ── Menu bar ──────────────────────────────────────────────────
    def _build_menu(self):
        # Create the application menu bar with File, Settings, and Help menus.
        #
        # Inputs:  None
        # Returns: None (attaches the menu bar to the root window)
        #
        # Menu structure:
        #     File:
        #         Open Log File…     → self.open_log_file()
        #         Export Blocklist…   → self.export_blocklist()
        #         Export Full Report… → self.export_json()
        #         Clear Database…     → self.clear_database()
        #         Exit                → self.quit()
        #     Settings:
        #         API Keys…           → self.show_api_settings()
        #         Scan Settings…      → self.show_scan_settings()
        #     Help:
        #         About               → Shows version/description dialog
        menubar = tk.Menu(self, bg="#1e293b", fg="#e2e8f0",
                          activebackground="#38bdf8", activeforeground="#0f172a",
                          font=("Segoe UI", 10))

        file_menu = tk.Menu(menubar, tearoff=0, bg="#1e293b", fg="#e2e8f0",
                            font=("Segoe UI", 10))
        file_menu.add_command(label="Open Log File…", command=self.open_log_file)
        file_menu.add_command(label="Export Blocklist…", command=self.export_blocklist)
        file_menu.add_command(label="Export Full Report (JSON)…", command=self.export_json)
        file_menu.add_command(label="Import Full Report (JSON)…", command=self.import_json)
        file_menu.add_separator()
        file_menu.add_command(label="Clear Database…", command=self.clear_database)
        file_menu.add_command(label="Prune Scan Log…", command=self.prune_scan_log_dialog)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        settings_menu = tk.Menu(menubar, tearoff=0, bg="#1e293b", fg="#e2e8f0",
                                font=("Segoe UI", 10))
        settings_menu.add_command(label="API Keys…", command=self.show_api_settings)
        settings_menu.add_command(label="Scan Settings…", command=self.show_scan_settings)
        settings_menu.add_separator()
        # Auto-stop toggle: stops scan when all platforms report consecutive rate limits
        self.var_auto_stop = tk.BooleanVar(
            value=self.config.get("auto_stop_rate_limit", True))
        settings_menu.add_checkbutton(
            label="Auto-Stop on Rate Limits",
            selectcolor="white",
            variable=self.var_auto_stop,
            command=self._toggle_auto_stop)
        # Whether the Advanced Filter Controls panel starts collapsed at
        # launch. Only affects the NEXT launch — does not collapse/expand
        # the panel in the current session.
        self.var_hide_advanced_filters = tk.BooleanVar(
            value=self.config.get("start_advanced_filters_hidden", True))
        settings_menu.add_checkbutton(
            label="Start with Advanced Filters Hidden",
            selectcolor="white",
            variable=self.var_hide_advanced_filters,
            command=self._toggle_advanced_filters_start_hidden)
        menubar.add_cascade(label="Settings", menu=settings_menu)

        help_menu = tk.Menu(menubar, tearoff=0, bg="#1e293b", fg="#e2e8f0",
                            font=("Segoe UI", 10))
        help_menu.add_command(label="About", command=lambda: messagebox.showinfo(
            "About NetPyINT",
            f"NetPyINT v{VERSION}\n\n"
            "Firewall Log Analyser & OSINT IP Reputation Aggregator"))
        menubar.add_cascade(label="Help", menu=help_menu)

        self.configure(menu=menubar)

    # ── Main UI ───────────────────────────────────────────────────
    def _build_ui(self):
        # Construct the main application layout with all widgets.
        #
        # Inputs:  None
        # Returns: None (populates the root window with frames and widgets)
        #
        # Layout structure (top to bottom):
        #     ┌─────────────────────────────────────────────────┐
        #     │ Top bar: title label + action buttons           │
        #     │   [Load Log] [Scan IPs] [Pause] [Stop] [Export] │
        #     ├─────────────────────────────────────────────────┤
        #     │ Progress bar + status label                     │
        #     ├──────────────────────┬──────────────────────────┤
        #     │                      │ Right sidebar:           │
        #     │  IP Data Table       │   Platform checkboxes    │
        #     │  (Treeview with      │   Threat level stats     │
        #     │   sortable columns)  │   "Scan new only" toggle │
        #     │                      │                          │
        #     ├──────────────────────┴──────────────────────────┤
        #     │ Tabbed notebook:                                │
        #     │   [IP Details] [Scan Log] [Parsed Entries]      │
        #     │   (ScrolledText widgets for each tab)           │
        #     └─────────────────────────────────────────────────┘
        #
        # Key widgets stored as instance attributes:
        #     self.tree          – Treeview (IP table, iid = IP address)
        #     self.progress      – Progressbar (scan progress)
        #     self.lbl_progress  – Label (scan status text)
        #     self.detail_text   – ScrolledText (IP detail view)
        #     self.log_text      – ScrolledText (scan activity log)
        #     self.parsed_text   – ScrolledText (raw parsed log entries)
        #     self.platform_vars – dict of BooleanVar per platform checkbox
        #     self.btn_scan/pause/stop/export – Action buttons
        # Main container
        main = ttk.Frame(self)
        main.pack(fill="both", expand=True, padx=10, pady=6)

        # ─ Top bar ─
        top = ttk.Frame(main)
        top.pack(fill="x", pady=(0, 6))

        ttk.Label(top, text="◆ NetPyINT", style="Title.TLabel").pack(side="left")

        self.btn_export = ttk.Button(top, text="Export Blocklist",
                                     command=self.export_blocklist)
        self.btn_export.pack(side="right", padx=4)

        self.btn_stop = ttk.Button(top, text="■ Stop", style="Stop.TButton",
                                   command=self.stop_scan, state="disabled")
        self.btn_stop.pack(side="right", padx=4)

        self.btn_pause = ttk.Button(top, text="⏸ Pause",
                                    command=self.toggle_pause, state="disabled")
        self.btn_pause.pack(side="right", padx=4)

        self.btn_scan = ttk.Button(top, text="▶ Scan IPs", style="Accent.TButton",
                                   command=self.start_scan)
        self.btn_scan.pack(side="right", padx=4)

        self.btn_load = ttk.Button(top, text="📂 Load Log File",
                                   command=self.open_log_file)
        self.btn_load.pack(side="right", padx=4)

        self.btn_delete = ttk.Button(top, text="🗑 Delete Selected",
                                      command=self.delete_selected_ips)
        self.btn_delete.pack(side="right", padx=4)

        self.btn_loghelper = ttk.Button(top, text="📋 Log Helper",
                                         command=self.open_log_helper)
        self.btn_loghelper.pack(side="right", padx=4)

        # ─ Progress (hidden until a scan starts) ─
        self._prog_frame = ttk.Frame(main)
        # Not packed yet — shown by start_scan / rescan_filtered, hidden by "done"
        self.lbl_progress = ttk.Label(self._prog_frame, text="Ready", width=30, anchor="w")
        self.lbl_progress.pack(side="left", padx=(60, 8))
        self.progress = ttk.Progressbar(self._prog_frame, mode="determinate")
        self.progress.pack(fill="x", side="left", expand=True, padx=(0, 60))

        # ─ Search bar ─
        self._search_frame = ttk.Frame(main)
        self._search_frame.pack(fill="x", pady=(0, 4))
        ttk.Label(self._search_frame, text="Search: ").pack(side="left", padx=(60, 0))
        self._search_var = tk.StringVar()
        self._search_entry = ttk.Entry(self._search_frame, textvariable=self._search_var,
                                        font=("Consolas", 10))
        self._search_entry.pack(side="left", fill="x", expand=True, padx=(4, 60))
        # Debounce: fire _apply_search only after typing pauses for 200 ms.
        # Each keystroke cancels the previous pending callback and schedules a
        # new one, so rapid typing never triggers an intermediate filter pass.
        self._search_debounce_id = None
        self._search_var.trace_add("write", lambda *_: self._schedule_search())
        # Search is SQL-based; _detached_rows is always empty but kept as a
        # stable attribute for the test suite and any external callers.
        self._detached_rows = set()

        # ─ Active filter summary (always visible, regardless of whether the
        #   sidebar's Coverage/Advanced Filters sections are collapsed) ─
        self._filter_summary_frame = ttk.Frame(main)
        self._filter_summary_frame.pack(fill="x", pady=(0, 4))
        self.lbl_filter_summary = ttk.Label(
            self._filter_summary_frame, text="", font=("Segoe UI", 8),
            foreground="#38bdf8")
        self.lbl_filter_summary.pack(anchor="w", padx=(60, 0))

        # ─ Content paned ─
        paned = ttk.PanedWindow(main, orient="vertical")
        paned.pack(fill="both", expand=True)

        # Upper: table + platform panel
        upper = ttk.Frame(paned)
        paned.add(upper, weight=3)

        upper_h = ttk.PanedWindow(upper, orient="horizontal")
        upper_h.pack(fill="both", expand=True)
        self._upper_h = upper_h

        # IP Table
        table_frame = ttk.Frame(upper_h)
        upper_h.add(table_frame, weight=4)

        cols = ("ip", "threat", "score", "hits", "first_seen", "last_seen",
                "country", "abuse", "vt", "otx", "type", "tags", "rdns",
                "pc_risk", "greynoise")
        col_widths = {
            "ip": 130, "threat": 90, "score": 65, "hits": 60,
            "first_seen": 115, "last_seen": 115, "country": 65,
            "abuse": 65, "vt": 65, "otx": 50, "type": 95, "rdns": 225, "tags": 145,
            "pc_risk": 110, "greynoise": 90,
        }
        col_labels = {
            "ip": "IP Address", "threat": "Threat", "score": "Score",
            "hits": "Hits", "first_seen": "First Seen", "last_seen": "Last Seen",
            "country": "CC", "abuse": "Abuse%", "vt": "VT%",
            "otx": "OTX", "type": "Type", "rdns": "Reverse DNS", "tags": "Tags",
            "pc_risk": "ProxyCheck Risk", "greynoise": "GreyNoise",
        }
        self._col_labels = col_labels

        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings",
                                  selectmode="extended")
        for c in cols:
            self.tree.heading(c, text=col_labels[c],
                              command=lambda _c=c: self._sort_tree(_c))
            self.tree.column(c, width=col_widths.get(c, 90), minwidth=40, stretch=False)

        vsb = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        # ── Right-click context menu for IP table ──
        # Provides quick actions on selected rows without needing toolbar buttons
        self.tree_menu = tk.Menu(self.tree, tearoff=0, bg="#1e293b", fg="#e2e8f0",
                                  activebackground="#38bdf8", activeforeground="#0f172a",
                                  font=("Segoe UI", 10))
        self.tree_menu.add_command(label="Delete Selected IPs",
                                    command=self.delete_selected_ips)
        self.tree_menu.add_command(label="Rescan Selected IPs",
                                    command=self.rescan_selected_ips)
        # Bind right-click (Button-3 on Linux/Windows, Button-2 on macOS)
        self.tree.bind("<Button-3>", self._show_tree_menu)
        self.tree.bind("<Button-2>", self._show_tree_menu)  # macOS right-click

        self.tree.tag_configure("Critical",  foreground=THREAT_COLORS["Critical"])
        self.tree.tag_configure("High",      foreground=THREAT_COLORS["High"])
        self.tree.tag_configure("Medium",    foreground=THREAT_COLORS["Medium"])
        self.tree.tag_configure("Low",       foreground=THREAT_COLORS["Low"])
        self.tree.tag_configure("Optional",  foreground=THREAT_COLORS["Optional"])
        self.tree.tag_configure("No Threat", foreground=THREAT_COLORS["No Threat"])
        self.tree.tag_configure("Partial",   foreground=THREAT_COLORS["Partial"])
        self.tree.tag_configure("Pending",   foreground=THREAT_COLORS["Pending"])
        # cc_hl sets only background so it never fights the threat-level foreground.
        # Rows whose CC column matches a user-configured code get a rose tint;
        # the ★ prefix on the CC value itself pinpoints which column triggered it.
        self.tree.tag_configure("cc_hl", background="#3a0f1f")
        self._cc_highlight = set(
            c.upper().strip()
            for c in self.config.get("cc_highlight_codes", [])
            if c.strip()
        )

        # Right panel: platform toggles + stats + filter (scrollable)
        # Wrapping in a Canvas+Scrollbar so all content is accessible even
        # on smaller screens where the sidebar overflows vertically.
        right_outer = ttk.Frame(upper_h, width=230)
        upper_h.add(right_outer, weight=1)

        # Canvas provides scrolling; the inner frame holds all widgets
        right_canvas = tk.Canvas(right_outer, bg="#0f172a", highlightthickness=0,
                                  width=220)
        right_scrollbar = ttk.Scrollbar(right_outer, orient="vertical",
                                         command=right_canvas.yview)
        right = ttk.Frame(right_canvas)  # This frame holds all sidebar content

        # Bind the inner frame's size changes to update the canvas scroll region
        right.bind("<Configure>",
                   lambda e: right_canvas.configure(scrollregion=right_canvas.bbox("all")))
        right_canvas.create_window((0, 0), window=right, anchor="nw")
        right_canvas.configure(yscrollcommand=right_scrollbar.set)

        # Pack canvas and scrollbar into the outer frame
        right_canvas.pack(side="left", fill="both", expand=True)
        right_scrollbar.pack(side="right", fill="y")

        # Enable mousewheel scrolling ONLY when hovering over the sidebar
        # Using enter/leave binding to avoid interfering with the main table
        # and ScrolledText widgets elsewhere in the UI
        def _on_sidebar_mousewheel(event):
            # Scroll the sidebar canvas in response to mousewheel events.
            #
            # Handles cross-platform scroll events:
            #   - Windows/macOS: event.delta is ±120 per notch; divide by 120 for units.
            #   - Linux: Button-4 (scroll up) and Button-5 (scroll down) events.
            # Windows/macOS use event.delta; Linux uses Button-4/5
            if event.delta:
                right_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            elif event.num == 4:
                right_canvas.yview_scroll(-3, "units")
            elif event.num == 5:
                right_canvas.yview_scroll(3, "units")

        def _bind_sidebar_scroll(event):
            # Activate mousewheel scrolling when mouse enters the sidebar.
            right_canvas.bind_all("<MouseWheel>", _on_sidebar_mousewheel)
            right_canvas.bind_all("<Button-4>", _on_sidebar_mousewheel)
            right_canvas.bind_all("<Button-5>", _on_sidebar_mousewheel)

        def _unbind_sidebar_scroll(event):
            # Deactivate mousewheel scrolling when mouse leaves the sidebar.
            right_canvas.unbind_all("<MouseWheel>")
            right_canvas.unbind_all("<Button-4>")
            right_canvas.unbind_all("<Button-5>")

        right_canvas.bind("<Enter>", _bind_sidebar_scroll)
        right_canvas.bind("<Leave>", _unbind_sidebar_scroll)

        ttk.Label(right, text="OSINT Platforms", style="Title.TLabel").pack(
            anchor="w", padx=8, pady=(4, 8))

        self.platform_vars = {}
        for p in PLATFORMS:
            var = tk.BooleanVar(value=self.config["enabled_platforms"].get(p, True))
            cb = ttk.Checkbutton(right, text=p, variable=var,
                                  command=self._save_platform_prefs)
            cb.pack(anchor="w", padx=12, pady=2)
            self.platform_vars[p] = var

        # Select All / Clear All buttons for platform checkboxes
        plat_btn_frame = ttk.Frame(right)
        plat_btn_frame.pack(anchor="w", padx=12, pady=(4, 0))
        ttk.Button(plat_btn_frame, text="Select All",
                   command=self._select_all_platforms).pack(side="left", padx=(0, 4))
        ttk.Button(plat_btn_frame, text="Clear All", style="DangerHover.TButton",
                   command=self._deselect_all_platforms).pack(side="left")

        ttk.Separator(right, orient="horizontal").pack(fill="x", padx=8, pady=10)

        # Stats labels
        self.stats_frame = ttk.Frame(right)
        self.stats_frame.pack(fill="x", padx=8)
        self.lbl_total_ips = ttk.Label(self.stats_frame, text="Total IPs: 0")
        self.lbl_total_ips.pack(anchor="w", pady=1)
        self.lbl_scanned = ttk.Label(self.stats_frame, text="Scanned: 0")
        self.lbl_scanned.pack(anchor="w", pady=1)
        self.lbl_critical = ttk.Label(self.stats_frame, text="Critical: 0",
                                       foreground=THREAT_COLORS["Critical"])
        self.lbl_critical.pack(anchor="w", pady=1)
        self.lbl_high = ttk.Label(self.stats_frame, text="High: 0",
                                   foreground=THREAT_COLORS["High"])
        self.lbl_high.pack(anchor="w", pady=1)
        self.lbl_medium = ttk.Label(self.stats_frame, text="Medium: 0",
                                     foreground=THREAT_COLORS["Medium"])
        self.lbl_medium.pack(anchor="w", pady=1)
        self.lbl_partial = ttk.Label(self.stats_frame, text="Partial: 0",
                                     foreground=THREAT_COLORS["Partial"])
        self.lbl_partial.pack(anchor="w", pady=1)
        self.lbl_low = ttk.Label(self.stats_frame, text="Low: 0",
                                   foreground=THREAT_COLORS["Low"])
        self.lbl_low.pack(anchor="w", pady=1)

        self.lbl_pending = ttk.Label(self.stats_frame, text="Pending: 0",
                                      foreground=THREAT_COLORS["Pending"])
        self.lbl_pending.pack(anchor="w", pady=1)
        self.lbl_optional = ttk.Label(self.stats_frame, text="Optional: 0",
                                       foreground=THREAT_COLORS.get("Optional", "#94a3b8"))
        self.lbl_optional.pack(anchor="w", pady=1)
        self.lbl_no_threat = ttk.Label(self.stats_frame, text="No Threat: 0",
                                        foreground=THREAT_COLORS.get("No Threat", "#94a3b8"))
        self.lbl_no_threat.pack(anchor="w", pady=1)
        self.lbl_blocked = ttk.Label(self.stats_frame, text="Blocklist ready: 0")
        self.lbl_blocked.pack(anchor="w", pady=1)

        ttk.Separator(right, orient="horizontal").pack(fill="x", padx=8, pady=10)

        # Scan-new-only toggle
        self.var_new_only = tk.BooleanVar(value=self.config.get("scan_new_only", False))
        ttk.Checkbutton(right, text="Scan new IPs only",
                         variable=self.var_new_only).pack(anchor="w", padx=12)

        # Auto Start Scan toggle
        self.var_auto_scan = tk.BooleanVar(value=self.config.get("auto_scan_enabled", False))
        ttk.Checkbutton(right, text="Auto Start Scan",
                         variable=self.var_auto_scan,
                         command=self._toggle_auto_scan).pack(anchor="w", padx=12)
        self.lbl_auto_scan_status = ttk.Label(
            right, text="", font=("Segoe UI", 8), foreground="#64748b")
        self.lbl_auto_scan_status.pack(anchor="w", padx=24, pady=(0, 2))

        ttk.Separator(right, orient="horizontal").pack(fill="x", padx=8, pady=10)

        # ── Filter & Rescan section ──
        # Dropdown to filter the table by scan coverage gaps. Collapsible via
        # the ▼/▶ triangle, same idiom as the Advanced Filter Controls panel
        # below — starts expanded (unlike the Advanced panel, which starts
        # collapsed).
        self._coverage_collapsed = False
        self.lbl_coverage_title = ttk.Label(right, text="▼ Filter by Coverage",
                                            style="Title.TLabel", cursor="hand2")
        self.lbl_coverage_title.pack(anchor="w", padx=8, pady=(4, 4))
        self.lbl_coverage_title.bind("<Button-1>",
                                     lambda e: self._toggle_coverage_collapsed())

        self._coverage_body = ttk.Frame(right)
        self._coverage_body.pack(fill="x")
        coverage_body = self._coverage_body

        # Build filter options: fixed headers, one per platform (Missing:), then by threat level,
        # then the country-highlight filter (requires CC Highlight codes to be configured).
        self.filter_options = ["All IPs", "Partial (incomplete scans)", "Pending (not scanned)"]
        for p in PLATFORMS:
            self.filter_options.append(f"Missing: {p}")
        for lvl in ("Critical", "High", "Medium", "Partial", "Low", "Optional", "No Threat"):
            self.filter_options.append(f"Threat: {lvl}")
        self.filter_options.append("Country: Highlighted")

        self.var_filter = tk.StringVar(value="All IPs")
        self.filter_combo = ttk.Combobox(coverage_body, textvariable=self.var_filter,
                                          values=self.filter_options, state="readonly",
                                          width=24, font=("Consolas", 9))
        self.filter_combo.pack(anchor="w", padx=12, pady=(0, 6))
        self.filter_combo.bind("<<ComboboxSelected>>",
                               lambda e: self._on_filter_changed())

        # Label showing count of IPs matching the current filter
        self.lbl_filter_count = ttk.Label(coverage_body, text="")
        self.lbl_filter_count.pack(anchor="w", padx=12, pady=(0, 4))

        # Rescan button: rescans only the filtered IPs, querying only their missing platforms
        self.btn_rescan_filtered = ttk.Button(
            coverage_body, text="▶ Rescan Filtered", style="Accent.TButton",
            command=self.rescan_filtered_ips)
        self.btn_rescan_filtered.pack(anchor="w", padx=12, pady=(0, 4))

        # Recalculate button: recomputes threat levels from existing DB data
        # without making any API calls. Useful after changing KEY_PLATFORMS
        # or scoring weights, or to promote Partial IPs that now have enough data.
        self.btn_recalculate = ttk.Button(
            coverage_body, text="🔄 Recalculate Levels",
            command=self.recalculate_threat_levels)
        self.btn_recalculate.pack(anchor="w", padx=12, pady=(0, 4))

        self._coverage_sep = ttk.Separator(right, orient="horizontal")
        self._coverage_sep.pack(fill="x", padx=8, pady=10)

        # ── Advanced Filter Controls ──
        # AND-combines with the "Filter by Coverage" dropdown above and with
        # each other. Session-only — not persisted to netpyint_config.json,
        # consistent with self.var_filter (defaults to "All IPs" every launch).
        self._filter_panel = FilterPanel(
            right, self.repo, on_change=self._on_filter_changed,
            config=self.config, save_config_fn=save_config,
            start_collapsed=self.config.get("start_advanced_filters_hidden", True))

        # Lower: notebook with details + log
        lower = ttk.Notebook(paned)
        self._lower_notebook = lower
        paned.add(lower, weight=2)
        def _set_sash(event):
            # Set the vertical sash position so the bottom notebook starts ~307px from
            # the window bottom. Unbinds itself after the first <Configure> event so
            # it only fires once on initial layout — not on every subsequent resize.
            paned.sashpos(0, event.height - 307)
            paned.unbind("<Configure>")
        paned.bind("<Configure>", _set_sash)

        # Detail tab
        detail_frame = ttk.Frame(lower)
        lower.add(detail_frame, text="  IP Details  ")
        # Menlo on macOS has proper box-drawing glyphs (═, ─, █, etc.) at a
        # fixed character width, matching the Data Insights tab. Consolas on
        # macOS falls back to a variable-width system font for those code points,
        # causing section headers like ══ TITLE ═══ to render at inconsistent
        # widths and ═ to appear as a single solid bar instead of a double line.
        _detail_font = ("Menlo", 10) if platform.system() == "Darwin" else ("Consolas", 10)
        self.detail_text = scrolledtext.ScrolledText(
            detail_frame, bg="#1e293b", fg="#e2e8f0", insertbackground="#38bdf8",
            font=_detail_font, wrap="word", state="disabled",
            relief="flat", padx=10, pady=8)
        self.detail_text.pack(fill="both", expand=True)

        # Hyperlink tag for clickable platform names in the detail view.
        # A single widget-level binding reads self._detail_links so new IPs
        # never stack extra callbacks on top of old ones.
        self._detail_links = {}  # tag_name → url, updated per _show_detail call
        for _tag in ("hyperlink", "hyperlink_vt", "hyperlink_otx",
                     "hyperlink_proxycheck", "hyperlink_greynoise"):
            self._configure_hyperlink_tag(_tag)

        # Data Insights tab (index 1 — between IP Details and Scan Log)
        # Menlo on macOS: has proper block-char glyphs so █/░ render at the same
        # width as ASCII, keeping bar columns visually aligned. Consolas on macOS
        # lacks these glyphs and falls back to a variable-width system font.
        _insights_font = ("Menlo", 9) if platform.system() == "Darwin" else ("Consolas", 9)
        insights_frame = ttk.Frame(lower)
        lower.add(insights_frame, text="  Data Insights  ")
        self.insights_text = scrolledtext.ScrolledText(
            insights_frame, bg="#1e293b", fg="#e2e8f0", insertbackground="#38bdf8",
            font=_insights_font, wrap="none", state="disabled",
            relief="flat", padx=10, pady=8)
        self.insights_text.pack(fill="both", expand=True)

        def _on_tab_changed(_event):
            if self._lower_notebook.index(self._lower_notebook.select()) == 1:
                self.refresh_insights()
        lower.bind("<<NotebookTabChanged>>", _on_tab_changed)

        # Log tab
        log_frame = ttk.Frame(lower)
        lower.add(log_frame, text="  Scan Log  ")
        self.log_text = scrolledtext.ScrolledText(
            log_frame, bg="#1e293b", fg="#94a3b8", insertbackground="#38bdf8",
            font=("Consolas", 9), wrap="word", state="disabled",
            relief="flat", padx=10, pady=8)
        self.log_text.pack(fill="both", expand=True)

        # Parsed log tab
        parsed_frame = ttk.Frame(lower)
        lower.add(parsed_frame, text="  Parsed Entries  ")
        self.parsed_text = scrolledtext.ScrolledText(
            parsed_frame, bg="#1e293b", fg="#94a3b8", insertbackground="#38bdf8",
            font=("Consolas", 9), wrap="word", state="disabled",
            relief="flat", padx=10, pady=8)
        self.parsed_text.pack(fill="both", expand=True)

        # Set the horizontal sash so the right panel starts wide enough to
        # show its scrollbar without the user having to drag it manually.
        # Retries until winfo_width() returns a real value (> 1) since the
        # window may not be fully laid out on the first idle cycle.
        def _set_sash():
            # Position the horizontal PanedWindow sash to give the sidebar a
            # fixed 310px width on startup.
            #
            # Deferred via after_idle() because winfo_width() returns 1 until
            # the window is fully drawn — this retry loop polls until the real
            # width is available, then sets sashpos(0) to width-310.
            self.update_idletasks()
            w = self._upper_h.winfo_width()
            if w > 100:
                self._upper_h.sashpos(0, w - 310)
            else:
                self.after(50, _set_sash)
        self.after_idle(_set_sash)

    # ── Platform pref save ─────────────────────────────────────
    def _save_platform_prefs(self):
        # Persist the current state of all platform checkboxes to config file.
        #
        # Inputs:  None (reads from self.platform_vars BooleanVars)
        # Returns: None (updates self.config and writes to disk)
        #
        # Called automatically whenever any platform checkbox is toggled.
        # Changes take effect immediately on the next scan – no restart needed.
        for p, var in self.platform_vars.items():
            self.config["enabled_platforms"][p] = var.get()
        save_config(self.config)

    def _select_all_platforms(self):
        # Enable all OSINT platform checkboxes and persist the setting.
        #
        # Inputs:  None (modifies self.platform_vars BooleanVars)
        # Returns: None (updates config and saves to disk)
        #
        # Usage:
        #     Called from the "Select All" button in the platform sidebar.
        #     Useful before starting a full scan to ensure no platforms
        #     were accidentally disabled from a prior session.
        for var in self.platform_vars.values():
            var.set(True)
        self._save_platform_prefs()

    def _deselect_all_platforms(self):
        # Disable all OSINT platform checkboxes and persist the setting.
        #
        # Inputs:  None (modifies self.platform_vars BooleanVars)
        # Returns: None (updates config and saves to disk)
        #
        # Usage:
        #     Called from the "Deselect All" button in the platform sidebar.
        #     Useful for selectively enabling just one or two platforms
        #     (e.g. re-running only AbuseIPDB after adding a new API key).
        for var in self.platform_vars.values():
            var.set(False)
        self._save_platform_prefs()

    # ── IP context menu & delete ───────────────────────────────

    def _show_tree_menu(self, event):
        # Show the right-click context menu at the cursor position.
        #
        # Inputs:
        #     event (tk.Event): The mouse event containing x/y coordinates.
        #
        # Returns: None (displays the context menu popup)
        #
        # Behavior:
        #     - Selects the row under the cursor if it isn't already selected,
        #       so users can right-click a row without first left-clicking it.
        #     - Only shows the menu if at least one row is selected.
        # Select the row under the cursor if not already selected
        row_id = self.tree.identify_row(event.y)
        if row_id:
            if row_id not in self.tree.selection():
                self.tree.selection_set(row_id)
            # Show context menu at cursor position
            self.tree_menu.post(event.x_root, event.y_root)

    def delete_selected_ips(self):
        # Delete the currently selected IPs from the database after confirmation.
        #
        # Inputs:  None (reads selection from self.tree)
        # Returns: None (deletes rows from 'ips' and 'scan_log' tables)
        #
        # Behavior:
        #     - Gets all currently selected rows from the Treeview (supports
        #       multi-select via Ctrl+Click or Shift+Click).
        #     - If nothing is selected, shows an info dialog and returns.
        #     - Shows a confirmation dialog listing the count and first few IPs.
        #     - On confirmation:
        #         • Deletes each IP from the 'ips' table.
        #         • Deletes associated records from the 'scan_log' audit table.
        #         • Commits the transaction.
        #         • Refreshes the table display.
        #     - On cancel: no changes are made.
        #
        # Usage:
        #     Called from the 🗑 Delete Selected button in the top bar,
        #     or from the right-click context menu → "Delete Selected IPs".
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("No selection",
                                "Select one or more IPs in the table first.")
            return

        count = len(selected)
        # Build a preview of the IPs to show in the confirmation dialog
        preview_ips = list(selected[:5])
        preview_str = "\n".join(f"  • {ip}" for ip in preview_ips)
        if count > 5:
            preview_str += f"\n  … and {count - 5} more"

        if not messagebox.askyesno(
            "Confirm Delete",
            f"Delete {count} IP(s) from the database?\n\n"
            f"{preview_str}\n\n"
            "This will remove all enrichment data, scan history, and\n"
            "scores for these IPs. This action cannot be undone."):
            return

        for ip in selected:
            self.repo.delete_ip(ip)

        self.repo.commit()
        self._log(f"Deleted {count} IP(s) from database.")
        self.refresh_table()

        # Clear the detail panel since the selected IP no longer exists
        self.detail_text.config(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.config(state="disabled")

    def open_log_helper(self):
        # Launch the companion log_helper.py script as a separate process.
        #
        # Inputs:  None
        # Returns: None (spawns a subprocess)
        #
        # Behavior:
        #     - Looks for log_helper.py in the same directory as this script.
        #     - Launches it using the same Python interpreter (sys.executable)
        #       as a detached subprocess so both GUIs run independently.
        #     - If the file is not found, shows an error dialog.
        #     - The subprocess runs fully independently — closing either
        #       window does not affect the other.
        #
        # Usage:
        #     Called from the "📋 Log Helper" button in the top bar.
        # Resolve log_helper.py inside the helpers/ subdirectory
        script_dir = os.path.dirname(os.path.abspath(__file__))
        helper_path = os.path.join(script_dir, "helpers", "log_helper.py")

        if not os.path.isfile(helper_path):
            messagebox.showerror("File Not Found",
                                 f"log_helper.py not found in:\n"
                                 f"{os.path.join(script_dir, 'helpers')}\n\n"
                                 "Ensure helpers/log_helper.py exists alongside "
                                 "netpyint_main.py.")
            return

        try:
            # Launch as a fully independent subprocess using the same Python
            # interpreter. Popen with no pipes lets it run detached.
            subprocess.Popen(
                [sys.executable, helper_path],
                cwd=script_dir,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            self._log("Launched Log Helper (log_helper.py)")
        except Exception as exc:
            messagebox.showerror("Launch Error",
                                 f"Failed to launch log_helper.py:\n{exc}")

    def rescan_selected_ips(self):
        # Rescan only the currently selected IPs, querying only platforms not yet scanned.
        #
        # Inputs:  None (reads selection from self.tree)
        # Returns: None
        #
        # Behavior:
        #     - Collects IP addresses from the Treeview selection.
        #     - Guards against an already-running scan (shows a warning if so).
        #     - Calls _launch_scan_thread(selected, rescan=True) which starts
        #       _scan_worker skipping platforms whose scanned_* flag is already 1.
        #
        # Usage:
        #     Called from the right-click context menu → "Rescan Selected IPs".
        #     Useful for re-querying a handful of specific IPs without
        #     filtering the entire table.
        selected = list(self.tree.selection())
        if not selected:
            messagebox.showinfo("No selection",
                                "Select one or more IPs in the table first.")
            return
        if self.scan_running:
            messagebox.showwarning("Scan in progress",
                                    "Please wait for the current scan to finish, "
                                    "or stop it first.")
            return

        self._log(f"Rescan starting for {len(selected)} selected IP(s)")
        self._launch_scan_thread(selected, rescan=True)

    # ── Table helpers ──────────────────────────────────────────

    def _sort_tree(self, col):
        # Sort the Treeview table by the specified column, toggling direction.
        #
        # Inputs:
        #     col (str): Column identifier (e.g. "ip", "threat", "score", "hits")
        #
        # Returns: None (reorders Treeview rows in-place)
        #
        # Behavior:
        #     - First click sorts descending; second click sorts ascending.
        #     - Attempts numeric sorting first (for score, hits, abuse%, etc.).
        #     - Falls back to alphabetical sorting if values aren't numeric.
        #     - Sort direction per column is tracked in _sort_col_reverse dict.
        #     - The current sort column and direction are saved so that
        #       refresh_table() can re-apply them after rebuilding rows.
        #
        # Usage:
        #     Bound as the command= callback on each Treeview heading.
        #     Users can click any column header to sort the IP table.
        rev = self._sort_col_reverse.get(col, True)  # True default → first click sorts descending
        # Persist state before any re-fetch so refresh_table reads the new sort.
        self._current_sort = (col, rev)
        self._sort_col_reverse[col] = not rev
        self._update_sort_arrows(col, rev)

        if col in _TREE_COL_TO_DB_SORT:
            # SQL-sortable column: re-fetch rows already ordered by the DB.
            # No Python sort or tree.move() calls needed.
            self.refresh_table()
        else:
            # "tags" is not in _TREE_COL_TO_DB_SORT (JSON array — no meaningful
            # SQL sort); fall back to in-memory sort on the displayed cell value.
            self._apply_tree_sort(col, rev)

    def _apply_tree_sort(self, col, reverse):
        # Sort the Treeview rows by column value without toggling state.
        #
        # Inputs:
        #     col     (str):  Column identifier to sort by.
        #     reverse (bool): True for descending, False for ascending.
        #
        # Returns: None (reorders Treeview rows in-place)
        #
        # This is the internal sort implementation shared by _sort_tree()
        # (user-initiated) and refresh_table() (restoring a saved sort).
        items = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]  # (cell_value, row_id)
        try:
            # replace('.','',1) strips the first decimal point; replace('-','',1) strips a leading minus,
            # leaving only digits — so "-3.5" becomes "35", which isdigit() accepts.
            items.sort(key=lambda t: float(t[0]) if t[0].replace('.','',1).replace('-','',1).isdigit() else t[0],
                       reverse=reverse)
        except Exception:
            items.sort(key=lambda t: t[0], reverse=reverse)
        for idx, (_, k) in enumerate(items):
            self.tree.move(k, "", idx)  # move() reorders without deleting/reinserting

    def _parse_filter(self):
        # Translate the active sidebar filter string into typed query parameters.
        # Returns (filt, threat_level_filter, unscanned_flag, cc_filter) so
        # callers can use the raw filt string for log messages and dialog text.
        #
        # cc_filter is None for all filters except "Country: Highlighted", where
        # it is a tuple of the currently highlighted country codes (may be empty).
        filt = self.var_filter.get() if hasattr(self, 'var_filter') else "All IPs"
        threat_level_filter = None
        unscanned_flag = None
        cc_filter = None
        if filt == "Partial (incomplete scans)":
            threat_level_filter = "Partial"
        elif filt == "Pending (not scanned)":
            threat_level_filter = "Pending"
        elif filt.startswith("Missing: "):
            flag_col = PLATFORM_TO_FLAG.get(filt[len("Missing: "):], "")  # strip prefix, look up column name
            if flag_col:
                unscanned_flag = flag_col
        elif filt.startswith("Threat: "):
            threat_level_filter = filt[len("Threat: "):]  # strip prefix, keep level name
        elif filt == "Country: Highlighted":
            cc_filter = tuple(getattr(self, '_cc_highlight', set()))  # tuple for SQL IN parameterisation
        return filt, threat_level_filter, unscanned_flag, cc_filter

    def _parse_advanced_filter(self):
        # Translate the Advanced Filter Controls panel's current widget state
        # into the kwargs accepted by IPRepository._build_filter_where()
        # (score_min/max, first_seen_days, last_seen_days, asn_isp_term,
        # country_codes, min_hits). AND-combines with _parse_filter()'s
        # output at every call site — kept as a separate method rather than
        # folded into _parse_filter() itself so that method's 4-tuple return
        # shape (depended on directly by test_netpyint.py) never changes.
        return self._filter_panel.get_filter_kwargs()

    def _update_filter_summary(self, filt, adv, search_term, filter_count):
        # Build the one-line "Filtering: ..." summary shown above the table
        # (self.lbl_filter_summary) so the active criteria stay visible
        # regardless of whether the Coverage/Advanced Filters sidebar
        # sections are collapsed. Combines every source that narrows
        # refresh_table()'s result set: the coverage dropdown, every
        # Advanced Filter Controls criterion, and the search box.
        parts = []
        if filt != "All IPs":
            parts.append(filt)
        if adv.get("score_min") is not None or adv.get("score_max") is not None:
            lo = adv.get("score_min")
            hi = adv.get("score_max")
            # Cast to int for display — the score sliders are DoubleVars, so
            # raw values are floats (e.g. 50.0) even though they're always
            # whole numbers in practice (rounded by FilterPanel itself).
            lo_s = round(lo) if lo is not None else 0
            hi_s = round(hi) if hi is not None else 100
            parts.append(f"Score {lo_s}-{hi_s}")
        if adv.get("min_hits") is not None:
            parts.append(f"Hits≥{adv['min_hits']}")
        if adv.get("first_seen_days") is not None:
            parts.append(f"First seen≤{adv['first_seen_days']}d")
        if adv.get("last_seen_days") is not None:
            parts.append(f"Last seen≤{adv['last_seen_days']}d")
        if adv.get("asn_isp_term"):
            parts.append(f"ASN/ISP~\"{adv['asn_isp_term']}\"")
        if adv.get("country_codes"):
            codes = adv["country_codes"]
            shown = ", ".join(codes[:5])
            if len(codes) > 5:
                shown += f", +{len(codes) - 5} more"
            parts.append(f"Countries: {shown}")
        if search_term:
            parts.append(f"Search \"{search_term}\"")

        if not parts:
            self.lbl_filter_summary.config(text="")
        else:
            self.lbl_filter_summary.config(
                text=f"Filtering: {' · '.join(parts)}  →  {filter_count:,} IPs")

    def _update_sort_arrows(self, active_col, reverse):
        for c, label in self._col_labels.items():
            if c == active_col:
                self.tree.heading(c, text=label + (" ↓" if reverse else " ↑"))
            else:
                self.tree.heading(c, text=label)

    def _on_filter_changed(self):
        # Handle filter dropdown changes by resetting sort and refreshing.
        #
        # Inputs:  None (reads self.var_filter)
        # Returns: None (resets sort state, then calls refresh_table)
        #
        # Behavior:
        #     - Clears the saved sort column and direction so the table
        #       reverts to the default ORDER BY total_hits DESC.
        #     - Clears the per-column toggle state so the next click on
        #       any column header starts fresh (ascending).
        #     - Refreshes the table with the new filter applied.
        #
        # Usage:
        #     Bound to the <<ComboboxSelected>> event on the filter dropdown.
        self._current_sort = None
        self._sort_col_reverse.clear()
        self._update_sort_arrows(None, False)
        self._update_coverage_title()
        self.refresh_table()

    def _toggle_coverage_collapsed(self):
        # Show/hide the "Filter by Coverage" section body (combo, count
        # label, rescan/recalculate buttons) — same ▼/▶ collapse idiom as
        # the Advanced Filter Controls panel (helpers/filter_panel.py).
        self._coverage_collapsed = not self._coverage_collapsed
        if self._coverage_collapsed:
            self._coverage_body.pack_forget()
        else:
            # before=: re-pack ahead of the separator/Advanced Filters section
            # that follow it, instead of appending to the end of right's
            # packing order (which would reorder the sidebar on every toggle).
            self._coverage_body.pack(fill="x", before=self._coverage_sep)
        self._update_coverage_title()

    def _update_coverage_title(self):
        # Mirrors FilterPanel._update_title() — keeps the active filter
        # visible (a "(Filtered)" suffix) even while the section is
        # collapsed, so a non-"All IPs" selection is never silently hidden.
        arrow = "▶" if self._coverage_collapsed else "▼"
        filt = self.var_filter.get() if hasattr(self, "var_filter") else "All IPs"
        suffix = " (Filtered)" if filt != "All IPs" else ""
        self.lbl_coverage_title.config(text=f"{arrow} Filter by Coverage{suffix}")

    def _schedule_search(self):
        # Debounce non-empty search input; apply empty-search (clear) instantly.
        #
        # Inputs:  None (reads self._search_var and self._search_debounce_id)
        # Returns: None
        #
        # Called by the _search_var trace on every change to the search field.
        #
        # Empty query (user cleared the field):
        #     Apply immediately so all rows reappear without a noticeable delay.
        #
        # Non-empty query (user is typing):
        #     Cancel any pending callback and schedule a fresh one 200 ms out.
        #     Keystrokes coalesce so the DB query fires once after typing pauses
        #     rather than on every character.
        if not self._search_var.get():
            # Clear: cancel any pending debounce, apply the empty filter right now.
            if self._search_debounce_id is not None:
                self.after_cancel(self._search_debounce_id)
                self._search_debounce_id = None
            self._apply_search()
        else:
            # Typing: reset the 200 ms timer on every keystroke.
            if self._search_debounce_id is not None:
                self.after_cancel(self._search_debounce_id)
            self._search_debounce_id = self.after(200, self._apply_search)

    def _apply_search(self):
        # Search is pushed to SQL: refresh_table() passes _search_var text to
        # get_ips_for_table(search_term=...) as a LIKE filter across ip, country,
        # reverse_dns, threat_level, greynoise_class, and proxycheck_type.
        # Only matching rows are fetched and inserted — no O(n × cols) Python
        # substring loop, no detach/reattach state to maintain.
        self.refresh_table()

    @staticmethod
    def _fmt_date(val):
        return format_date(val)

    def refresh_table(self):
        # Reload IP records from the database into the Treeview table.
        #
        # Inputs:  None (queries self.db; reads self.var_filter for active filter)
        # Returns: None (clears and repopulates self.tree; updates stats labels)
        #
        # Behavior:
        #     - Clears all existing rows from the Treeview.
        #     - Builds a SQL query filtered by the sidebar dropdown selection:
        #         • "All IPs" → no WHERE clause
        #         • "Partial (incomplete scans)" → WHERE threat_level='Partial'
        #         • "Pending (not scanned)" → WHERE threat_level='Pending'
        #         • "Missing: <Platform>" → WHERE scanned_<platform> = 0
        #     - For each IP, fetches scoring + scan flag columns to recompute
        #       the display score via compute_threat_level().
        #     - Inserts a row with colour-coded tag matching the threat level.
        #     - Updates sidebar stats from the FULL database (unfiltered),
        #       plus a filter match count from the filtered result set.
        self.tree.delete(*self.tree.get_children())

        # ── Build filter parameters for the repository ──
        filt, threat_level_filter, unscanned_flag, cc_filter = self._parse_filter()
        adv = self._parse_advanced_filter()

        # ── Derive search term and sort direction for the query ──
        # Both are pushed into SQL so no Python post-processing is needed for
        # the common case.  "tags" (JSON array) and "score" (displayed value may
        # differ from stored full_score for unscanned IPs) fall back to
        # _apply_tree_sort() after population so displayed values drive the order.
        search_term = (self._search_var.get().strip()
                       if hasattr(self, '_search_var') else None) or None

        sql_sort_col = sql_sort_asc = None
        if self._current_sort:
            sc, rev = self._current_sort
            if sc in _TREE_COL_TO_DB_SORT:
                sql_sort_col = sc
                sql_sort_asc = not rev   # rev=True → DESC → sort_asc=False

        # ── Fetch rows: all display + scoring columns in ONE query ──
        # On HDD the fetchall() inside get_ips_for_table() can take several seconds
        # for large databases; print a status line before it starts so the terminal
        # does not appear frozen during the wait.
        _startup = getattr(self, '_startup_loading', False)
        if _startup:
            print("\r[NetPyINT] Loading database: querying...", end="", flush=True)
        cur = self.repo.get_ips_for_table(
            threat_level_filter, unscanned_flag,
            search_term=search_term,
            sort_col=sql_sort_col,
            sort_asc=sql_sort_asc,
            cc_filter=cc_filter,
            **adv,
        )

        # ── Populate table rows ──
        _row_total = len(cur)
        _last_pct_printed = -1
        if _startup:
            if _row_total > 0:
                print(f"\r[NetPyINT] Loading database:   0% ({_row_total:,} IPs)",
                      end="", flush=True)
            else:
                print(f"\r[NetPyINT] Loading database: (no IPs){' ' * 20}", flush=True)

        filter_count = 0
        for row in cur:
            (ip, threat, abuse, vt, hits, fs, ls, cc, gn, otx, rdns,
             sh_vulns, idb_vulns, idb_tags, pc_type, pc_risk, full_score,
             s_abuse, s_vt, s_gn, s_shod, s_idb,
             s_otx, s_pc, s_ipi, s_ipapi, s_dns) = row

            # Use the score cached in the DB by update_threat_level().
            # Fall back to computing it only for legacy rows (full_score == -1).
            if full_score is not None and full_score >= 0:
                sc = full_score
            else:
                score_data = dict(zip(_SCORE_KEYS,
                    (abuse, vt, sh_vulns, idb_vulns, idb_tags, gn, otx,
                     pc_type, hits, s_abuse, s_vt, s_gn, s_shod, s_idb,
                     s_otx, s_pc, s_ipi, s_ipapi, s_dns)))
                _, sc = compute_threat_level(score_data)
            score_val = f"{sc:.0f}"

            tag = get_threat_tag(threat, THREAT_COLORS)
            abuse_s, vt_s, otx_s, pc_risk_s = format_score_cols(abuse, vt, otx, pc_risk)
            tags_s = parse_idb_tags(idb_tags)
            cc_display, cc_highlighted = format_country(cc, self._cc_highlight)
            row_tags = (tag, "cc_hl") if cc_highlighted else (tag,)

            # iid=ip makes each row's internal id equal to the IP address string,
            # so tree.exists(ip) and tree.item(ip) work in O(1) without a linear scan.
            self.tree.insert("", "end", iid=ip, values=(
                ip, threat, score_val, hits, self._fmt_date(fs), self._fmt_date(ls),
                cc_display, abuse_s, vt_s, otx_s, pc_type or "–", tags_s, rdns or "–",
                pc_risk_s, gn or "–"),
                tags=row_tags)
            filter_count += 1
            if _startup and _row_total > 0:
                pct = filter_count * 100 // _row_total
                # pct // 10 gives the current 10-percent bucket; comparing to the last printed
                # bucket fires the print exactly once per 10% increment rather than every row.
                if pct // 10 > _last_pct_printed // 10:
                    _last_pct_printed = pct
                    print(f"\r[NetPyINT] Loading database: {pct:>3}%", end="", flush=True)

        # ── Update sidebar stats (always from full database) ──
        self._update_sidebar_stats()

        # ── Update filter match count ──
        if hasattr(self, 'lbl_filter_count'):
            if filt == "All IPs":
                self.lbl_filter_count.config(text="")
            else:
                self.lbl_filter_count.config(text=f"Showing {filter_count} IPs")

        # ── Update the always-visible filter summary above the table ──
        if hasattr(self, "lbl_filter_summary"):
            self._update_filter_summary(filt, adv, search_term, filter_count)

        # ── Python sort fallback for non-SQL columns only ──
        # SQL-sortable columns are already ordered by the query above.
        # Only "tags" (JSON array, not meaningfully sortable in SQL) reaches this branch.
        if self._current_sort:
            col, rev = self._current_sort
            if col not in _TREE_COL_TO_DB_SORT:
                self._apply_tree_sort(col, rev)

    def refresh_insights(self):
        # Recompute and redisplay Data Insights for the currently filtered IP set.
        # Reads the same filter state as refresh_table() so the two views are always in sync.
        _, threat_level_filter, unscanned_flag, cc_filter = self._parse_filter()
        adv = self._parse_advanced_filter()
        search_term = (self._search_var.get().strip()
                       if hasattr(self, "_search_var") else None) or None
        filter_label = self.var_filter.get() if hasattr(self, "var_filter") else "All IPs"

        records = self.repo.get_insights_records(
            threat_level=threat_level_filter,
            unscanned_flag=unscanned_flag,
            cc_filter=cc_filter,
            search_term=search_term,
            **adv,
        )
        report = build_insights_report(records)
        text = render_insights_text(report, filter_label=filter_label)

        self.insights_text.config(state="normal")
        self.insights_text.delete("1.0", "end")
        self.insights_text.insert("end", text)
        self.insights_text.config(state="disabled")

    def _update_single_ip(self, ip):
        # Update a single IP's row in the Treeview without rebuilding the table.
        #
        # Inputs:
        #     ip (str): The IP address to update.
        #
        # Returns: None (updates the row in-place if it exists in the Treeview)
        #
        # Behavior:
        #     - Fetches the IP's current data from the database (single query).
        #     - If the IP exists in the Treeview, updates its cell values and
        #       colour tag in-place using tree.item().
        #     - If the IP is not in the Treeview (e.g. filtered out), skips it.
        #     - Updates sidebar stats via a lightweight GROUP BY query.
        #     - Does NOT re-sort — the row stays in its current position.
        #       Re-sorting 18k rows per IP would defeat the purpose.
        #
        # Performance:
        #     - 1 DB query (vs 18,001 for a full refresh_table)
        #     - 1 Treeview update (vs 18k deletes + 18k inserts)
        #     - O(1) per call instead of O(N)
        #
        # Usage:
        #     Called from _poll_queue when a scan worker sends ("update_ip", ip).
        row = self.repo.get_display_row(ip)
        if not row:
            return

        (threat, abuse, vt, hits, fs, ls, cc, gn, otx, rdns,
         sh_vulns, idb_vulns, idb_tags, pc_type, pc_risk, full_score,
         s_abuse, s_vt, s_gn, s_shod, s_idb,
         s_otx, s_pc, s_ipi, s_ipapi, s_dns) = row

        if full_score is not None and full_score >= 0:
            sc = full_score
        else:
            score_data = dict(zip(_SCORE_KEYS,
                [abuse, vt, sh_vulns, idb_vulns, idb_tags, gn, otx,
                 pc_type, hits, s_abuse, s_vt, s_gn, s_shod, s_idb,
                 s_otx, s_pc, s_ipi, s_ipapi, s_dns]))
            _, sc = compute_threat_level(score_data)
        score_val = f"{sc:.0f}"

        tag = get_threat_tag(threat, THREAT_COLORS)
        abuse_s, vt_s, otx_s, pc_risk_s = format_score_cols(abuse, vt, otx, pc_risk)
        tags_s = parse_idb_tags(idb_tags)
        cc_display, cc_highlighted = format_country(cc, self._cc_highlight)
        row_tags = (tag, "cc_hl") if cc_highlighted else (tag,)

        new_values = (
            ip, threat, score_val, hits, self._fmt_date(fs), self._fmt_date(ls),
            cc_display, abuse_s, vt_s, otx_s, pc_type or "–", tags_s, rdns or "–",
            pc_risk_s, gn or "–")

        # Update in-place if the row exists in the Treeview
        if self.tree.exists(ip):
            self.tree.item(ip, values=new_values, tags=row_tags)
        # If IP isn't in tree (filtered out), skip — no insert needed

        # Lightweight stats update
        self._update_sidebar_stats()


    def _update_sidebar_stats(self):
        # Update the sidebar threat-level count labels from the database.
        #
        # Inputs:  None (queries self.db)
        # Returns: None (updates all lbl_* stat Label widgets in the sidebar)
        #
        # Uses a single GROUP BY query to count IPs per threat level, which
        # scales to tens of thousands of IPs without performance degradation.
        # Called after every per-IP update during scanning (via _poll_queue)
        # to keep stats current without triggering a full table rebuild.
        #
        # Performance: Single query regardless of table size.
        all_counts = defaultdict(int, self.repo.get_threat_level_counts())
        total_all = sum(all_counts.values())
        scanned_all = total_all - all_counts.get("Pending", 0)

        self.lbl_total_ips.config(text=f"Total IPs: {total_all}")
        self.lbl_scanned.config(text=f"Scanned: {scanned_all}")
        self.lbl_critical.config(text=f"Critical: {all_counts.get('Critical', 0)}")
        self.lbl_high.config(text=f"High: {all_counts.get('High', 0)}")
        self.lbl_medium.config(text=f"Medium: {all_counts.get('Medium', 0)}")
        self.lbl_low.config(text=f"Low: {all_counts.get('Low', 0)}")
        self.lbl_partial.config(text=f"Partial: {all_counts.get('Partial', 0)}")
        self.lbl_pending.config(text=f"Pending: {all_counts.get('Pending', 0)}")
        self.lbl_optional.config(text=f"Optional: {all_counts.get('Optional', 0)}")
        self.lbl_no_threat.config(text=f"No Threat: {all_counts.get('No Threat', 0)}")
        blocked = all_counts.get("Critical", 0) + all_counts.get("High", 0) + all_counts.get("Medium", 0)
        self.lbl_blocked.config(text=f"Blocklist ready: {blocked}")

    def _set_scan_state(self, scanning):
        # Toggle button states for scan-in-progress (scanning=True) or idle (scanning=False).
        if scanning:
            self.btn_scan.config(state="disabled")
            self.btn_rescan_filtered.config(state="disabled")
            self.btn_recalculate.config(state="disabled")
            self.btn_pause.config(state="normal")
            self.btn_stop.config(state="normal")
        else:
            self.btn_scan.config(state="normal")
            self.btn_rescan_filtered.config(state="normal")
            self.btn_recalculate.config(state="normal")
            self.btn_pause.config(state="disabled", text="⏸ Pause")
            self.btn_stop.config(state="disabled")

    def _launch_scan_thread(self, ips, rescan=False):
        # Common scan-thread setup shared by start_scan, rescan_selected_ips,
        # and rescan_filtered_ips.  Sets scan state, initialises the progress bar,
        # and starts the daemon thread running _scan_worker.
        self.scan_running = True
        self.scan_stop.clear()
        self.scan_paused.set()
        self._set_scan_state(True)
        self.progress["maximum"] = len(ips)
        self.progress["value"] = 0
        self._prog_frame.pack(fill="x", pady=(0, 4), before=self._search_frame)
        self.scan_thread = threading.Thread(
            target=self._scan_worker, args=(ips,), kwargs={"rescan": rescan},
            daemon=True)
        self.scan_thread.start()

    def _on_select(self, event):
        # Display full details for the selected IP in the detail panel.
        #
        # Inputs:
        #     event (tk.Event): The <<TreeviewSelect>> event (unused beyond
        #                       triggering; selection is read from self.tree).
        #
        # Returns: None (populates self.detail_text ScrolledText widget)
        #
        # Behavior:
        #     - Reads the selected IP address from the Treeview's selection.
        #     - Fetches the complete row from the ips table.
        #     - Formats a multi-section detail report including:
        #         • IP address and computed threat level with score
        #         • Timestamps (first/last seen, last scanned)
        #         • Location & network info (country, city, ISP, ASN, rDNS)
        #         • OSINT scores from each platform
        #         • Shodan open ports and vulnerabilities
        #         • Log context (firewall rules, dst/src ports, protocols)
        #         • Raw JSON platform responses (expandable)
        #     - The detail text widget is set to read-only (state="disabled")
        #       after population to prevent accidental editing.
        sel = self.tree.selection()
        if not sel:
            return
        ip = sel[0]
        data = self.repo.get_ip_record(ip)
        if not data:
            return

        self.detail_text.config(state="normal")
        self.detail_text.delete("1.0", "end")

        threat = data.get("threat_level", "Pending")
        cached = data.get("full_score", -1.0)
        if cached is not None and cached >= 0:
            score = cached
        else:
            _, score = compute_threat_level(data)

        # Pre-parse raw_results to pull per-platform fields used in OSINT Scores
        try:
            _raw = json.loads(data.get("raw_results", "{}"))
        except Exception:
            _raw = {}
        _vt_rep = _raw.get("virustotal", {}).get("reputation")
        _vt_rep_str = (f", {_vt_rep:+d} community score"
                       if _vt_rep is not None else "")

        # Pre-parse ProxyCheck JSON so risk/confidence can appear in OSINT Scores
        _pc_raw = data.get("proxycheck_data", "")
        try:
            _pc = json.loads(_pc_raw) if (_pc_raw and _pc_raw != "{}") else {}
        except Exception:
            _pc = {}
        _pc_conf = _pc.get("confidence")
        _pc_conf_str = f"{_pc_conf}%" if _pc_conf is not None else "–"

        def _fmt_score(val):
            return "n/a" if val is None or val == -1 else val

        lines = [
            f"{'═'*60}",
            f"  IP ADDRESS:    {data['ip']}",
            f"  THREAT LEVEL:  {threat}  (score: {score:.1f}/100)",
            f"{'═'*60}",
            "",
            f"  First Seen:    {format_detail_date(data.get('first_seen',''))}",
            f"  Last Seen:     {format_detail_date(data.get('last_seen',''))}",
            f"  Total Hits:    {data.get('total_hits',0)}",
            f"  New Hits:      {data.get('new_hits',0)}",
            f"  Last Scanned:  {format_detail_date(data.get('last_scanned',''))}",
        ]
        # Attack Velocity: hits/day over the full observation window (3a)
        _first_dt = _parse_log_ts(data.get("first_seen", ""))
        if _first_dt:
            _days = max(1, (datetime.now() - _first_dt).days)
            _vel = data.get("total_hits", 0) / _days
            _vel_str = f"{_vel:.1f} hits/day  ({_days} day span)"
        else:
            _vel_str = "–"
        lines.append(f"  Attack Velocity: {_vel_str}")
        lines += [
            "",
            f"\n══ LOCATION & NETWORK {'═' * 40}\n",
            f"  Country:       {data.get('country','–')}",
            f"  City:          {data.get('city','–')}",
            f"  ISP:           {data.get('isp','–')}",
            f"  ASN:           {data.get('asn','–')}",
            f"  Reverse DNS:   {data.get('reverse_dns','–')}",
            "",
            f"\n══ OSINT SCORES {'═' * 46}\n",
            f"  AbuseIPDB:     {_fmt_score(data.get('abuseipdb_score'))}%  confidence",
            f"  VirusTotal:    {_fmt_score(data.get('vt_score'))}%  malicious{_vt_rep_str}",
            f"  GreyNoise:     {data.get('greynoise_class','–')} "
            f"(noise={_fmt_score(data.get('greynoise_noise'))}, riot={_fmt_score(data.get('greynoise_riot'))})",
            f"  OTX Pulses:    {_fmt_score(data.get('otx_pulses'))}",
            f"  ProxyCheck:    risk={_fmt_score(data.get('proxycheck_risk'))}  confidence={_pc_conf_str}",
        ]

        # Score History: chronological audit trail of threat-level changes (2a)
        _history = self.repo.get_score_history(ip, limit=15)
        if _history:
            lines.append("")
            lines.append(f"\n══ SCORE HISTORY {'═' * 45}\n")
            for _ts, _lvl, _sc in _history:
                lines.append(f"  {format_detail_date(_ts):<20}  {_lvl:<12}  score: {_sc:.0f}")

        # ── ProxyCheck ──
        lines.append("")
        lines.append(f"\n══ PROXYCHECK {'═' * 48}\n")
        lines.append(f"  Detected As:   {data.get('proxycheck_type','–')}")

        # Full ProxyCheck detail from the pre-parsed JSON blob (_pc)
        # Risk score and confidence are already shown in OSINT Scores above.
        if _pc:
            try:
                pc = _pc
                # Detection flags
                flags_str = []
                for flag in ["anonymous", "proxy", "vpn", "tor", "hosting", "scraper"]:
                    val = pc.get(flag)
                    if val is True:
                        flags_str.append(f"{flag}=✓")
                    elif val is False:
                        flags_str.append(f"{flag}=✗")
                if flags_str:
                    lines.append(f"  Flags:         {', '.join(flags_str)}")
                # First/last seen
                fs = pc.get("first_seen", "")
                ls = pc.get("last_seen", "")
                if fs:
                    lines.append(f"  First Seen:    {fs}")
                if ls:
                    lines.append(f"  Last Seen:     {ls}")
                # Operator info
                op = pc.get("operator", {})
                if op and isinstance(op, dict):
                    op_name = op.get("name", "")
                    if op_name:
                        lines.append(f"  Operator:      {op_name}")
                    services = op.get("services", [])
                    if services:
                        lines.append(f"  Services:      {', '.join(str(s) for s in services)}")
                    addl = op.get("additional_operators", [])
                    if addl:
                        lines.append(f"  Also Seen:     {', '.join(str(a) for a in addl)}")
                # Attack history
                atk = pc.get("attack_history", {})
                if atk and isinstance(atk, dict):
                    atk_items = [f"{k}={v}" for k, v in atk.items() if v]
                    if atk_items:
                        lines.append(f"  Attacks:       {', '.join(atk_items)}")
            except (json.JSONDecodeError, Exception):
                lines.append(f"  (raw data: {_pc_raw[:200]})")
        else:
            lines.append(f"  Not yet scanned")

        lines += [
            "",
            f"\n══ SHODAN INTERNETDB {'═' * 41}\n",
            f"  Ports:         {data.get('internetdb_ports','–')}",
            f"  Vulns:         {data.get('internetdb_vulns','–')}",
            f"  Tags:          {data.get('internetdb_tags','–')}",
            f"  CPEs:          {data.get('internetdb_cpes','–')}",
            "",
            f"\n══ SHODAN {'═' * 52}\n",
            f"  Open Ports:    {data.get('shodan_ports','–')}",
            f"  Vulns:         {data.get('shodan_vulns','–')}",
        ]

        lines += [
            "",
            f"\n══ LOG CONTEXT {'═' * 47}\n",
            f"  Rules:         {data.get('log_rules','–')}",
            f"  Dst Ports:     {data.get('dst_ports','–')}",
            f"  Src Ports:     {data.get('src_ports','–')}",
            f"  Protocols:     {data.get('protocols','–')}",
        ]
        # Port Diversity: unique destination ports targeted (3b)
        _dst_raw = data.get("dst_ports", "")
        if _dst_raw:
            _unique = {p.strip() for p in _dst_raw.split(",") if p.strip()}
            _div_str = f"{len(_unique)} unique destination port(s)"
        else:
            _div_str = "–"
        lines.append(f"  Port Diversity:  {_div_str}")
        lines += [
            "",
            f"\n══ SCAN COVERAGE {'═' * 45}\n",
        ]

        # Show per-platform scan status with ✓/✗ indicators
        # KEY platforms are marked with [KEY] to highlight their importance
        for platform, flag_col in PLATFORM_TO_FLAG.items():
            scanned = data.get(flag_col, 0)
            icon = "✓" if scanned else "✗"
            key_tag = " [KEY]" if platform in KEY_PLATFORMS else ""
            lines.append(f"  {icon}  {platform}{key_tag}")

        # Count how many key platforms are missing
        missing_key = [p for p in KEY_PLATFORMS
                       if not data.get(PLATFORM_TO_FLAG.get(p, ""), 0)]
        if missing_key:
            lines.append(f"")
            lines.append(f"  ⚠  Missing key data: {', '.join(missing_key)}")
            lines.append(f"     Threat level is PARTIAL until these report.")

        lines += [
            "",
            f"\n══ NOTES {'═' * 53}\n",
            f"  {data.get('notes','–')}",
        ]

        # Show raw JSON results
        raw = data.get("raw_results", "{}")
        try:
            raw_dict = json.loads(raw)
            if raw_dict:
                lines.append("")
                lines.append(f"\n══ RAW PLATFORM RESULTS {'═' * 38}\n")
                lines.append(json.dumps(raw_dict, indent=4))
        except Exception:
            pass

        self.detail_text.insert("1.0", "\n".join(lines))

        # Apply clickable hyperlink tags to platform labels when scanned
        self._detail_links.clear()
        ip = data["ip"]
        if data.get("scanned_abuseipdb", 0):
            self._detail_links["hyperlink"] = (
                f"https://www.abuseipdb.com/check/{ip}")
            pos = self.detail_text.search("AbuseIPDB", "1.0", stopindex="end")
            if pos:
                self.detail_text.tag_add(
                    "hyperlink", pos, f"{pos}+{len('AbuseIPDB')}c")
        if data.get("scanned_virustotal", 0):
            self._detail_links["hyperlink_vt"] = (
                f"https://www.virustotal.com/gui/ip-address/{ip}")
            pos = self.detail_text.search("VirusTotal", "1.0", stopindex="end")
            if pos:
                self.detail_text.tag_add(
                    "hyperlink_vt", pos, f"{pos}+{len('VirusTotal')}c")
        if data.get("scanned_otx", 0):
            self._detail_links["hyperlink_otx"] = (
                f"https://otx.alienvault.com/indicator/ip/{ip}")
            pos = self.detail_text.search("OTX Pulses", "1.0", stopindex="end")
            if pos:
                self.detail_text.tag_add(
                    "hyperlink_otx", pos, f"{pos}+{len('OTX Pulses')}c")
        if data.get("scanned_proxycheck", 0):
            self._detail_links["hyperlink_proxycheck"] = (
                f"https://proxycheck.io/lookup/{ip}")
            pos = self.detail_text.search("ProxyCheck", "1.0", stopindex="end")
            if pos:
                self.detail_text.tag_add(
                    "hyperlink_proxycheck", pos, f"{pos}+{len('ProxyCheck')}c")
        if data.get("scanned_greynoise", 0):
            self._detail_links["hyperlink_greynoise"] = (
                f"https://viz.greynoise.io/ip/{ip}")
            pos = self.detail_text.search("GreyNoise", "1.0", stopindex="end")
            if pos:
                self.detail_text.tag_add(
                    "hyperlink_greynoise", pos, f"{pos}+{len('GreyNoise')}c")

        self.detail_text.config(state="disabled")

    # ── Log file loading ──────────────────────────────────────
    def open_log_file(self):
        # Open a firewall log file, parse it, and merge results into the database.
        #
        # Inputs:  None (opens a file dialog for user selection)
        # Returns: None (updates database and refreshes the UI table)
        #
        # Workflow:
        #     1. Open a file chooser dialog filtered for .txt/.log files.
        #     2. Parse all matching log lines via parse_log_file().
        #     3. Display parsed entries in the "Parsed Entries" tab (max 500 shown).
        #     4. Aggregate entries by source IP via aggregate_entries().
        #     5. For each unique public IP:
        #         a. Skip RFC1918 private/reserved addresses.
        #         b. If IP already exists in DB → UPDATE:
        #            - Add new hits to total_hits
        #            - Set new_hits to this import's count
        #            - Merge firewall rules, dst ports, src ports, protocols
        #            - Update first_seen if new timestamp is earlier
        #            - Update last_seen to the latest timestamp
        #         c. If IP is new → INSERT with all parsed metadata.
        #     6. Commit all changes and refresh the table display.
        #
        # The merge logic uses set unions to avoid duplicate entries in the
        # comma-separated port/rule/protocol fields. This means loading the
        # same log file twice won't create duplicate metadata (though it will
        # double-count the hit total – this is by design to track volume).
        path = filedialog.askopenfilename(
            title="Select Firewall Log File",
            filetypes=[("Text / Log files", "*.txt *.log"), ("All files", "*.*")])
        if not path:
            return
        self._log(f"Loading log file: {path}")
        entries = parse_log_file(path)
        self._log(f"Parsed {len(entries)} log entries.")

        if not entries:
            messagebox.showwarning("No entries",
                                    "No matching log entries found in the file.\n"
                                    "Ensure lines contain SRC= fields with banIP "
                                    "or 'reject wan in' rules.")
            return

        # Show parsed entries
        self.parsed_text.config(state="normal")
        self.parsed_text.delete("1.0", "end")
        self.parsed_text.insert("end",
            f"File: {path}\nParsed entries: {len(entries)}\n{'─'*60}\n\n")
        for e in entries[:500]:  # limit display
            self.parsed_text.insert("end",
                f"{e.get('timestamp','')}  SRC={e['src']}  "
                f"PROTO={e.get('proto','')}  SPT={e.get('spt','')}  "
                f"DPT={e.get('dpt','')}  Rule={e.get('rule','')}\n")
        if len(entries) > 500:
            self.parsed_text.insert("end", f"\n… ({len(entries)-500} more entries)\n")
        self.parsed_text.config(state="disabled")

        agg = aggregate_entries(entries)
        self.loaded_ips = agg
        new_count = 0
        updated_count = 0

        # Filter out RFC1918/reserved IPs before the batch DB query (M3).
        public_agg = {}
        for ip, info in agg.items():
            try:
                if not ipaddress.ip_address(ip).is_private:
                    public_agg[ip] = info
            except ValueError:
                pass  # skip malformed IPs

        # Single batch query replaces N individual get_log_import_data() calls.
        existing_batch = self.repo.get_log_import_data_batch(list(public_agg.keys()))

        for ip, info in public_agg.items():
            existing = existing_batch.get(ip)  # None if IP is new

            # Convert sets to sorted comma-separated strings for DB storage
            rules_str = ", ".join(sorted(info["rules"]))
            ports_str = ", ".join(sorted(info["dst_ports"]))
            src_ports_str = ", ".join(sorted(info["src_ports"]))
            protos_str = ", ".join(sorted(info["protocols"]))

            if existing:
                # ── UPDATE existing IP record ──
                # Unpack the previously stored values for merging
                old_hits, old_fs, old_ls, old_rules, old_ports, old_protos, old_src_ports = existing

                new_first = _pick_ts(old_fs, info["first_ts"], use_min=True)
                new_last  = _pick_ts(old_ls, info["last_ts"],  use_min=False)

                # Merge metadata using set unions to avoid duplicates:
                # Split old CSV string → combine with new set → remove blanks → sort → rejoin
                merged_rules = ", ".join(sorted(set(
                    (old_rules or "").split(", ") + list(info["rules"])) - {""}))
                merged_ports = ", ".join(sorted(set(
                    (old_ports or "").split(", ") + list(info["dst_ports"])) - {""}))
                merged_src_ports = ", ".join(sorted(set(
                    (old_src_ports or "").split(", ") + list(info["src_ports"])) - {""}))
                merged_protos = ", ".join(sorted(set(
                    (old_protos or "").split(", ") + list(info["protocols"])) - {""}))

                # Write merged data back: accumulate total_hits, overwrite new_hits
                self.repo.update_log_import(ip,
                    old_hits + info["hits"], info["hits"],
                    new_last, new_first,
                    merged_rules, merged_ports, merged_src_ports, merged_protos)
                updated_count += 1
            else:
                # First time seeing this IP – create a fresh row with parsed data
                # threat_level defaults to 'Pending' until OSINT scan runs
                self.repo.insert_ip(ip, info["first_ts"], info["last_ts"],
                                    info["hits"], rules_str, ports_str,
                                    src_ports_str, protos_str)
                new_count += 1

        # Commit all inserts/updates in a single transaction for performance
        self.repo.commit()
        self._log(f"Database updated: {new_count} new IPs, {updated_count} updated.")
        # Newly inserted IPs have full_score = -1 (the column default).
        # Computing and caching their initial score here (before refresh_table)
        # ensures the Score column sort works immediately after import without
        # requiring a restart.  _populate_missing_scores is a no-op for IPs
        # that already have a real score, so this is safe to call every import.
        self._populate_missing_scores()
        self.refresh_table()  # Reload the Treeview table with updated data

    # ── OSINT scanning ────────────────────────────────────────
    def start_scan(self):
        # Begin a background OSINT scan of all (or new-only) IPs in the database.
        #
        # Inputs:  None (reads scan criteria from self.var_new_only checkbox)
        # Returns: None (launches a daemon thread running _scan_worker)
        #
        # Behavior:
        #     - If a scan is already running, exits immediately (guard flag).
        #     - Queries the DB for IPs to scan based on the "new only" toggle:
        #         • If checked: only IPs where threat_level = 'Pending'
        #         • If unchecked: all IPs in the database
        #     - If no IPs match, shows an info dialog and returns.
        #     - Resets threading events (stop cleared, pause set to running).
        #     - Disables the Scan button and enables Pause/Stop buttons.
        #     - Initialises the progress bar to the total IP count.
        #     - Spawns a daemon thread running _scan_worker() with the IP list.
        #
        # Threading model:
        #     The scan thread is a daemon so it dies automatically if the
        #     user closes the application window. Communication back to the
        #     GUI is exclusively through self.msg_queue (never direct widget
        #     calls from the background thread, which would crash Tkinter).
        if self.scan_running:
            return  # Prevent duplicate scan launches
        # Determine which IPs to scan based on the "new only" checkbox
        scan_new = self.var_new_only.get()
        if scan_new:
            ips = self.repo.get_pending_ips()
        else:
            ips = self.repo.get_all_ips()
        if not ips:
            messagebox.showinfo("Nothing to scan",
                                "No IPs in database matching scan criteria.")
            return

        self._launch_scan_thread(ips, rescan=False)

    def _configure_hyperlink_tag(self, tag):
        # Register appearance and cursor/click bindings for one hyperlink tag.
        # The Button-1 handler reads self._detail_links at click time so all
        # tags can share this pattern without capturing a stale URL in a closure.
        self.detail_text.tag_configure(tag, foreground="#38bdf8", underline=True)
        self.detail_text.tag_bind(
            tag, "<Enter>",
            lambda _: self.detail_text.config(cursor="hand2"))
        self.detail_text.tag_bind(
            tag, "<Leave>",
            lambda _: self.detail_text.config(cursor=""))
        self.detail_text.tag_bind(
            tag, "<Button-1>",
            # t=tag captures the tag name at definition time (not at click time),
            # avoiding the classic loop-variable closure pitfall.
            lambda _, t=tag: webbrowser.open(self._detail_links[t])
            if self._detail_links.get(t) else None)

    def _fetch_threat_row(self, ip):
        # Fetch the columns required to compute a threat level for a single IP.
        # Returns a dict keyed by THREAT_LEVEL_COLUMNS, or None if the IP isn't in the DB.
        # Note: not called internally; kept as a convenience for the test suite's
        # _FakeApp adapter and any external callers that need scoring data by IP.
        return self.repo.get_scoring_data(ip, THREAT_LEVEL_COLUMNS)

    def _scan_worker(self, ips, rescan=False):
        # Background OSINT scan coordinator — runs on a daemon thread.
        #
        # Builds a _ScanContext containing all shared scan-session state, then
        # dispatches per-IP work to _scan_one_ip either serially (parallel_workers=1)
        # or via a bounded ThreadPoolExecutor (parallel_workers > 1).  Sends a
        # ("done", None) queue message when all IPs are processed so the GUI can
        # re-enable controls regardless of how the scan ended.
        #
        # Inputs:
        #     ips    (list[str]): IP addresses to scan in the order returned by
        #                         the DB query (sorted by total_hits descending).
        #     rescan (bool):      True  → skip platforms already flagged in the DB
        #                                  (fill gaps only — used by Rescan actions).
        #                         False → query all enabled platforms unconditionally.
        #
        # Returns: None  (all output goes via self.msg_queue or directly to the DB)
        #
        # Serial mode (parallel_workers == 1):
        #     IPs are processed one at a time on this thread.  scan_stop is checked
        #     before each IP; scan_paused is checked inside _scan_one_ip before each
        #     platform call.  This is identical to the original pre-parallel behaviour.
        #
        # Parallel mode (parallel_workers 2–8):
        #     A ThreadPoolExecutor with N threads is created.  IPs are submitted
        #     lazily — at most N futures are in-flight at any time (bounded backfill
        #     pattern).  When auto-stop fires, _try_submit() stops submitting new IPs
        #     immediately, limiting the "winding down" tail to the N workers already
        #     running.  _scan_one_ip checks scan_stop before updating the progress
        #     counter, so queued-but-not-yet-started futures exit silently without
        #     advancing the progress bar.
        #
        # Thread safety in parallel mode:
        #     - _ScanContext.config is a deep-copy of self.config taken here so that
        #       a concurrent Settings → API Keys save cannot race with worker reads.
        #     - _ScanContext.enabled is a plain dict snapshot (not live BooleanVars).
        #     - Each worker opens its own SQLite connection (WAL mode handles the
        #       concurrent writes; the per-platform commit ensures visibility).
        #     - rate_limit_streak is guarded by ctx.rl_lock; progress_counter by
        #       ctx.progress_lock.  All other ctx fields are read-only after init.
        #
        # Queue messages emitted:
        #     ("log",      message_str)    → scan log entries and error notes
        #     ("progress", (idx, total, ip)) → advances the progress bar
        #     ("status",   message_str)    → status label update on stop
        #     ("update_ip", ip_str)        → triggers a single-row UI refresh
        #     ("done",     None)           → re-enables buttons, final table refresh
        #
        # DB update strategy:
        #     Geo/ISP/ASN fields use COALESCE(NULLIF(col,''), ?) so the first
        #     platform to provide a value "wins" and later ones do not overwrite it.
        #     Score columns (abuseipdb_score, vt_score) are always overwritten with
        #     the latest data.  Each platform's writes are committed immediately so
        #     partial results survive an interrupted scan and are visible to other
        #     workers reading the same DB concurrently.
        delay = self.config.get("scan_delay_ms", 1100) / 1000.0
        ctx = _ScanContext(
            enabled={p: self.platform_vars[p].get() for p in PLATFORMS},
            platform_limiters={
                plat.name: _PlatformRateLimiter(max(delay, plat.min_delay))
                for plat in _PLATFORM_REGISTRY
            },
            rl_lock=threading.Lock(),
            rate_limit_streak={},
            auto_stop=self.config.get("auto_stop_rate_limit", True),
            label=" rescan" if rescan else "",
            progress_lock=threading.Lock(),
            progress_counter=[0],
            total=len(ips),
            config=copy.deepcopy(self.config),
            msg_queue=self.msg_queue,
            scan_stop=self.scan_stop,
            scan_paused=self.scan_paused,
            db_path=self._db_path,
            rescan=rescan,
            registry=_PLATFORM_REGISTRY,  # use the local registry so test patches intercept calls
        )
        scan_engine.run_scan(ips, ctx)

    def _scan_one_ip(self, ip, ctx):
        # Fill in any missing UI-bridge fields from self (supports test-built contexts).
        if ctx.msg_queue is None:
            ctx.msg_queue = self.msg_queue
        if ctx.scan_stop is None:
            ctx.scan_stop = self.scan_stop
        if ctx.scan_paused is None:
            ctx.scan_paused = self.scan_paused
        if ctx.db_path is None:
            ctx.db_path = self._db_path
        if ctx.registry is None:
            ctx.registry = _PLATFORM_REGISTRY
        scan_engine.scan_one_ip(ip, ctx)

    def toggle_pause(self):
        # Toggle the scan between paused and running states.
        #
        # Inputs:  None (reads self.scan_paused Event state)
        # Returns: None (toggles the Event and updates the Pause button text)
        #
        # Behavior:
        #     - If currently running (Event is set): clear the Event to pause.
        #       The scan thread blocks on scan_paused.wait() until resumed.
        #     - If currently paused (Event is clear): set the Event to resume.
        #       The scan thread unblocks and continues with the next IP.
        #
        # The pause/resume mechanism uses threading.Event, which provides
        # a clean way to suspend the background thread without killing it.
        if self.scan_paused.is_set():
            # Currently running → pause: clear the event to block the thread
            self.scan_paused.clear()
            self.btn_pause.config(text="▶ Resume")
            self._log("Scan paused.")
        else:
            # Currently paused → resume: set the event to unblock the thread
            self.scan_paused.set()
            self.btn_pause.config(text="⏸ Pause")
            self._log("Scan resumed.")

    def stop_scan(self):
        # Signal the background scan thread to stop after the current IP.
        #
        # Inputs:  None
        # Returns: None (sets the stop Event; thread exits on next iteration)
        #
        # Behavior:
        #     - Sets the scan_stop Event, which the scan thread checks at
        #       the top of each iteration. It will break after the current
        #       IP finishes processing.
        #     - Also sets scan_paused to unblock the thread if it's currently
        #       paused (otherwise it would hang forever waiting on the Event).
        #     - The actual cleanup (re-enabling buttons, resetting state) is
        #       handled by the "done" message in _poll_queue.
        self.scan_stop.set()           # Signal the thread to stop
        self.scan_paused.set()         # Unblock if currently paused
        self._log("Stop signal sent.")

    # ── Recalculate threat levels ─────────────────────────────
    def recalculate_threat_levels(self):
        # Recompute threat levels for the currently filtered IPs using existing
        # database data only — no API calls are made.
        #
        # Inputs:  None (reads IPs from current Treeview rows; fetches scoring
        #          fields from DB for each)
        # Returns: None (updates threat_level column; refreshes table)
        #
        # Behavior:
        #     - Collects all IP addresses currently displayed in the table
        #       (respecting the active sidebar filter).
        #     - For each IP, reads the scoring-relevant columns and scan flags
        #       from the database.
        #     - Runs compute_threat_level() to determine the current level
        #       based on the latest KEY_PLATFORMS definition and scoring weights.
        #     - Updates the threat_level column if it has changed.
        #     - No API calls are made — this is purely a local recalculation.
        #
        # Scope:
        #     - Filter set to "All IPs" → recalculates every IP in the database.
        #     - Filter set to "Partial" → recalculates only Partial IPs.
        #     - Filter set to "Missing: VirusTotal" → recalculates only IPs
        #       missing VT data.
        #     - This matches the same dataset that "▶ Rescan Filtered" operates on.
        #
        # Use cases:
        #     - After changing KEY_PLATFORMS (e.g. removing GreyNoise), IPs
        #       that were "Partial" because only GreyNoise was missing will
        #       be promoted to their actual scored level.
        #     - After adjusting scoring weights or thresholds in
        #       compute_threat_level(), existing scores are remapped to
        #       the updated level boundaries.
        #     - Targeted recalculation: filter to "Partial", recalculate just
        #       those to see which ones now qualify for a final level.
        #
        # Usage:
        #     Called from the "🔄 Recalculate Levels" button in the sidebar.
        if self.scan_running:
            messagebox.showwarning("Scan in progress",
                                    "Please wait for the current scan to finish, "
                                    "or stop it first.")
            return

        # Derive filter parameters via the shared helper so the recalculation
        # scope exactly matches the visible table rows.
        filt, threat_level_filter, unscanned_flag, cc_filter = self._parse_filter()
        adv = self._parse_advanced_filter()

        # Fetch scoring data from DB directly — no Treeview traversal needed.
        rows_by_ip = self.repo.get_scoring_data_for_filter(
            THREAT_LEVEL_COLUMNS, threat_level_filter, unscanned_flag,
            cc_filter=cc_filter,
            **adv,
        )

        if not rows_by_ip:
            messagebox.showinfo("Empty", "No IPs match the current filter.")
            return

        self._log(f"Recalculating threat levels for {len(rows_by_ip)} IPs (filter: {filt})")

        # Always write full_score for every IP so the sort and display cache
        # are populated — even when the threat level label has not changed.
        # Only count and log actual label transitions for the user message.
        batch = []
        changed = 0
        change_lines = []   # collect for a single batched log write (L2)
        for ip, row in rows_by_ip.items():
            old_level = row[0]
            data = dict(zip(THREAT_LEVEL_COLUMNS, row[1:]))
            new_level, score = compute_threat_level(data)
            if new_level != old_level:
                changed += 1
                if len(change_lines) < 20:
                    change_lines.append(f"  {ip}: {old_level} → {new_level} (score {score:.0f})")
            batch.append((new_level, score, ip))

        if change_lines:
            extra = f"\n  … and {changed - len(change_lines)} more" if changed > len(change_lines) else ""
            self._log("Level changes:\n" + "\n".join(change_lines) + extra)

        self.repo.update_threat_levels_batch(batch)
        self.repo.commit()
        self.refresh_table()
        total = len(rows_by_ip)
        self._log(f"Recalculation complete: {changed} level change(s), "
                  f"{total} score(s) refreshed.")

        if changed > 0:
            messagebox.showinfo("Recalculation Complete",
                                f"Updated {changed} of {total} IP threat levels.\n"
                                f"(Filter: {filt})")
        else:
            messagebox.showinfo("Recalculation Complete",
                                f"All {total} filtered IPs already at correct levels.\n"
                                f"Scores have been refreshed for sorting.")

    # ── Rescan filtered IPs ──────────────────────────────────
    def rescan_filtered_ips(self):
        # Rescan only the IPs currently shown in the filtered table view,
        # querying ONLY the platforms that have not yet returned data.
        #
        # Inputs:  None (reads IPs from current Treeview rows)
        # Returns: None (launches a daemon thread running _scan_worker with rescan=True)
        #
        # Behavior:
        #     - Collects all IP addresses currently displayed in the table
        #       (i.e. matching the active sidebar filter).
        #     - If a scan is already running, shows a warning and returns.
        #     - If no IPs are displayed, shows an info dialog.
        #     - For each IP, the background worker checks which scanned_*
        #       flags are 0 and only queries those missing platforms.
        #     - After each IP, recomputes the threat level (which may
        #       transition from "Partial" to a final level once all key
        #       platforms have reported).
        #
        # Usage:
        #     Called from the "▶ Rescan Filtered" button in the sidebar.
        #     Typical workflow:
        #       1. Select "Missing: AbuseIPDB" from the filter dropdown
        #       2. Table shows only IPs where scanned_abuseipdb=0
        #       3. Click "▶ Rescan Filtered" to query AbuseIPDB for just those IPs
        #       4. After completion, IPs transition from Partial → final threat level
        if self.scan_running:
            messagebox.showwarning("Scan in progress",
                                    "Please wait for the current scan to finish, "
                                    "or stop it first.")
            return

        # Collect IPs currently visible in the (possibly filtered) table
        ips = list(self.tree.get_children())
        if not ips:
            messagebox.showinfo("No IPs", "No IPs match the current filter.")
            return

        self._log(f"Rescan starting for {len(ips)} filtered IPs (missing platforms only)")
        self._launch_scan_thread(ips, rescan=True)

    # _rescan_worker has been merged into _scan_worker(rescan=True).

    # ── Queue polling ─────────────────────────────────────────
    def _poll_queue(self):
        # Process pending messages from the scan thread's message queue.
        #
        # Inputs:  None (reads from self.msg_queue)
        # Returns: None (updates UI widgets based on message type)
        #
        # This method runs on the main GUI thread and is called every 150ms
        # via self.after(). It drains all pending messages from the queue
        # in a non-blocking loop (get_nowait), then reschedules itself.
        #
        # Message types (tuple of (kind, data)):
        #     ("progress", (idx, total, ip))  → Update progress bar and status label
        #     ("log", message_str)            → Append message to the Scan Log tab
        #     ("status", status_str)          → Update the status label text only
        #     ("update_ip", ip_str)           → Update a single IP's row in-place (O(1))
        #     ("done", None)                  → Scan complete: re-enable buttons,
        #                                       reset state, final table refresh
        #
        # Performance:
        #     The "update_ip" message replaces the old "refresh" message which
        #     called refresh_table() after every IP — destroying and rebuilding
        #     all 18k+ rows. The new approach updates only the single changed
        #     row in O(1), with sidebar stats batched once per poll cycle.
        #
        # Why polling instead of direct widget calls:
        #     Tkinter is not thread-safe. The scan thread cannot call widget
        #     methods directly without risking crashes or deadlocks. The queue
        #     pattern decouples the threads cleanly.
        try:
            stats_dirty = False  # Track if any IP was updated this poll cycle
            while True:
                kind, data = self.msg_queue.get_nowait()
                if kind == "progress":
                    # idx is 1-based (worker increments before sending).
                    idx, total, ip = data
                    self.progress["value"] = idx
                    self.lbl_progress.config(
                        text=f"Scanning {idx}/{total}: {ip}")
                elif kind == "log":
                    # Append a timestamped message to the Scan Log tab
                    self._log(data)
                elif kind == "status":
                    # Update just the status label (e.g. "Scan stopped.")
                    self.lbl_progress.config(text=data)
                elif kind == "update_ip":
                    # Update a single IP's row in-place (O(1) per IP)
                    # instead of rebuilding the entire table.
                    # Delegates to _update_single_ip() which reads the cached
                    # score from the DB — no compute_threat_level() call needed.
                    self._update_single_ip(data)
                    stats_dirty = True
                elif kind == "done":
                    # ── Scan complete cleanup ──
                    scanned_done = int(self.progress["value"])
                    total_done   = int(self.progress["maximum"])
                    self.scan_running = False
                    self._set_scan_state(False)
                    self.lbl_progress.config(text="Scan complete.")
                    self.refresh_table()                       # Final table refresh
                    self.refresh_insights()                    # Update Data Insights after scan
                    self._filter_panel.refresh_countries()     # Newly scanned IPs may add country codes
                    self._prog_frame.pack_forget()             # Hide progress bar
                    self._log(f"═══ Scan complete: {scanned_done}/{total_done} ═══")
                    # Flush WAL into the main .db file so scan data is visible
                    # to Git immediately — without this, data sits in the -wal
                    # file which is not tracked in version control.
                    self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                    stats_dirty = False  # refresh_table already updated stats
                    # Post-scan delay: schedule next auto-scan from scan completion
                    # rather than from when it started, with an extra 5-min buffer.
                    if self._auto_scan_post_delay_pending and self.var_auto_scan.get():
                        self._auto_scan_post_delay_pending = False
                        interval_h = self.config.get("auto_scan_interval_hours", 1)
                        total_ms = int(interval_h * 3600 * 1000) + 5 * 60 * 1000
                        self._auto_scan_after_id = self.after(total_ms, self._auto_scan_tick)
                        next_dt = datetime.now() + timedelta(hours=interval_h, minutes=5)
                        next_str = next_dt.strftime("%H:%M")
                        if hasattr(self, "lbl_auto_scan_status"):
                            self.lbl_auto_scan_status.config(text=f"Next: ~{next_str}")
                        self._log(f"Auto Scan: next scan in {interval_h}h + 5min buffer (~{next_str})")
                    elif self._auto_scan_post_delay_pending:
                        self._auto_scan_post_delay_pending = False
            # After draining all queued messages, update stats ONCE
            # (not per-IP — avoids redundant GROUP BY queries)
        except queue.Empty:
            if stats_dirty:
                self._update_sidebar_stats()
        # Reschedule this method to run again in 150ms
        self.after(150, self._poll_queue)

    def _log(self, msg):
        # Append a timestamped message to the Scan Log tab.
        # Trims the oldest 500 lines whenever the buffer exceeds 2 000 lines
        # so long-running sessions don't degrade Tkinter rendering (M2).
        self.log_text.config(state="normal")
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{ts}] {msg}\n")
        if int(self.log_text.index("end-1c").split(".")[0]) > 2000:
            self.log_text.delete("1.0", "500.0")
        self.log_text.see("end")
        self.log_text.config(state="disabled")

    # ── Export ─────────────────────────────────────────────────
    def export_blocklist(self):
        export_import.export_blocklist(self, self.repo, self._log,
                                       cc_highlight=self._cc_highlight)

    def export_json(self):
        export_import.export_json(self, self.repo, self._log)

    def import_json(self):
        export_import.import_json(self, self.repo, self._log,
                                  self.refresh_table, self.recalculate_threat_levels)
        self._filter_panel.refresh_countries()  # imported records may add new country codes

    def clear_database(self):
        export_import.clear_database(self, self.repo, self._log, self.refresh_table)
        self._filter_panel.refresh_countries()  # DB is now empty — clear the Listbox too

    def _auto_prune_scan_log(self):
        # Prune scan_log at startup based on the configured retention window.
        # A value of 0 means keep forever — no pruning is performed.
        retention = self.config.get("scan_log_max_days", 60)
        if retention > 0:
            pruned = self.repo.prune_scan_log(retention)
            if pruned:
                print(f"\r[NetPyINT]   -> Pruned {pruned:,} old scan_log entries "
                      f"(>{retention} days).{' ' * 10}", flush=True)
                self._log(f"Startup: pruned {pruned} scan_log entries older than "
                          f"{retention} days.")

    def prune_scan_log_dialog(self):
        # Open a dialog showing scan_log stats and letting the user prune old entries.
        stats = self.repo.get_scan_log_stats()
        count = stats["count"]
        oldest = (stats["oldest"] or "–")[:16]
        newest = (stats["newest"] or "–")[:16]

        dialog = tk.Toplevel(self)
        dialog.title("Prune Scan Log")
        dialog.geometry("420x260")
        dialog.configure(bg="#0f172a")
        dialog.transient(self)
        dialog.grab_set()

        ttk.Label(dialog, text="Scan Log Maintenance",
                  style="Title.TLabel").pack(anchor="w", padx=16, pady=(12, 4))

        info_frame = ttk.Frame(dialog)
        info_frame.pack(fill="x", padx=16, pady=(0, 10))
        ttk.Label(info_frame, text=f"Current rows:  {count:,}").pack(anchor="w")
        ttk.Label(info_frame, text=f"Oldest entry:  {oldest}").pack(anchor="w")
        ttk.Label(info_frame, text=f"Newest entry:  {newest}").pack(anchor="w")

        ttk.Separator(dialog, orient="horizontal").pack(fill="x", padx=16, pady=(4, 10))

        days_frame = ttk.Frame(dialog)
        days_frame.pack(fill="x", padx=16, pady=(0, 6))
        ttk.Label(days_frame, text="Delete entries older than:").pack(side="left")
        days_var = tk.IntVar(value=self.config.get("scan_log_max_days", 60))
        days_spin = ttk.Spinbox(days_frame, from_=1, to=365, textvariable=days_var,
                                width=6)
        days_spin.pack(side="left", padx=(8, 4))
        ttk.Label(days_frame, text="days").pack(side="left")

        auto_var = tk.BooleanVar(value=self.config.get("scan_log_max_days", 60) > 0)
        ttk.Checkbutton(dialog, text="Auto-prune on startup at this threshold",
                        variable=auto_var).pack(anchor="w", padx=16, pady=(0, 4))

        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill="x", padx=16, pady=(10, 16))

        def on_prune():
            days = days_var.get()
            pruned = self.repo.prune_scan_log(days)
            # Save auto-prune preference: use configured days if enabled, else 0
            self.config["scan_log_max_days"] = days if auto_var.get() else 0
            save_config(self.config)
            dialog.destroy()
            self._log(f"Scan log pruned: {pruned} entries older than {days} days removed.")
            messagebox.showinfo("Pruned",
                                f"Removed {pruned:,} scan log entries older than {days} days.")

        ttk.Button(btn_frame, text="Prune Now", style="Accent.TButton",
                   command=on_prune).pack(side="right")
        ttk.Button(btn_frame, text="Cancel",
                   command=dialog.destroy).pack(side="right", padx=(0, 8))

    # ── Settings dialogs ──────────────────────────────────────
    def show_api_settings(self):
        settings_dialogs.show_api_settings(self, self.config, self._log)

    def show_scan_settings(self):
        settings_dialogs.show_scan_settings(
            self, self.config, self._log, self.refresh_table,
            lambda codes: setattr(self, "_cc_highlight", codes),
            restart_auto_scan_fn=self._restart_auto_scan_timer)

    def _toggle_auto_stop(self):
        # Toggle the rate-limit auto-stop setting and save to config.
        #
        # Inputs:  None (reads from self.var_auto_stop BooleanVar)
        # Returns: None (updates config and saves to disk)
        #
        # Behavior:
        #     - When enabled, scans automatically stop if ALL active platforms
        #       report consecutive rate-limit errors (5 in a row each).
        #     - When disabled, scans continue until manually stopped or all
        #       IPs are processed, regardless of rate-limit errors.
        #     - The setting persists across sessions via netpyint_config.json.
        #
        # Usage:
        #     Called from the Settings → "Auto-Stop on Rate Limits" checkbutton.
        enabled = self.var_auto_stop.get()
        self.config["auto_stop_rate_limit"] = enabled
        save_config(self.config)
        state = "enabled" if enabled else "disabled"
        self._log(f"Auto-stop on rate limits: {state}")

    def _toggle_advanced_filters_start_hidden(self):
        # Toggle whether the Advanced Filter Controls panel starts
        # collapsed at launch, and save to config.
        #
        # Inputs:  None (reads from self.var_hide_advanced_filters BooleanVar)
        # Returns: None (updates config and saves to disk)
        #
        # Behavior:
        #     - Only affects the NEXT launch — does not collapse or expand
        #       the panel in the current session.
        #     - The setting persists across sessions via netpyint_config.json.
        #
        # Usage:
        #     Called from Settings → "Start with Advanced Filters Hidden" checkbutton.
        enabled = self.var_hide_advanced_filters.get()
        self.config["start_advanced_filters_hidden"] = enabled
        save_config(self.config)
        state = "hidden" if enabled else "shown"
        self._log(f"Advanced Filters will start {state} on next launch.")

    # ── Auto Start Scan ───────────────────────────────────────────
    def _toggle_auto_scan(self):
        enabled = self.var_auto_scan.get()
        self.config["auto_scan_enabled"] = enabled
        save_config(self.config)
        if enabled:
            self._start_auto_scan_timer()
            interval_h = self.config.get("auto_scan_interval_hours", 1)
            self._log(f"Auto Scan enabled (interval: {interval_h}h).")
        else:
            self._cancel_auto_scan_timer()
            self._log("Auto Scan disabled.")

    def _start_auto_scan_timer(self):
        self._cancel_auto_scan_timer()
        interval_h = self.config.get("auto_scan_interval_hours", 1)
        interval_ms = int(interval_h * 3600 * 1000)
        self._auto_scan_after_id = self.after(interval_ms, self._auto_scan_tick)
        post_delay = self.config.get("auto_scan_post_delay", False)
        extra = timedelta(minutes=5) if post_delay else timedelta()
        next_dt = datetime.now() + timedelta(hours=interval_h) + extra
        next_str = next_dt.strftime("%H:%M")
        if hasattr(self, "lbl_auto_scan_status"):
            self.lbl_auto_scan_status.config(text=f"Next: ~{next_str}")

    def _cancel_auto_scan_timer(self):
        if self._auto_scan_after_id is not None:
            self.after_cancel(self._auto_scan_after_id)
            self._auto_scan_after_id = None
        if hasattr(self, "lbl_auto_scan_status"):
            self.lbl_auto_scan_status.config(text="")

    def _restart_auto_scan_timer(self):
        if self.var_auto_scan.get():
            self._start_auto_scan_timer()

    def _auto_scan_tick(self):
        self._auto_scan_after_id = None
        if not self.var_auto_scan.get():
            return
        post_delay = self.config.get("auto_scan_post_delay", False)
        if self.scan_running:
            self._log("Auto Scan: scan already running, rescheduling.")
            self._start_auto_scan_timer()
            return
        ips = list(self.tree.get_children())
        if ips:
            self._log(f"Auto Scan: starting rescan for {len(ips)} filtered IP(s)...")
            if post_delay:
                # Let the "done" handler schedule the next tick after the scan finishes
                self._auto_scan_post_delay_pending = True
            self._launch_scan_thread(ips, rescan=True)
            if not post_delay:
                self._start_auto_scan_timer()
        else:
            self._log("Auto Scan: no IPs visible in current filter, skipping.")
            self._start_auto_scan_timer()


# ─────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────
# When run directly (not imported), create the application window
# and start the Tkinter event loop. The event loop runs until the
# user closes the window or selects File → Exit.
if __name__ == "__main__":
    app = NetPyINTApp()   # Instantiate: loads config, connects DB, builds UI
    app.mainloop()        # Start Tkinter event loop (blocks until window closes)
