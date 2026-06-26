#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════╗
# ║              NetPyINT – Data Access Layer                        ║
# ║    IPRepository: all SQL for the 'ips' and 'scan_log' tables     ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# Single place for every query against the database. Callers pass
# normalised Python values; the repository handles parameterisation
# and column layout. JSON serialisation (json.dumps / json.loads)
# stays in the caller — the repository only stores and retrieves strings.
#
# Public surface (imported by netpyint_main.py):
#     IPRepository, init_db

import re
import sqlite3
from datetime import datetime, timedelta

from config import DB_FILE, PLATFORM_TO_FLAG

# Regex for valid column definitions passed to _migrate_column.
# Matches "TYPE DEFAULT value" where TYPE is TEXT/INTEGER/REAL and value is
# a single-quoted string or an optional-sign integer. Blocks injection chars.
_VALID_MIGRATION_DEF_RE = re.compile(
    r"^(TEXT|INTEGER|REAL) DEFAULT ('[^']*'|-?\d+)$"
)


def _migrate_column(conn, column_name, column_def, repo=None):
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", column_name):
        raise ValueError(f"_migrate_column: invalid column name {column_name!r}")
    if not _VALID_MIGRATION_DEF_RE.fullmatch(column_def):
        raise ValueError(f"_migrate_column: disallowed column def {column_def!r}")
    try:
        conn.execute(f"SELECT {column_name} FROM ips LIMIT 1")
    except sqlite3.OperationalError:
        conn.execute(f"ALTER TABLE ips ADD COLUMN {column_name} {column_def}")
        conn.commit()
        if repo is not None:
            repo._col_names = None  # invalidate column-name cache (L5)


def init_db(db_path=DB_FILE):
    # check_same_thread=False: scan worker writes while GUI thread reads.
    conn = sqlite3.connect(db_path, check_same_thread=False)
    # WAL mode allows concurrent reads during writes, keeping the GUI responsive.
    conn.execute("PRAGMA journal_mode=WAL")
    # Merge any leftover WAL from a prior unclean exit so all reads come from
    # the single .db file — this eliminates split-file seeking on HDD.
    conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
    # 64 MB page cache (default is ~2 MB / 512 pages).  With 65K+ IP rows the
    # default evicts pages constantly; a larger cache keeps the scoring columns
    # in memory after the first read, making _recompute_stale_levels() and
    # refresh_table() much faster on HDD.
    conn.execute("PRAGMA cache_size = -65536")
    # Memory-mapped I/O lets SQLite read the .db file via mmap(2) rather than
    # repeated read(2) calls; on HDD this avoids syscall overhead for large
    # sequential scans.
    conn.execute("PRAGMA mmap_size = 268435456")
    # Temp tables (e.g. from ORDER BY on large result sets) go to RAM instead
    # of a temp file on disk.
    conn.execute("PRAGMA temp_store = MEMORY")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS ips (
            ip               TEXT PRIMARY KEY,
            first_seen       TEXT,
            last_seen        TEXT,
            total_hits       INTEGER DEFAULT 0,
            new_hits         INTEGER DEFAULT 0,
            country          TEXT DEFAULT '',
            city             TEXT DEFAULT '',
            isp              TEXT DEFAULT '',
            asn              TEXT DEFAULT '',
            reverse_dns      TEXT DEFAULT '',
            threat_level     TEXT DEFAULT 'Pending',
            abuseipdb_score  REAL DEFAULT -1,
            vt_score         REAL DEFAULT -1,
            shodan_ports     TEXT DEFAULT '',
            shodan_vulns     TEXT DEFAULT '',
            internetdb_ports TEXT DEFAULT '',
            internetdb_vulns TEXT DEFAULT '',
            internetdb_tags  TEXT DEFAULT '',
            internetdb_cpes  TEXT DEFAULT '',
            greynoise_class  TEXT DEFAULT '',
            greynoise_noise  INTEGER DEFAULT -1,
            greynoise_riot   INTEGER DEFAULT -1,
            otx_pulses       INTEGER DEFAULT -1,
            proxycheck_risk  INTEGER DEFAULT -1,
            proxycheck_type  TEXT DEFAULT '',
            proxycheck_data  TEXT DEFAULT '',
            ipinfo_data      TEXT DEFAULT '',
            log_rules        TEXT DEFAULT '',
            dst_ports        TEXT DEFAULT '',
            src_ports        TEXT DEFAULT '',
            protocols        TEXT DEFAULT '',
            notes            TEXT DEFAULT '',
            last_scanned     TEXT DEFAULT '',
            raw_results      TEXT DEFAULT '{}',
            scanned_abuseipdb  INTEGER DEFAULT 0,
            scanned_virustotal INTEGER DEFAULT 0,
            scanned_shodan     INTEGER DEFAULT 0,
            scanned_internetdb INTEGER DEFAULT 0,
            scanned_greynoise  INTEGER DEFAULT 0,
            scanned_otx        INTEGER DEFAULT 0,
            scanned_proxycheck INTEGER DEFAULT 0,
            scanned_ipinfo     INTEGER DEFAULT 0,
            scanned_ipapi      INTEGER DEFAULT 0,
            scanned_dns        INTEGER DEFAULT 0
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_log (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip        TEXT,
            platform  TEXT,
            status    TEXT,
            response  TEXT
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS score_history (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip        TEXT,
            level     TEXT,
            score     REAL
        )
    """)
    conn.commit()

    conn.execute("CREATE INDEX IF NOT EXISTS idx_score_history_ip"
                 " ON score_history(ip, timestamp DESC)")

    _migrate_column(conn, "src_ports", "TEXT DEFAULT ''")
    for flag_col in PLATFORM_TO_FLAG.values():
        _migrate_column(conn, flag_col, "INTEGER DEFAULT 0")
    _migrate_column(conn, "internetdb_ports", "TEXT DEFAULT ''")
    _migrate_column(conn, "internetdb_vulns", "TEXT DEFAULT ''")
    _migrate_column(conn, "internetdb_tags", "TEXT DEFAULT ''")
    _migrate_column(conn, "internetdb_cpes", "TEXT DEFAULT ''")
    _migrate_column(conn, "proxycheck_risk", "INTEGER DEFAULT -1")
    _migrate_column(conn, "proxycheck_type", "TEXT DEFAULT ''")
    _migrate_column(conn, "proxycheck_data", "TEXT DEFAULT ''")
    _migrate_column(conn, "full_score",      "REAL DEFAULT -1")
    # Pre-computed counts for the JSON fields used in compute_threat_level().
    # Caching these avoids json.loads() per-IP during startup scoring loops.
    # Sentinel -1 means "not yet computed"; >=0 is the real value.
    _migrate_column(conn, "vuln_count",      "INTEGER DEFAULT -1")
    _migrate_column(conn, "tag_count",       "INTEGER DEFAULT -1")

    # Covering indexes for the query patterns that dominate runtime:
    #   threat_level — WHERE threat_level=? (filter, pending/partial queries, export)
    #   full_score   — ORDER BY full_score DESC (Score / Threat column sorts)
    #   country      — WHERE country IN (...) (CC Highlight filter)
    #   total_hits   — ORDER BY total_hits DESC (default table sort)
    # IF NOT EXISTS makes these idempotent on existing databases.
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ips_threat_level"
                 " ON ips(threat_level)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ips_full_score"
                 " ON ips(full_score DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ips_country"
                 " ON ips(country)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ips_total_hits"
                 " ON ips(total_hits DESC)")
    conn.commit()

    return conn

# ── Identifier whitelists ─────────────────────────────────────────────────────
#
# SQL parameterization (?) only works for VALUES, not for identifiers (column
# names) or structural fragments (WHERE clauses). Any column name interpolated
# into a SQL string must be validated against one of these frozensets first.
# Raising on an unknown name is the only safe defence against identifier
# injection — even when callers currently only pass trusted constants.

# Every column that exists (or may exist after migrations) in the ips table.
_VALID_IP_COLUMNS = frozenset({
    "ip", "first_seen", "last_seen", "total_hits", "new_hits",
    "country", "city", "isp", "asn", "reverse_dns",
    "threat_level", "abuseipdb_score", "vt_score",
    "shodan_ports", "shodan_vulns",
    "internetdb_ports", "internetdb_vulns", "internetdb_tags", "internetdb_cpes",
    "greynoise_class", "greynoise_noise", "greynoise_riot",
    "otx_pulses", "proxycheck_risk", "proxycheck_type", "proxycheck_data",
    "ipinfo_data", "log_rules", "dst_ports", "src_ports", "protocols",
    "notes", "last_scanned", "raw_results", "full_score",
    "vuln_count", "tag_count",
    "scanned_abuseipdb", "scanned_virustotal", "scanned_shodan",
    "scanned_internetdb", "scanned_greynoise", "scanned_otx",
    "scanned_proxycheck", "scanned_ipinfo", "scanned_ipapi", "scanned_dns",
})

# Subset: columns that may appear as the scan-flag target in mark_scanned().
_VALID_SCAN_FLAGS = frozenset({
    "scanned_abuseipdb", "scanned_virustotal", "scanned_shodan",
    "scanned_internetdb", "scanned_greynoise", "scanned_otx",
    "scanned_proxycheck", "scanned_ipinfo", "scanned_ipapi", "scanned_dns",
})


def _ctime_sort_expr(col):
    # Return a SQLite expression that converts a ctime string stored in `col`
    # (format: "Mon Mar 23 13:16:46 2026") to a sortable ISO string
    # ("2026-03-23 13:16:46") so ORDER BY produces chronological order.
    # Plain alphabetical ORDER BY would sort by day-of-week abbreviation instead.
    # Builds a SQL expression that converts "Mon Mar 23 13:16:46 2026" →
    # "2026-03-23 13:16:46" so ORDER BY produces chronological order.
    # Character offsets (1-based in SQLite SUBSTR):
    #   pos 1-3  = day-of-week abbrev (unused)
    #   pos 5-7  = month abbrev  → mapped to 01-12 via CASE
    #   pos 9-10 = day (may have leading space for single-digit days)
    #   pos 12-19 = HH:MM:SS
    #   pos 21-24 = year
    return (
        f"(SUBSTR({col},21,4)||'-'||"                           # year
        f"CASE SUBSTR({col},5,3)"                               # month abbrev → number
        f" WHEN 'Jan' THEN '01' WHEN 'Feb' THEN '02' WHEN 'Mar' THEN '03'"
        f" WHEN 'Apr' THEN '04' WHEN 'May' THEN '05' WHEN 'Jun' THEN '06'"
        f" WHEN 'Jul' THEN '07' WHEN 'Aug' THEN '08' WHEN 'Sep' THEN '09'"
        f" WHEN 'Oct' THEN '10' WHEN 'Nov' THEN '11' WHEN 'Dec' THEN '12'"
        f" ELSE '00' END||'-'||"
        f"printf('%02d',CAST(TRIM(SUBSTR({col},9,2)) AS INTEGER))||' '||"  # zero-pad day
        f"SUBSTR({col},12,8))"                                  # HH:MM:SS
    )


# Maps Treeview column IDs → real DB column names that can be pushed into
# ORDER BY.  Columns absent from this dict fall back to _apply_tree_sort()
# (Python sort on displayed tree values).
#
# "tags" is absent: JSON array, lexicographic sort is not meaningful.
# "score" maps to full_score.  _populate_missing_scores() in netpyint_main.py
#          runs at startup AND immediately after every log import so that
#          full_score is always populated before the table is displayed.
#          SQL ORDER BY full_score therefore always matches the displayed Score
#          column — newly imported IPs never linger at -1 between operations.
# "threat" maps to full_score so clicking the Threat header sorts by numeric
#          severity rather than alphabetical threat-level text.
# All values are members of _VALID_IP_COLUMNS so they are safe to interpolate.
_TREE_COL_TO_DB_SORT = {
    "ip":         "ip",
    "threat":     "full_score",   # sort by numeric severity, not alphabetical text
    "score":      "full_score",
    "hits":       "total_hits",
    "first_seen": "first_seen",
    "last_seen":  "last_seen",
    "country":    "country",
    "abuse":      "abuseipdb_score",
    "vt":         "vt_score",
    "otx":        "otx_pulses",
    "type":       "proxycheck_type",
    "rdns":       "reverse_dns",
    "pc_risk":    "proxycheck_risk",
    "greynoise":  "greynoise_class",
}


def _require_valid_columns(cols, valid_set=_VALID_IP_COLUMNS):
    # Raise ValueError if any column name is not in the whitelist.
    # Call this before building any f-string that interpolates column names.
    bad = [c for c in cols if c not in valid_set]
    if bad:
        raise ValueError(f"Unknown/disallowed column name(s): {bad!r}")


# Columns fetched when reading existing IP data for a log import merge.
_LOG_IMPORT_COLS = (
    "total_hits", "first_seen", "last_seen",
    "log_rules", "dst_ports", "protocols", "src_ports"
)

# Columns fetched to populate the rescan-mode skip flags.
_SCAN_FLAG_COLS = (
    "scanned_abuseipdb", "scanned_virustotal",
    "scanned_shodan", "scanned_internetdb", "scanned_greynoise", "scanned_otx",
    "scanned_proxycheck", "scanned_ipinfo", "scanned_ipapi", "scanned_dns",
)


class IPRepository:
    # Data access layer for the NetPyINT SQLite database.
    #
    # Wraps a sqlite3.Connection. All SQL statements live here; no raw
    # SQL should appear in the application layer (netpyint_main.py).
    #
    # Transaction management: commit() is intentionally exposed so the
    # caller controls transaction boundaries (e.g. one commit per IP
    # in the scan worker, one commit per log import batch).
    #
    # Thread safety: inherits the check_same_thread=False setting of the
    # connection passed in; the caller is responsible for ensuring only
    # one thread writes at a time (the existing scan-worker contract).

    def __init__(self, conn):
        self._db = conn
        self._col_names = None

    # ── Commit ────────────────────────────────────────────────────

    def commit(self):
        self._db.commit()

    def rollback(self):
        # Roll back the current transaction. Callers MUST call this inside any
        # except-block that catches a database error mid-operation, otherwise
        # partially-written rows will persist until the next commit or close.
        self._db.rollback()

    # ── Read: IP lists ────────────────────────────────────────────

    def get_all_ips(self):
        # Return every IP address currently in the database.
        return [r[0] for r in self._db.execute("SELECT ip FROM ips").fetchall()]

    def get_pending_ips(self):
        # Return IPs not yet scanned (threat_level = 'Pending').
        return [r[0] for r in self._db.execute(
            "SELECT ip FROM ips WHERE threat_level='Pending'").fetchall()]

    # ── Read: scoring / threat-level data ────────────────────────

    def get_partial_scoring_data(self, scoring_cols):
        # Return scoring dicts for all Partial IPs, including 'ip' and 'full_score'.
        # scoring_cols is THREAT_LEVEL_COLUMNS from config.py.
        #
        # full_score is fetched alongside the scoring columns so that
        # _recompute_stale_levels() can compare the newly computed score against
        # the cached value and skip UPDATEs for rows where nothing changed.
        _require_valid_columns(scoring_cols)
        cols = ["ip", "full_score"] + list(scoring_cols)
        rows = self._db.execute(
            "SELECT " + ", ".join(cols) + " FROM ips WHERE threat_level='Partial'"
        ).fetchall()
        return [dict(zip(cols, row)) for row in rows]

    def get_scoring_data(self, ip, scoring_cols):
        # Return a scoring dict for a single IP, or None if not found.
        _require_valid_columns(scoring_cols)
        row = self._db.execute(
            "SELECT " + ", ".join(scoring_cols) + " FROM ips WHERE ip=?", (ip,)
        ).fetchone()
        if row is None:
            return None
        return dict(zip(scoring_cols, row))

    # ── Read: full record / export ────────────────────────────────

    def get_ip_record(self, ip):
        # Return the full row for an IP as a dict, or None if not found.
        row = self._db.execute("SELECT * FROM ips WHERE ip=?", (ip,)).fetchone()
        if not row:
            return None
        cols = self.get_column_names()
        return dict(zip(cols, row))

    def get_column_names(self):
        # Return the list of column names for the ips table (cached after first call).
        if self._col_names is None:
            self._col_names = [
                d[0] for d in self._db.execute("SELECT * FROM ips LIMIT 0").description
            ]
        return self._col_names

    def get_all_for_export(self):
        # Return all rows as a list of dicts, ordered for the JSON report.
        # full_score DESC puts highest-severity IPs first; ties broken by ip.
        rows = self._db.execute(
            "SELECT * FROM ips ORDER BY full_score DESC, ip").fetchall()
        cols = self.get_column_names()
        return [dict(zip(cols, r)) for r in rows]

    # ── Read: scan-worker helpers ─────────────────────────────────

    def get_scan_flags(self, ip):
        # Return the scanned_* flag dict for an IP, or None if not found.
        # Used in rescan mode to skip already-queried platforms.
        row = self._db.execute(
            "SELECT " + ", ".join(_SCAN_FLAG_COLS) + " FROM ips WHERE ip=?", (ip,)
        ).fetchone()
        if not row:
            return None
        return dict(zip(_SCAN_FLAG_COLS, row))

    def get_raw_results(self, ip):
        # Return the raw_results JSON string for an IP, or None.
        row = self._db.execute(
            "SELECT raw_results FROM ips WHERE ip=?", (ip,)).fetchone()
        return row[0] if row else None

    # ── Read: log-import helper ───────────────────────────────────

    def get_log_import_data(self, ip):
        # Return existing log metadata for an IP, or None if it doesn't exist yet.
        # Tuple order matches _LOG_IMPORT_COLS: (total_hits, first_seen, last_seen,
        #   log_rules, dst_ports, protocols, src_ports)
        return self._db.execute(
            "SELECT " + ", ".join(_LOG_IMPORT_COLS) + " FROM ips WHERE ip=?", (ip,)
        ).fetchone()

    def get_log_import_data_batch(self, ips):
        # Return {ip: row_tuple} for all IPs in ips in one query (M3).
        # Row tuple order matches _LOG_IMPORT_COLS (same as get_log_import_data).
        if not ips:
            return {}
        placeholders = ",".join("?" * len(ips))
        cols = ("ip",) + _LOG_IMPORT_COLS
        rows = self._db.execute(
            f"SELECT {', '.join(cols)} FROM ips WHERE ip IN ({placeholders})",
            list(ips)
        ).fetchall()
        return {r[0]: r[1:] for r in rows}

    def get_ips_with_missing_scores(self, scoring_cols):
        # Return rows for IPs with full_score < 0 (not yet scored) (M4).
        # Columns: (ip, threat_level, *scoring_cols) matching _populate_missing_scores usage.
        _require_valid_columns(scoring_cols)
        all_cols = ["ip", "threat_level"] + list(scoring_cols)
        return self._db.execute(
            "SELECT " + ", ".join(all_cols) + " FROM ips WHERE full_score < 0"
        ).fetchall()

    # ── Insert ────────────────────────────────────────────────────

    def insert_ip(self, ip, first_seen, last_seen, hits,
                  log_rules, dst_ports, src_ports, protocols):
        # Create a new IP row from the first log import that references it.
        self._db.execute(
            "INSERT INTO ips (ip, first_seen, last_seen, total_hits, new_hits,"
            " log_rules, dst_ports, src_ports, protocols) VALUES (?,?,?,?,?,?,?,?,?)",
            (ip, first_seen, last_seen, hits, hits,
             log_rules, dst_ports, src_ports, protocols))

    def log_scan(self, ip, platform, status, response):
        # Append an API call entry to the scan_log audit table.
        # Response is capped at 2000 chars to keep the DB manageable.
        self._db.execute(
            "INSERT INTO scan_log (timestamp, ip, platform, status, response)"
            " VALUES (?,?,?,?,?)",
            (datetime.now().isoformat(), ip, platform, status, response[:2000]))

    # ── Update: log import ────────────────────────────────────────

    def update_log_import(self, ip, total_hits, new_hits, last_seen, first_seen,
                          log_rules, dst_ports, src_ports, protocols):
        # Merge updated hit counts, timestamps, and metadata for an existing IP.
        self._db.execute(
            "UPDATE ips SET total_hits=?, new_hits=?, last_seen=?, first_seen=?,"
            " log_rules=?, dst_ports=?, src_ports=?, protocols=? WHERE ip=?",
            (total_hits, new_hits, last_seen, first_seen,
             log_rules, dst_ports, src_ports, protocols, ip))

    # ── Update: per-platform results ──────────────────────────────

    def mark_scanned(self, ip, flag_column):
        # Set a scanned_* flag to 1, indicating the platform was queried successfully.
        if flag_column not in _VALID_SCAN_FLAGS:
            raise ValueError(f"Invalid scan flag column: {flag_column!r}")
        self._db.execute(f"UPDATE ips SET {flag_column}=1 WHERE ip=?", (ip,))

    def _backfill_update(self, ip, overwrite=None, backfill=None):
        # Build and execute a single UPDATE for one IP.
        # overwrite: {col: val} — columns always set to the new value.
        # backfill:  {col: val} — columns filled only when currently empty ('').
        overwrite = overwrite or {}
        backfill = backfill or {}
        _require_valid_columns(list(overwrite) + list(backfill))
        parts = [f"{c}=?" for c in overwrite]
        # COALESCE(NULLIF(col,''), ?) — only writes when the column is currently
        # empty (''); if a value is already stored, the update is a no-op for
        # that column.  This lets the first platform to report geo data "win"
        # without later platforms overwriting it with potentially lower-quality data.
        parts += [f"{c}=COALESCE(NULLIF({c},''),?)" for c in backfill]
        if not parts:
            return
        params = list(overwrite.values()) + list(backfill.values()) + [ip]
        self._db.execute(f"UPDATE ips SET {', '.join(parts)} WHERE ip=?", params)

    def update_reverse_dns(self, ip, hostname):
        # Authoritative (direct SET) — used only by the DNS Reverse Lookup platform.
        # Overwrites any previously backfilled value from a lower-priority source such as
        # Shodan or ip-api, which is intentional: a live PTR record is more canonical
        # than an indexed hostname scraped by a third-party scanner.
        self._db.execute("UPDATE ips SET reverse_dns=? WHERE ip=?", (hostname, ip))

    def backfill_reverse_dns(self, ip, hostname):
        # Fallback write — used by ip-api, IPInfo, Shodan, and InternetDB.
        # The COALESCE(NULLIF(col,''), ?) pattern writes only when reverse_dns is
        # currently empty, so the first non-empty result across those platforms wins
        # and later calls are no-ops.  Empty-string hostnames are rejected early so
        # a platform that returned nothing never clears a value set by an earlier one.
        if not hostname:
            return
        self._db.execute(
            "UPDATE ips SET reverse_dns=COALESCE(NULLIF(reverse_dns,''),?) WHERE ip=?",
            (hostname, ip)
        )

    def get_missing_rdns_batch(self):
        # Return (ip, raw_results, ipinfo_data) for IPs with blank reverse_dns that
        # have at least one hostname-capable platform already scanned.
        # raw_results holds every platform's full API response as a merged JSON dict
        # (written by scan_engine after each IP completes), so hostname data from
        # ip-api, Shodan, and InternetDB is recoverable without re-querying APIs.
        # ipinfo_data is fetched separately because IPInfo's response is also stored
        # in its own dedicated column, making extraction more reliable than relying
        # solely on raw_results when partial scans have occurred.
        return self._db.execute(
            "SELECT ip, raw_results, ipinfo_data FROM ips "
            "WHERE (reverse_dns='' OR reverse_dns IS NULL) "
            "AND (scanned_dns=1 OR scanned_ipapi=1 OR scanned_ipinfo=1 "
            "     OR scanned_shodan=1 OR scanned_internetdb=1)"
        ).fetchall()

    def update_reverse_dns_batch(self, changes):
        # Batch version of backfill_reverse_dns for the startup retroactive pass.
        # changes: list of (ip, hostname) tuples.
        # Uses the same COALESCE guard as the per-scan backfill so it is safe to call
        # even if some rows already have a value (e.g. DNS populated after this query ran).
        self._db.executemany(
            "UPDATE ips SET reverse_dns=COALESCE(NULLIF(reverse_dns,''),?) WHERE ip=?",
            [(hostname, ip) for ip, hostname in changes]
        )

    def update_ipapi(self, ip, country, city, isp, asn):
        self._backfill_update(ip, backfill={"country": country, "city": city,
                                            "isp": isp, "asn": asn})

    def update_abuseipdb(self, ip, score, country, isp):
        self._backfill_update(ip, overwrite={"abuseipdb_score": score},
                              backfill={"country": country, "isp": isp})

    def update_virustotal(self, ip, score, asn, country):
        self._backfill_update(ip, overwrite={"vt_score": score},
                              backfill={"asn": asn, "country": country})

    def update_shodan(self, ip, ports_json, vulns_json, city, isp, asn):
        self._backfill_update(ip,
            overwrite={"shodan_ports": ports_json, "shodan_vulns": vulns_json},
            backfill={"city": city, "isp": isp, "asn": asn})

    def update_internetdb(self, ip, ports_json, vulns_json, tags_json, cpes_json):
        # Backfills shodan_ports/vulns if Shodan hasn't run yet.
        self._backfill_update(ip,
            overwrite={"internetdb_ports": ports_json, "internetdb_vulns": vulns_json,
                       "internetdb_tags": tags_json, "internetdb_cpes": cpes_json},
            backfill={"shodan_ports": ports_json, "shodan_vulns": vulns_json})

    def update_greynoise(self, ip, classification, noise, riot):
        self._db.execute(
            "UPDATE ips SET greynoise_class=?, greynoise_noise=?,"
            " greynoise_riot=? WHERE ip=?",
            (classification, int(noise), int(riot), ip))

    def update_otx(self, ip, pulse_count, country):
        self._backfill_update(ip, overwrite={"otx_pulses": pulse_count},
                              backfill={"country": country})

    def update_proxycheck(self, ip, risk, type_str, data_json):
        self._db.execute(
            "UPDATE ips SET proxycheck_risk=?, proxycheck_type=?,"
            " proxycheck_data=? WHERE ip=?",
            (risk, type_str, data_json, ip))

    def update_ipinfo(self, ip, data_json, city, country):
        self._backfill_update(ip, overwrite={"ipinfo_data": data_json},
                              backfill={"city": city, "country": country})

    def update_raw_results(self, ip, results_json, timestamp):
        # Store the merged raw-results blob and update the last_scanned timestamp.
        self._db.execute(
            "UPDATE ips SET raw_results=?, last_scanned=? WHERE ip=?",
            (results_json, timestamp, ip))

    def log_score_history(self, ip, level, score):
        # Append one row to the score_history audit table.
        self._db.execute(
            "INSERT INTO score_history (timestamp, ip, level, score) VALUES (?,?,?,?)",
            (datetime.now().isoformat(), ip, level, score))

    def update_threat_level(self, ip, level, score=None, vuln_count=None, tag_count=None):
        # Build a single UPDATE that covers all provided fields.
        # vuln_count / tag_count are cached counts for the JSON scoring fields;
        # passing them here avoids a second round-trip to store the cache.
        sets, params = ["threat_level=?"], [level]
        if score is not None:
            sets.append("full_score=?")
            params.append(score)
        if vuln_count is not None:
            sets.append("vuln_count=?")
            params.append(vuln_count)
        if tag_count is not None:
            sets.append("tag_count=?")
            params.append(tag_count)
        params.append(ip)
        self._db.execute(f"UPDATE ips SET {', '.join(sets)} WHERE ip=?", params)
        if score is not None:
            self.log_score_history(ip, level, score)

    def update_threat_levels_batch(self, changes, record_history=True):
        # Persist multiple threat-level + score changes in a single executemany.
        # changes: iterable of (level, score, ip) tuples.
        # record_history=False skips writing to score_history (used during
        # startup initial-score caching where no real level event occurred).
        changes = list(changes)
        self._db.executemany(
            "UPDATE ips SET threat_level=?, full_score=? WHERE ip=?",
            changes
        )
        if record_history and changes:
            ts = datetime.now().isoformat()
            self._db.executemany(
                "INSERT INTO score_history (timestamp, ip, level, score) VALUES (?,?,?,?)",
                [(ts, ip, level, score) for level, score, ip in changes]
            )

    def get_score_history(self, ip, limit=20):
        # Return the last `limit` score-history entries for an IP, newest first.
        return self._db.execute(
            "SELECT timestamp, level, score FROM score_history"
            " WHERE ip=? ORDER BY timestamp DESC LIMIT ?",
            (ip, limit)
        ).fetchall()

    def _build_filter_where(self, threat_level, unscanned_flag, cc_filter,
                            search_term=None, *,
                            score_min=None, score_max=None,
                            first_seen_days=None, last_seen_days=None,
                            asn_isp_term=None, country_codes=None,
                            min_hits=None):
        # Build the shared WHERE clause used by get_scoring_data_for_filter,
        # get_ips_for_table, and get_insights_records.
        # Returns (where_clause_str, params_list), or (None, None) when cc_filter
        # or country_codes is active but empty (caller should return an empty
        # result immediately).
        #
        # The keyword-only params (score_min onward) back the Advanced Filter
        # Controls sidebar panel and AND-combine with the legacy positional
        # filters above. Each defaults to None ("control not engaged, don't
        # filter") — callers/tests that only pass the original params are
        # unaffected.
        where_parts = []
        params = []
        if threat_level is not None:
            where_parts.append("threat_level=?")
            params.append(threat_level)
        if unscanned_flag is not None:
            _require_valid_columns([unscanned_flag], _VALID_SCAN_FLAGS)
            where_parts.append(f"{unscanned_flag}=0")
        if cc_filter is not None:
            if not cc_filter:
                return None, None  # active filter, no codes → no rows match
            placeholders = ",".join("?" * len(cc_filter))
            where_parts.append(f"country IN ({placeholders})")
            params.extend(cc_filter)

        # ── Advanced filter panel clauses ──────────────────────────
        if country_codes is not None:
            if not country_codes:
                return None, None  # listbox engaged, nothing checked → no rows match
            placeholders = ",".join("?" * len(country_codes))
            where_parts.append(f"country IN ({placeholders})")
            params.extend(country_codes)

        if score_min is not None or score_max is not None:
            lo = score_min if score_min is not None else 0
            hi = score_max if score_max is not None else 100
            if lo <= 0:
                # full_score = -1 is the "Pending/not yet scored" sentinel.
                # Only raising the floor above 0 should exclude Pending rows —
                # leaving the floor at 0 means "don't hide anything extra".
                where_parts.append("(full_score BETWEEN ? AND ? OR full_score = -1)")
            else:
                where_parts.append("full_score BETWEEN ? AND ?")
            params.extend([lo, hi])

        if min_hits is not None:
            where_parts.append("total_hits >= ?")
            params.append(min_hits)

        if first_seen_days is not None:
            cutoff = (datetime.now() - timedelta(days=first_seen_days)).strftime("%Y-%m-%d %H:%M:%S")
            where_parts.append(f"{_ctime_sort_expr('first_seen')} >= ?")
            params.append(cutoff)

        if last_seen_days is not None:
            cutoff = (datetime.now() - timedelta(days=last_seen_days)).strftime("%Y-%m-%d %H:%M:%S")
            where_parts.append(f"{_ctime_sort_expr('last_seen')} >= ?")
            params.append(cutoff)

        if asn_isp_term:
            # Comma-separated terms OR together (e.g. "AS123, AS456" matches
            # IPs belonging to either ASN) — each term itself OR-matches
            # against both asn and isp.
            terms = [t.strip() for t in asn_isp_term.split(",") if t.strip()]
            if terms:
                term_clauses = []
                for term in terms:
                    like = f"%{term}%"
                    term_clauses.append("(asn LIKE ? OR isp LIKE ?)")
                    params.extend([like, like])
                where_parts.append("(" + " OR ".join(term_clauses) + ")")

        if search_term:
            like = f"%{search_term}%"
            where_parts.append(
                "(ip LIKE ? OR country LIKE ? OR reverse_dns LIKE ?"
                " OR threat_level LIKE ? OR greynoise_class LIKE ?"
                " OR proxycheck_type LIKE ?)"
            )
            params.extend([like] * 6)
        where_clause = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""
        return where_clause, params

    def get_scoring_data_for_filter(self, scoring_cols,
                                    threat_level=None, unscanned_flag=None,
                                    cc_filter=None, *,
                                    score_min=None, score_max=None,
                                    first_seen_days=None, last_seen_days=None,
                                    asn_isp_term=None, country_codes=None,
                                    min_hits=None):
        # Return {ip: (old_level, *scoring_col_values)} for all IPs matching
        # the sidebar filter without going through the Treeview widget.
        # Used by recalculate_threat_levels() to avoid the redundant
        # Treeview-traversal → DB re-fetch round-trip.
        #
        # cc_filter (tuple|None): if set, restricts to IPs whose country code
        #                         is in the tuple (values are parameterized).
        #                         An empty tuple means no codes are highlighted,
        #                         so no rows match and {} is returned immediately.
        #
        # The keyword-only params back the Advanced Filter Controls panel —
        # see _build_filter_where() for their semantics.
        _require_valid_columns(scoring_cols)
        select_cols = ["ip", "threat_level"] + list(scoring_cols)
        base = f"SELECT {', '.join(select_cols)} FROM ips"
        where_clause, params = self._build_filter_where(
            threat_level, unscanned_flag, cc_filter,
            score_min=score_min, score_max=score_max,
            first_seen_days=first_seen_days, last_seen_days=last_seen_days,
            asn_isp_term=asn_isp_term, country_codes=country_codes,
            min_hits=min_hits)
        if where_clause is None:
            return {}   # cc_filter or country_codes active but empty → no rows
        return {
            row[0]: row[1:]
            for row in self._db.execute(base + where_clause, params)
        }

    # ── Read: table display ───────────────────────────────────────

    # Fixed column list for analytics/insights queries (omits heavy blob columns).
    _INSIGHTS_COLS = (
        "ip", "threat_level", "full_score",
        "country", "city", "isp", "asn",
        "abuseipdb_score", "vt_score", "otx_pulses",
        "greynoise_class", "greynoise_noise", "greynoise_riot",
        "proxycheck_risk", "proxycheck_type",
        "internetdb_tags", "internetdb_vulns", "internetdb_ports",
        "internetdb_cpes",
        "shodan_vulns", "shodan_ports",
        "total_hits", "new_hits",
        "first_seen", "last_seen",
        "log_rules", "dst_ports", "src_ports", "protocols",
        "scanned_abuseipdb", "scanned_virustotal", "scanned_shodan",
        "scanned_internetdb", "scanned_greynoise", "scanned_otx",
        "scanned_proxycheck", "scanned_ipinfo", "scanned_ipapi", "scanned_dns",
    )

    # Fixed column list for the Treeview table display query.
    _TABLE_COLS = (
        "ip", "threat_level", "abuseipdb_score", "vt_score", "total_hits",
        "first_seen", "last_seen", "country", "greynoise_class", "otx_pulses",
        "reverse_dns", "shodan_vulns", "internetdb_vulns", "internetdb_tags",
        "proxycheck_type", "proxycheck_risk",
        "full_score",                           # numeric severity set by update_threat_level()
        "scanned_abuseipdb", "scanned_virustotal",
        "scanned_greynoise", "scanned_shodan", "scanned_internetdb",
        "scanned_otx", "scanned_proxycheck", "scanned_ipinfo",
        "scanned_ipapi", "scanned_dns",
    )

    def get_ips_for_table(self, threat_level=None, unscanned_flag=None,
                          search_term=None, sort_col=None, sort_asc=False,
                          cc_filter=None, *,
                          score_min=None, score_max=None,
                          first_seen_days=None, last_seen_days=None,
                          asn_isp_term=None, country_codes=None,
                          min_hits=None):
        # Return all display+scoring columns for table population.
        #
        # threat_level   (str|None): parameterized WHERE threat_level=?
        # unscanned_flag (str|None): whitelisted column; WHERE <flag>=0
        # search_term    (str|None): LIKE filter across the six most useful text
        #                            columns (ip, country, reverse_dns,
        #                            threat_level, greynoise_class,
        #                            proxycheck_type).  All values parameterized.
        # sort_col       (str|None): Treeview column ID from _TREE_COL_TO_DB_SORT;
        #                            None falls back to ORDER BY total_hits DESC.
        # sort_asc       (bool):     True = ASC, False = DESC.
        # cc_filter      (tuple|None): if set, restricts to IPs whose country
        #                              code is in the tuple (parameterized).
        #                              Empty tuple → no codes highlighted → no rows.
        #
        # The keyword-only params back the Advanced Filter Controls panel —
        # see _build_filter_where() for their semantics.
        base = "SELECT " + ", ".join(self._TABLE_COLS) + " FROM ips"
        where_clause, params = self._build_filter_where(
            threat_level, unscanned_flag, cc_filter, search_term,
            score_min=score_min, score_max=score_max,
            first_seen_days=first_seen_days, last_seen_days=last_seen_days,
            asn_isp_term=asn_isp_term, country_codes=country_codes,
            min_hits=min_hits)
        if where_clause is None:
            return []   # cc_filter or country_codes active but empty → no rows

        # ORDER BY: use the mapped DB column when the caller supplies a valid
        # sort_col; fall back to total_hits DESC (the default display order).
        db_col = _TREE_COL_TO_DB_SORT.get(sort_col) if sort_col else None
        if db_col == "full_score":
            # full_score = -1 is the sentinel for "not yet scored".
            # All IPs must sort together by their numeric score so that Pending,
            # Partial, and Final rows are interleaved purely by score value.
            #
            # DESC: -1 is numerically less than every real score (0–100), so
            #       unscored rows sink to the bottom naturally — no grouping needed.
            #
            # ASC:  -1 is less than 0, so unscored rows would float to the top
            #       without intervention.  Replace -1 with 101 (above the 0–100
            #       real range) so unscored rows still sort last.
            if sort_asc:
                # CASE remaps -1 → 101 so unscored rows land after all real scores
                order_clause = (
                    " ORDER BY CASE WHEN full_score >= 0 THEN full_score ELSE 101 END ASC"
                )
            else:
                order_clause = " ORDER BY full_score DESC"
        elif db_col in ("first_seen", "last_seen"):
            expr = _ctime_sort_expr(db_col)
            order_clause = f" ORDER BY {expr} {'ASC' if sort_asc else 'DESC'}"
        elif db_col:
            order_clause = f" ORDER BY {db_col} {'ASC' if sort_asc else 'DESC'}"
        else:
            order_clause = " ORDER BY total_hits DESC"

        return self._db.execute(
            base + where_clause + order_clause, params
        ).fetchall()

    def get_insights_records(self, threat_level=None, unscanned_flag=None,
                             cc_filter=None, search_term=None, *,
                             score_min=None, score_max=None,
                             first_seen_days=None, last_seen_days=None,
                             asn_isp_term=None, country_codes=None,
                             min_hits=None):
        # Return full analytics columns for all IPs matching the current filter.
        # Applies identical WHERE logic to get_ips_for_table() so Data Insights
        # always reflects exactly the same visible set as the Treeview.
        # Omits raw_results / ipinfo_data / proxycheck_data (large blobs).
        base = "SELECT " + ", ".join(self._INSIGHTS_COLS) + " FROM ips"
        where_clause, params = self._build_filter_where(
            threat_level, unscanned_flag, cc_filter, search_term,
            score_min=score_min, score_max=score_max,
            first_seen_days=first_seen_days, last_seen_days=last_seen_days,
            asn_isp_term=asn_isp_term, country_codes=country_codes,
            min_hits=min_hits)
        if where_clause is None:
            return []   # cc_filter or country_codes active but empty → no rows
        rows = self._db.execute(base + where_clause, params).fetchall()
        return [dict(zip(self._INSIGHTS_COLS, row)) for row in rows]

    def get_display_row(self, ip):
        # Return the display+scoring columns for a single IP (used for in-place row updates).
        cols = self._TABLE_COLS[1:]  # skip "ip" — it's the WHERE key, not a fetched column
        row = self._db.execute(
            "SELECT " + ", ".join(cols) + " FROM ips WHERE ip=?", (ip,)
        ).fetchone()
        return row  # tuple matching _TABLE_COLS[1:], or None

    def get_threat_level_counts(self):
        # Return {threat_level: count} for all IPs in the database (for sidebar stats).
        return {
            lvl: cnt
            for lvl, cnt in self._db.execute(
                "SELECT threat_level, COUNT(*) FROM ips GROUP BY threat_level"
            )
        }

    # ── Read: blocklist export ────────────────────────────────────

    def count_ips_by_level(self, level):
        # Return the count of IPs at a single threat level (for checkbox labels).
        return self._db.execute(
            "SELECT COUNT(*) FROM ips WHERE threat_level=?", (level,)
        ).fetchone()[0]

    def count_ips_by_levels(self, levels):
        # Return the total count of IPs matching any of the given threat levels.
        placeholders = ",".join("?" * len(levels))
        return self._db.execute(
            f"SELECT COUNT(*) FROM ips WHERE threat_level IN ({placeholders})",
            levels
        ).fetchone()[0]

    def get_ips_by_levels(self, levels):
        # Return (ip, threat_level) rows for all IPs matching the given levels.
        placeholders = ",".join("?" * len(levels))
        return self._db.execute(
            f"SELECT ip, threat_level FROM ips"
            f" WHERE threat_level IN ({placeholders}) ORDER BY full_score DESC, ip",
            levels
        ).fetchall()

    def count_ips_by_countries(self, cc_codes):
        # Return count of IPs whose country code is in cc_codes.
        if not cc_codes:
            return 0
        placeholders = ",".join("?" * len(cc_codes))
        return self._db.execute(
            f"SELECT COUNT(*) FROM ips WHERE country IN ({placeholders})",
            list(cc_codes)
        ).fetchone()[0]

    def get_ips_by_countries(self, cc_codes):
        # Return (ip, country) rows for IPs whose country code is in cc_codes.
        if not cc_codes:
            return []
        placeholders = ",".join("?" * len(cc_codes))
        return self._db.execute(
            f"SELECT ip, country FROM ips"
            f" WHERE country IN ({placeholders}) ORDER BY full_score DESC, ip",
            list(cc_codes)
        ).fetchall()

    def get_distinct_countries(self):
        # Return [(country_code, count), ...] for every non-empty country
        # value currently present in ips, ordered alphabetically by code.
        # Powers the Advanced Filter Controls country multi-select Listbox —
        # distinct from cc_highlight_codes/_cc_highlight, which is a fixed
        # user-configured watchlist rather than a query against live data.
        return self._db.execute(
            "SELECT country, COUNT(*) FROM ips"
            " WHERE country IS NOT NULL AND country != ''"
            " GROUP BY country ORDER BY country ASC"
        ).fetchall()

    # ── Read / write: JSON import ─────────────────────────────────

    def get_column_set(self):
        # Return the set of column names currently in the ips table.
        # Used by import_json to filter records to the live schema.
        return {
            row[1]
            for row in self._db.execute("PRAGMA table_info(ips)").fetchall()
        }

    def upsert_record(self, filtered):
        # Merge an imported record into ips without destroying unmentioned columns.
        # Uses INSERT … ON CONFLICT DO UPDATE so columns absent from the imported
        # record retain their existing values (unlike INSERT OR REPLACE, which
        # deletes and re-inserts the row, losing any column not present in the import).
        _require_valid_columns(filtered.keys())
        cols = list(filtered.keys())
        cols_sql = ", ".join(cols)
        placeholders = ", ".join("?" * len(cols))
        update_set = ", ".join(f"{c}=excluded.{c}" for c in cols if c != "ip")
        if update_set:
            self._db.execute(
                f"INSERT INTO ips ({cols_sql}) VALUES ({placeholders})"
                f" ON CONFLICT(ip) DO UPDATE SET {update_set}",
                list(filtered.values()))
        else:
            # Only the primary key was provided — insert new row, leave existing untouched.
            self._db.execute(
                f"INSERT OR IGNORE INTO ips ({cols_sql}) VALUES ({placeholders})",
                list(filtered.values()))

    # ── scan_log maintenance ──────────────────────────────────────

    def get_scan_log_stats(self):
        # Return {count, oldest, newest} for the scan_log table.
        # oldest/newest are ISO timestamp strings or None when the table is empty.
        row = self._db.execute(
            "SELECT COUNT(*), MIN(timestamp), MAX(timestamp) FROM scan_log"
        ).fetchone()
        return {"count": row[0] or 0, "oldest": row[1], "newest": row[2]}

    def prune_scan_log(self, days):
        # Delete scan_log rows whose timestamp is older than `days` days.
        # Returns the number of rows deleted. Never touches the ips table.
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        result = self._db.execute(
            "DELETE FROM scan_log WHERE timestamp < ?", (cutoff,))
        self._db.commit()
        return result.rowcount

    # ── Delete ────────────────────────────────────────────────────

    def delete_ip(self, ip):
        # Remove an IP and its associated scan-log and score-history entries.
        self._db.execute("DELETE FROM ips WHERE ip=?", (ip,))
        self._db.execute("DELETE FROM scan_log WHERE ip=?", (ip,))
        self._db.execute("DELETE FROM score_history WHERE ip=?", (ip,))

    def clear_all(self):
        # Truncate all three tables. Caller must confirm with the user first.
        self._db.execute("DELETE FROM ips")
        self._db.execute("DELETE FROM scan_log")
        self._db.execute("DELETE FROM score_history")
