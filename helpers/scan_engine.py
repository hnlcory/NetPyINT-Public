#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════╗
# ║              NetPyINT – Scan Engine                              ║
# ║    Thread-safe OSINT scan coordinator and platform registry      ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# Owns all background scanning logic: the platform registry, the per-IP
# worker, and the coordinator that fans work out across threads.
# Has no Tkinter dependency — all GUI communication goes via a queue.Queue
# passed in through _ScanContext.
#
# Public surface (imported by netpyint_main.py):
#     _PlatformRateLimiter
#     _ScanContext
#     _Platform
#     _PLATFORM_REGISTRY
#     run_scan(ips, ctx)        — the coordinator (runs on a daemon thread)
#     scan_one_ip(ip, ctx)      — per-IP worker (serial or pool task)

import concurrent.futures
import json
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime

from api_requests import (
    query_abuseipdb, query_virustotal, query_shodan,
    query_internetdb, query_greynoise, query_otx,
    query_proxycheck, query_ipinfo, query_ipapi_free,
    query_reverse_dns,
    RATE_LIMIT_THRESHOLD, _is_rate_limit_error,
)
from config import RESULT_KEY_TO_PLATFORM, RATE_LIMIT_EXEMPT, THREAT_LEVEL_COLUMNS
from db_repository import IPRepository
from scoring import compute_threat_level, compute_vuln_tag_counts


# ─────────────────────────────────────────────────────────────────
# Per-platform rate limiter
# ─────────────────────────────────────────────────────────────────

class _PlatformRateLimiter:
    # Thread-safe per-platform rate limiter used by the parallel scan worker.
    #
    # One instance is created per OSINT platform at scan start and shared across
    # all worker threads for that scan session. Workers call wait_and_mark()
    # immediately before issuing an HTTP request to the platform. The call
    # blocks until at least min_delay seconds have passed since the previous
    # call from ANY thread, then stamps the current time before returning.
    #
    # Why the lock is held during sleep:
    #     Holding the lock for the full sleep duration serialises callers in
    #     strict order.  If N threads arrive simultaneously, thread 1 sleeps,
    #     wakes, marks _last_call, and releases.  Thread 2 then acquires the
    #     lock, recomputes the gap (now ≈ min_delay again), sleeps the full
    #     interval, and so on.  The net effect is one call per min_delay second,
    #     regardless of how many workers are contending.
    #
    #     Without this serialisation — i.e. if the lock were released before
    #     sleeping — all waiting threads would see a stale _last_call and could
    #     all compute gap ≤ 0 simultaneously, bursting through at once and
    #     violating the rate limit.
    def __init__(self, min_delay):
        self._min_delay = min_delay
        self._lock = threading.Lock()
        self._last_call = 0.0

    def wait_and_mark(self):
        with self._lock:
            now = time.monotonic()
            gap = self._last_call + self._min_delay - now
            if gap > 0:
                time.sleep(gap)
            self._last_call = time.monotonic()


# ─────────────────────────────────────────────────────────────────
# Shared scan-session context
# ─────────────────────────────────────────────────────────────────

@dataclass
class _ScanContext:
    # Immutable scan-session context passed from run_scan to every
    # scan_one_ip call (serial or parallel).
    #
    # UI-bridge fields (msg_queue, scan_stop, scan_paused, db_path) let the
    # engine communicate with the GUI without importing Tkinter.
    #
    # registry: the platform registry tuple to iterate. Defaults to scan_engine's
    # own _PLATFORM_REGISTRY if None, but can be overridden by the caller so that
    # lambdas in the registry close over the caller's (patchable) namespace.
    enabled:           dict             # platform name → bool (snapshot at scan start)
    platform_limiters: dict             # platform name → _PlatformRateLimiter
    rl_lock:           threading.Lock   # guards rate_limit_streak
    rate_limit_streak: dict             # platform name → consecutive rate-limit error count
    auto_stop:         bool             # True → stop when all platforms are rate-limited
    label:             str              # log prefix: "" or " rescan"
    progress_lock:     threading.Lock   # guards progress_counter
    progress_counter:  list             # [int] — incremented atomically per started IP
    total:             int              # total IPs in this batch
    config:            dict             # deep-copy of app config taken at scan start
    # Optional UI-bridge fields — None is valid only when scan_one_ip is called from
    # NetPyINTApp._scan_one_ip, which fills them in from self before dispatching.
    msg_queue:         object = None    # queue.Queue for posting messages to the GUI
    scan_stop:         object = None    # threading.Event; set to halt all workers
    scan_paused:       object = None    # threading.Event; cleared to pause, set to resume
    db_path:           object = None    # SQLite file path for per-worker connections
    rescan:            bool   = False   # True → skip already-scanned platforms per IP
    registry:          object = None    # platform registry; None → use _PLATFORM_REGISTRY


# ─────────────────────────────────────────────────────────────────
# Platform registry
# ─────────────────────────────────────────────────────────────────
#
# Reverse DNS priority system
# ───────────────────────────
# The registry order directly controls which platform's hostname fills
# reverse_dns first.  Two write tiers are used:
#
#   Tier 1 — authoritative (direct SET via update_reverse_dns):
#       DNS Reverse Lookup only.  Always overwrites any prior value,
#       including one backfilled by a lower-priority source.
#
#   Tier 2 — fallback (COALESCE via backfill_reverse_dns):
#       ip-api, IPInfo, Shodan, InternetDB.  Only writes when the field
#       is currently empty; later platforms are no-ops if an earlier one
#       already filled it in.
#
# Priority order (highest → lowest):
#   1. DNS Reverse Lookup   (r["reverse_dns"])
#   2. ip-api (free)        (r["reverse"])
#   3. IPInfo               (r["hostname"])   ← moved to pos 3 for rdns priority;
#                                               geo backfill unaffected (ip-api wins first)
#   4. Shodan               (r["hostnames"][0])
#   5. Shodan InternetDB    (r["hostnames"][0])
#
# IMPORTANT (M5): This registry is intentionally duplicated in netpyint_main.py.
# Any change to order, platform list, or rdns fields must be applied to both files.

@dataclass(frozen=True)
class _Platform:
    name:       str     # key in enabled/PLATFORMS ("AbuseIPDB", "DNS Reverse Lookup", …)
    result_key: str     # key stored in per-IP results dict ("abuseipdb", "dns", …)
    flag_col:   str     # scanned_* column in the DB
    log_tag:    str     # prefix for queue log messages
    query_fn:   object  # (ip: str, config: dict) -> dict
    update_fn:  object  # (repo: IPRepository, ip: str, result: dict) -> None
    needs_key:  bool  = False   # True → platform returns _skipped when API key missing
    min_delay:  float = 0.0     # actual sleep = max(scan_delay, min_delay)
    log_name:   str   = ""      # if non-empty, call repo.log_scan after success


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


# ─────────────────────────────────────────────────────────────────
# Per-IP worker
# ─────────────────────────────────────────────────────────────────

def scan_one_ip(ip, ctx):
    # Query all enabled OSINT platforms for a single IP address.
    #
    # Designed to run either directly on the scan thread (serial mode) or
    # as a ThreadPoolExecutor task (parallel mode).  All GUI communication
    # goes via ctx.msg_queue; no Tkinter widgets are accessed directly.
    #
    # UI-bridge fields (scan_stop, msg_queue, scan_paused, db_path) must be set.
    # When calling via NetPyINTApp._scan_one_ip(), they are filled automatically.
    if ctx.scan_stop is None or ctx.msg_queue is None or ctx.db_path is None:
        raise ValueError(
            "scan_one_ip requires ctx.scan_stop, ctx.msg_queue, and ctx.db_path. "
            "Call via NetPyINTApp._scan_one_ip() which fills them from self, "
            "or build _ScanContext with all UI-bridge fields explicitly set.")
    if ctx.scan_stop.is_set():
        return

    with ctx.progress_lock:
        ctx.progress_counter[0] += 1
        idx = ctx.progress_counter[0]
    ctx.msg_queue.put(("progress", (idx, ctx.total, ip)))

    results = {}
    queried_any = False

    local_conn = sqlite3.connect(ctx.db_path, check_same_thread=False)
    local_repo = IPRepository(local_conn)

    try:
        flags = {}
        if ctx.rescan:
            flags = local_repo.get_scan_flags(ip)
            if flags is None:
                return

        registry = ctx.registry if ctx.registry is not None else _PLATFORM_REGISTRY
        for plat in registry:
            if ctx.scan_stop.is_set():
                return
            ctx.scan_paused.wait()

            if not ctx.enabled.get(plat.name):
                continue
            if ctx.rescan and flags.get(plat.flag_col):
                continue

            ctx.msg_queue.put(("log", f"[{plat.log_tag}{ctx.label}] {ip}"))
            ctx.platform_limiters[plat.name].wait_and_mark()

            r = plat.query_fn(ip, ctx.config)
            results[plat.result_key] = r
            skipped = plat.needs_key and bool(r.get("_skipped"))

            if not r.get("_error") and not skipped:
                plat.update_fn(local_repo, ip, r)
                if plat.log_name:
                    local_repo.log_scan(ip, plat.log_name, "OK", json.dumps(r))
                local_repo.mark_scanned(ip, plat.flag_col)
                local_repo.commit()
                queried_any = True
            elif skipped:
                ctx.msg_queue.put(("log", f"  ↳ {plat.name} skipped (no API key)"))
            else:
                ctx.msg_queue.put(("log", f"  ↳ {plat.name} error: {r['_error']}"))
                queried_any = True

        if ctx.rescan and not queried_any:
            ctx.msg_queue.put(("log", f"  ↳ {ip} – all enabled platforms already scanned"))
            return

        try:
            if ctx.rescan:
                existing_raw = local_repo.get_raw_results(ip)
                try:
                    raw_dict = json.loads(existing_raw) if existing_raw else {}
                except Exception:
                    raw_dict = {}
                raw_dict.update(results)
                local_repo.update_raw_results(ip, json.dumps(raw_dict, default=str),
                                              datetime.now().isoformat())
            else:
                local_repo.update_raw_results(ip, json.dumps(results, default=str),
                                              datetime.now().isoformat())

            if ctx.auto_stop:
                with ctx.rl_lock:
                    participating = set()
                    for rkey, platform in RESULT_KEY_TO_PLATFORM.items():
                        if platform in RATE_LIMIT_EXEMPT or not ctx.enabled.get(platform):
                            continue
                        r = results.get(rkey)
                        if r is None or r.get("_skipped"):
                            continue
                        participating.add(platform)
                        if _is_rate_limit_error(r):
                            ctx.rate_limit_streak[platform] = (
                                ctx.rate_limit_streak.get(platform, 0) + 1)
                        elif not r.get("_error"):
                            ctx.rate_limit_streak[platform] = 0

                    if participating and all(
                            ctx.rate_limit_streak.get(p, 0) >= RATE_LIMIT_THRESHOLD
                            for p in participating):
                        over = {p: ctx.rate_limit_streak[p] for p in participating}
                        ctx.msg_queue.put(("log",
                            f"⚠ AUTO-STOP: All active platforms hit rate limits "
                            f"({RATE_LIMIT_THRESHOLD}x consecutive): {over}"))
                        ctx.scan_stop.set()

            score_data = local_repo.get_scoring_data(ip, THREAT_LEVEL_COLUMNS)
            if score_data:
                level, score = compute_threat_level(score_data)
                vuln_count, tag_count = compute_vuln_tag_counts(score_data)
                local_repo.update_threat_level(ip, level, score,
                                               vuln_count=vuln_count,
                                               tag_count=tag_count)
                ctx.msg_queue.put(("log",
                    f"  ↳ {ip}  →  {level} (score {score:.0f})"))

        except Exception as exc:
            ctx.msg_queue.put(("log", f"  ↳ {ip} post-scan error: {exc}"))
        finally:
            try:
                local_repo.commit()
            except Exception:
                pass
            ctx.msg_queue.put(("update_ip", ip))

    finally:
        local_conn.close()


# ─────────────────────────────────────────────────────────────────
# Scan coordinator
# ─────────────────────────────────────────────────────────────────

def run_scan(ips, ctx):
    # Background OSINT scan coordinator — intended to run on a daemon thread.
    #
    # Dispatches per-IP work to scan_one_ip either serially (ctx.config
    # parallel_workers == 1) or via a bounded ThreadPoolExecutor (2–8 workers).
    # Sends a ("done", None) queue message when all IPs are processed so the
    # GUI can re-enable controls regardless of how the scan ended.
    n_workers = max(1, min(8, ctx.config.get("parallel_workers", 1)))
    stop_msg  = "Rescan stopped." if ctx.rescan else "Scan stopped."

    if n_workers == 1:
        for ip in ips:
            if ctx.scan_stop.is_set():
                ctx.msg_queue.put(("status", stop_msg))
                break
            scan_one_ip(ip, ctx)
    else:
        ctx.msg_queue.put(("log", f"[Parallel] Starting scan with {n_workers} workers"))
        with concurrent.futures.ThreadPoolExecutor(max_workers=n_workers) as pool:
            ip_iter = iter(ips)
            active = {}

            def _try_submit():
                if ctx.scan_stop.is_set():
                    return
                try:
                    ip = next(ip_iter)
                    active[pool.submit(scan_one_ip, ip, ctx)] = ip
                except StopIteration:
                    pass

            for _ in range(n_workers):
                _try_submit()

            while active:
                done, _ = concurrent.futures.wait(
                    active, return_when=concurrent.futures.FIRST_COMPLETED)
                for fut in done:
                    try:
                        fut.result()
                    except Exception as exc:
                        ctx.msg_queue.put(("log",
                            f"  ↳ Worker error for {active[fut]}: {exc}"))
                    del active[fut]
                    _try_submit()

        if ctx.scan_stop.is_set():
            ctx.msg_queue.put(("status", stop_msg))

    ctx.msg_queue.put(("done", None))
