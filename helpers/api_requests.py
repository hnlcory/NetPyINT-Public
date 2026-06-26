#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════╗
# ║              NetPyINT – OSINT API Clients                        ║
# ║    HTTP helper and per-platform query functions                  ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# Each function queries one external threat intelligence platform.
# They all follow the same contract:
#
#   Inputs:  An IP address string, plus an API key where required.
#   Returns: A normalised dict of extracted fields on success,
#            {"_error": "..."} on failure,
#            {"_skipped": True} if the required API key is missing.
#
# The normalised dicts are designed so the scan worker can directly
# update the relevant database columns without further transformation.
#
# Public surface (imported by netpyint_main.py):
#     _api_get()
#     query_abuseipdb(), query_virustotal(), query_shodan()
#     query_internetdb(), query_greynoise(), query_otx()
#     query_proxycheck(), query_ipinfo(), query_ipapi_free()
#     query_reverse_dns()
#     RATE_LIMIT_THRESHOLD, _is_rate_limit_error()

import json
import socket
import sys
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from urllib.parse import quote

from config import VERSION

# Built once at import time so _api_get() doesn't rebuild the string per call.
_USER_AGENT = (f"NetPyINT-ThreatIntel/{VERSION}"
               f" (Python/{sys.version_info[0]}.{sys.version_info[1]})")

# ─────────────────────────────────────────────────────────────────
# Shared HTTP helper
# ─────────────────────────────────────────────────────────────────

def _api_get(url, headers=None, timeout=15):
    # Perform an HTTP GET request and return the parsed JSON response.
    #
    # This is the shared HTTP helper used by all OSINT query functions.
    # It wraps urllib to avoid requiring the 'requests' library.
    #
    # Inputs:
    #     url     (str):  Full URL to fetch (already URL-encoded).
    #     headers (dict): Optional HTTP headers (e.g. API keys, Accept types).
    #     timeout (int):  Seconds before the request times out (default 15).
    #
    # Returns:
    #     dict – Parsed JSON response body on success.
    #     dict – {"_error": "<message>", "_status": <int>} on HTTP errors.
    #            _status is the HTTP status code (e.g. 429, 403, 404).
    #     dict – {"_error": "<message>"} on network/parse failures.
    #
    # Rate-limit detection:
    #     HTTP 429 (Too Many Requests) is the standard rate-limit response.
    #     Some APIs also use 403 (Forbidden) when quotas are exceeded.
    #     The caller can check r.get("_status") to distinguish error types.
    #
    # Usage:
    #     Called internally by every query_* function. Not called directly
    #     by the GUI or scan worker.
    req = Request(url, headers=headers or {})
    # Set a realistic User-Agent if the caller didn't provide one.
    # Python's default urllib User-Agent ("Python-urllib/3.x") is blocked
    # by Cloudflare (error 1010) on endpoints like Shodan InternetDB.
    if not req.has_header("User-agent") and not req.has_header("User-Agent"):
        req.add_header("User-Agent", _USER_AGENT)
    try:
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except HTTPError as exc:
        # HTTP 4xx/5xx – try to read the error response body for context
        # APIs often include rate-limit messages or error details in the body
        error_body = ""
        try:
            error_body = exc.read().decode()[:500]  # Cap at 500 chars
        except Exception:
            pass
        status = exc.code  # HTTP status code (e.g. 429, 403, 404)
        return {
            "_error": f"HTTP {status}: {error_body or str(exc)}",
            "_status": status,
        }
    except (URLError, Exception) as exc:
        # Network errors (DNS failure, timeout, connection refused, etc.)
        return {"_error": str(exc)}


# ─────────────────────────────────────────────────────────────────
# Platform query functions
# ─────────────────────────────────────────────────────────────────

def query_abuseipdb(ip, api_key, max_days=90):
    # Query AbuseIPDB for crowd-sourced abuse reports on an IP address.
    #
    # AbuseIPDB aggregates reports from system administrators worldwide.
    # The key metric is the "abuse confidence score" (0-100%), which
    # indicates how confident the community is that the IP is malicious.
    #
    # Inputs:
    #     ip       (str): IPv4 address to check (e.g. "118.123.1.39").
    #     api_key  (str): AbuseIPDB API key. If empty, returns _skipped.
    #     max_days (int): How far back to look for reports (default 90 days).
    #
    # Returns:
    #     dict with keys:
    #         abuseConfidenceScore (int):  0-100 confidence percentage
    #         totalReports         (int):  Number of abuse reports filed
    #         country              (str):  ISO country code of the IP
    #         isp                  (str):  Internet Service Provider name
    #         domain               (str):  Associated domain name
    #         usageType            (str):  e.g. "Data Center/Web Hosting/Transit"
    #         isWhitelisted        (bool): Whether IP is on AbuseIPDB's whitelist
    #
    # Usage:
    #     Called from _scan_worker() when "AbuseIPDB" is enabled.
    #     The abuseConfidenceScore is stored in the DB as abuseipdb_score
    #     and contributes 35% weight to the overall threat level.
    if not api_key:
        return {"_skipped": True}
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={quote(ip)}&maxAgeInDays={max_days}&verbose"  # quote() URL-encodes the IP
    headers = {"Key": api_key, "Accept": "application/json"}
    data = _api_get(url, headers)
    if not data or "_error" in data:
        return data or {"_error": "empty"}
    # AbuseIPDB wraps results in a "data" key. If missing or null, the
    # response is malformed (possibly an error page or quota message).
    # Also check for "errors" key which AbuseIPDB uses for validation errors.
    if data.get("errors"):
        return {"_error": f"AbuseIPDB error: {data['errors']}"}
    d = data.get("data")
    if not isinstance(d, dict) or "abuseConfidenceScore" not in d:
        return {"_error": f"AbuseIPDB unexpected response structure: {str(data)[:200]}"}
    return {
        "abuseConfidenceScore": d.get("abuseConfidenceScore", 0),
        "totalReports": d.get("totalReports", 0),
        "country": d.get("countryCode", ""),
        "isp": d.get("isp", ""),
        "domain": d.get("domain", ""),
        "usageType": d.get("usageType", ""),
        "isWhitelisted": d.get("isWhitelisted", False),
    }


def query_virustotal(ip, api_key):
    # Query VirusTotal for multi-engine reputation analysis of an IP address.
    #
    # VirusTotal aggregates results from 70+ antivirus engines and URL
    # scanners. The key metric is the percentage of engines that flag
    # the IP as malicious or suspicious.
    #
    # Inputs:
    #     ip      (str): IPv4 address to check.
    #     api_key (str): VirusTotal API key (v3). If empty, returns _skipped.
    #
    # Returns:
    #     dict with keys:
    #         malicious   (int):   Count of engines flagging as malicious
    #         suspicious  (int):   Count of engines flagging as suspicious
    #         harmless    (int):   Count of engines flagging as clean
    #         undetected  (int):   Count of engines with no opinion
    #         score_pct   (float): (malicious + suspicious) / total * 100
    #         country     (str):   Country code from VT's geo data
    #         asn         (int):   Autonomous System Number
    #         as_owner    (str):   AS organisation name
    #         reputation  (int):   VT community reputation score
    #
    # Usage:
    #     Called from _scan_worker() when "VirusTotal" is enabled.
    #     The score_pct is stored as vt_score and contributes 25% weight
    #     to the overall threat level.
    if not api_key:
        return {"_skipped": True}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{quote(ip)}"
    headers = {"x-apikey": api_key}
    data = _api_get(url, headers)
    if not data or "_error" in data:
        return data or {"_error": "empty"}
    # VT v3 returns {"error": {"code": "..."}} for quota exceeded, invalid
    # requests, and other API errors — even sometimes as HTTP 200
    if data.get("error"):
        err_code = data["error"].get("code", "unknown") if isinstance(data["error"], dict) else data["error"]
        return {"_error": f"VirusTotal API error: {err_code}"}
    # Navigate the nested VT v3 response structure and validate it exists.
    # Error only when the "attributes" key is absent entirely; an empty
    # attributes dict (present but empty) is valid and scores as 0.
    data_obj = data.get("data", {})
    if not isinstance(data_obj, dict) or "attributes" not in data_obj:
        return {"_error": f"VirusTotal unexpected response (no attributes): {str(data)[:200]}"}
    attrs = data_obj["attributes"]
    if not isinstance(attrs, dict):
        return {"_error": f"VirusTotal unexpected response (attributes not a dict): {str(data)[:200]}"}
    stats = attrs.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 1   # fallback to 1 avoids ZeroDivisionError
    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
        "score_pct": round((malicious + suspicious) / max(total, 1) * 100, 1),
        "country": attrs.get("country", ""),
        "asn": attrs.get("asn", ""),
        "as_owner": attrs.get("as_owner", ""),
        "reputation": attrs.get("reputation", 0),
    }


def query_shodan(ip, api_key):
    # Query Shodan for internet-facing services, open ports, and known vulns.
    #
    # Shodan continuously scans the entire IPv4 space and indexes what
    # services are running on each IP. Useful for identifying exposed
    # services and known CVEs on the attacker's infrastructure.
    #
    # Inputs:
    #     ip      (str): IPv4 address to check.
    #     api_key (str): Shodan API key. If empty, returns _skipped.
    #
    # Returns:
    #     dict with keys:
    #         ports     (list[int]):  Open ports found (e.g. [22, 80, 443])
    #         vulns     (list[str]):  CVE IDs found (e.g. ["CVE-2021-44228"])
    #         country   (str):       Country name
    #         city      (str):       City name
    #         isp       (str):       ISP name
    #         asn       (str):       ASN string
    #         os        (str):       Detected operating system
    #         hostnames (list[str]): Associated hostnames
    #
    # Usage:
    #     Called from _scan_worker() when "Shodan" is enabled.
    #     The vulns list contributes up to 10% weight to threat scoring –
    #     each CVE adds +3 points, capped at 10 total.
    if not api_key:
        return {"_skipped": True}
    url = f"https://api.shodan.io/shodan/host/{quote(ip)}?key={api_key}"
    data = _api_get(url)
    if not data or "_error" in data:
        return data or {"_error": "empty"}
    # Shodan returns {"error": "..."} for invalid keys, rate limits,
    # or IPs not in their database (distinct from HTTP-level errors)
    if data.get("error"):
        return {"_error": f"Shodan: {data['error']}"}
    return {
        "ports": data.get("ports", []),
        "vulns": data.get("vulns", []),
        "country": data.get("country_name", ""),
        "city": data.get("city", ""),
        "isp": data.get("isp", ""),
        "asn": data.get("asn", ""),
        "os": data.get("os", ""),
        "hostnames": data.get("hostnames", []),
    }


def query_internetdb(ip):
    # Query Shodan's free InternetDB API for ports, tags, vulns, and CPEs.
    #
    # InternetDB is a free, keyless API that provides a lightweight summary
    # of what Shodan knows about an IP. Unlike the paid Shodan API, it does
    # not require authentication and has no documented rate limit.
    #
    # The API endpoint is: https://internetdb.shodan.io/{ip}
    #
    # Inputs:
    #     ip (str): IPv4 address to look up.
    #     (No API key required.)
    #
    # Returns:
    #     dict with keys:
    #         ports     (list[int]):  Open ports found (e.g. [22, 80, 443])
    #         tags      (list[str]):  Descriptive tags (e.g. ["cdn", "cloud",
    #                                 "eol-os", "self-signed", "vpn"])
    #         vulns     (list[str]):  CVE IDs found (e.g. ["CVE-2021-44228"])
    #         cpes      (list[str]):  Common Platform Enumeration identifiers
    #                                 (e.g. ["cpe:/a:apache:http_server:2.4.49"])
    #         hostnames (list[str]):  Associated hostnames
    #
    #     On failure:
    #         {"_error": "..."} with optional "_status" for HTTP errors.
    #
    # InternetDB tags of interest for threat analysis:
    #     "eol-os"      – End-of-life operating system (unpatched)
    #     "eol-product" – End-of-life software
    #     "malware"     – Known malware indicators
    #     "c2"          – Command and control server
    #     "self-signed" – Self-signed TLS certificate
    #     "vpn"         – VPN endpoint
    #     "tor"         – Tor exit node
    #     "proxy"       – Proxy server
    #     "cdn"         – Content delivery network
    #     "cloud"       – Cloud provider infrastructure
    #
    # Usage:
    #     Called from _scan_worker() when "Shodan InternetDB" is enabled.
    #     The vulns field feeds into threat scoring alongside paid Shodan vulns.
    #     Tags provide additional context in the IP Details panel.
    url = f"https://internetdb.shodan.io/{quote(ip)}"
    data = _api_get(url)
    if not data:
        return {"_error": "empty response"}
    if "_error" in data:
        status = data.get("_status", 0)
        # InternetDB returns HTTP 404 for IPs not in their database.
        # This is a valid result — the IP simply has no observed services.
        if status == 404:
            return {
                "ports": [],
                "tags": [],
                "vulns": [],
                "cpes": [],
                "hostnames": [],
            }
        return data
    # Check for error in response body (e.g. {"detail": "..."})
    if data.get("detail") and not data.get("ip"):
        return {"_error": f"InternetDB: {data['detail']}"}
    return {
        "ports": data.get("ports", []),
        "tags": data.get("tags", []),
        "vulns": data.get("vulns", []),
        "cpes": data.get("cpes", []),
        "hostnames": data.get("hostnames", []),
    }


def query_greynoise(ip, api_key):
    # Query GreyNoise to classify whether an IP is mass-scanning the internet.
    #
    # GreyNoise operates a global sensor network that detects IPs performing
    # widespread scanning. It classifies IPs as:
    #   - "malicious"  → known attacker / scanner
    #   - "benign"     → known-good service (e.g. search engine crawler)
    #   - "unknown"    → seen scanning but intent unclear
    #
    # Inputs:
    #     ip      (str): IPv4 address to check.
    #     api_key (str): GreyNoise API key (optional). Falls back to the
    #                    free community endpoint if empty.
    #
    # Returns:
    #     dict with keys:
    #         noise          (bool): True if IP is seen mass-scanning
    #         riot           (bool): True if IP belongs to a known-good service
    #         classification (str):  "malicious", "benign", or "unknown"
    #         name           (str):  Service name if identified (e.g. "Shodan")
    #         message        (str):  Human-readable summary from GreyNoise
    #
    # Usage:
    #     Called from _scan_worker() when "GreyNoise" is enabled.
    #     A "malicious" classification adds +10 to the threat score;
    #     "benign" subtracts -5 as a safety offset.
    if not api_key:
        # Community endpoint works without authentication but has lower rate limits
        url = f"https://api.greynoise.io/v3/community/{quote(ip)}"
        headers = {}
    else:
        url = f"https://api.greynoise.io/v3/community/{quote(ip)}"
        headers = {"key": api_key}
    data = _api_get(url, headers)
    if not data:
        return {"_error": "empty response"}
    # GreyNoise community API returns HTTP 404 for IPs not in their dataset.
    # This is NOT an error — it means GreyNoise successfully checked but has
    # no observations. We treat this as a valid "unknown" classification so
    # the scanned flag gets set (we did query successfully).
    if "_error" in data:
        status = data.get("_status", 0)
        if status == 404:
            # IP not observed scanning — valid result, classify as unknown
            return {
                "noise": False,
                "riot": False,
                "classification": "unknown",
                "name": "",
                "message": "IP not observed by GreyNoise",
            }
        # Any other HTTP error (429 rate limit, 403 forbidden, etc.) is a real error
        return data
    # Check for error message in a 200 response body
    if data.get("error"):
        return {"_error": f"GreyNoise: {data['error']}"}
    return {
        "noise": data.get("noise", False),
        "riot": data.get("riot", False),
        "classification": data.get("classification", "unknown"),
        "name": data.get("name", ""),
        "message": data.get("message", ""),
    }


def query_otx(ip):
    # Query AlienVault OTX (Open Threat Exchange) for threat intelligence pulses.
    #
    # OTX is a free, community-driven threat intelligence platform. "Pulses"
    # are curated collections of indicators (IPs, domains, hashes) associated
    # with specific threat campaigns or malware families.
    #
    # Inputs:
    #     ip (str): IPv4 address to check.
    #     (No API key required – the OTX public API is free and open.)
    #
    # Returns:
    #     dict with keys:
    #         pulse_count (int): Number of OTX pulses referencing this IP
    #         reputation  (int): OTX reputation score
    #         country     (str): Country name from OTX's geo data
    #         asn         (str): ASN string
    #
    # Usage:
    #     Called from _scan_worker() when "AlienVault OTX" is enabled.
    #     Each OTX pulse adds +2 to the threat score, capped at 10 total.
    #     A high pulse count indicates the IP appears in multiple known
    #     threat campaigns.
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{quote(ip)}/general"
    data = _api_get(url)
    if not data or "_error" in data:
        return data or {"_error": "empty"}
    # OTX returns {"error": "..."} for some invalid requests
    if data.get("error"):
        return {"_error": f"OTX: {data['error']}"}
    # Validate that pulse_info exists (expected in all valid responses)
    if "pulse_info" not in data and "indicator" not in data:
        return {"_error": f"OTX unexpected response: {str(data)[:200]}"}
    return {
        "pulse_count": data.get("pulse_info", {}).get("count", 0),
        "reputation": data.get("reputation", 0),
        "country": data.get("country_name", ""),
        "asn": data.get("asn", ""),
    }


def query_proxycheck(ip, api_key):
    # Query the proxycheck.io V3 API for proxy/VPN/Tor detection and risk data.
    #
    # ProxyCheck specialises in detecting anonymising services: proxies, VPNs,
    # Tor exit nodes, scrapers, and hosting/datacenter IPs. The V3 API returns
    # a structured response with nested categories for network, location,
    # detections, detection history, attack history, and operator information.
    #
    # Inputs:
    #     ip      (str): IPv4 address to check.
    #     api_key (str): ProxyCheck API key. If empty, returns _skipped.
    #
    # Returns:
    #     dict with keys:
    #         anonymous   (bool):  True if any anonymising service detected
    #         proxy       (bool):  True if operating as a proxy
    #         vpn         (bool):  True if operating as a VPN
    #         tor         (bool):  True if Tor exit node
    #         hosting     (bool):  True if datacenter/hosting IP
    #         scraper     (bool):  True if known scraper
    #         risk        (int):   0-100 risk score from ProxyCheck
    #         confidence  (int):   0-100 detection confidence
    #         type_str    (str):   Comma-separated detected types (e.g. "vpn, hosting")
    #         operator    (dict):  Operator info if available (name, services, etc.)
    #         attack_history (dict): Attack history if available
    #         first_seen  (str):   ISO 8601 first detection timestamp or ""
    #         last_seen   (str):   ISO 8601 last detection timestamp or ""
    #
    # Auth:
    #     API key passed as query parameter: ?key={api_key}
    #     Free tier: 1,000 queries/day with key (100/day without)
    #
    # Rate limits:
    #     Unregistered: 100/day
    #     Free with key: 1,000/day
    #     Paid: 10,000+ /day
    #     Burst: 700-1050 requests/second depending on region
    #
    # V3 API endpoint:
    #     https://proxycheck.io/v3/{ip}?key={api_key}
    #
    # V3 response structure (nested under the IP address key):
    #     { "status": "ok", "{ip}": {
    #         "network": { asn, isp, organisation, network_type, ... },
    #         "location": { country, country_code, city, ... },
    #         "detections": { anonymous, proxy, vpn, tor, hosting, scraper,
    #                         risk, confidence, first_seen, last_seen },
    #         "detection_history": { ... },
    #         "attack_history": { ... },
    #         "operator": { name, services, additional_operators } | null
    #     }}
    #
    # Usage:
    #     Called from _scan_worker() when "ProxyCheck" is enabled.
    #     Results are stored for context; scoring impact is minor
    #     (up to +5 points for proxy/VPN/Tor/scraper detection).
    if not api_key:
        return {"_skipped": True}
    url = f"https://proxycheck.io/v3/{quote(ip)}?key={quote(api_key)}"
    data = _api_get(url)
    if not data or "_error" in data:
        return data or {"_error": "empty"}
    # V3 uses proper HTTP status codes; check for error status in body
    status = data.get("status", "")
    if status in ("denied", "refused", "error"):
        msg = data.get("message", status)
        return {"_error": f"ProxyCheck: {msg}"}
    # V3 nests the result under the IP address as key
    ip_data = data.get(ip, {})
    if not ip_data or not isinstance(ip_data, dict):
        return {"_error": f"ProxyCheck: no data for {ip} in response"}
    # Extract nested categories
    detections = ip_data.get("detections", {})
    operator = ip_data.get("operator", None)
    attack_hist = ip_data.get("attack_history", {})
    # Build the type string from detected flags
    detected_types = []
    for dtype in ["proxy", "vpn", "tor", "hosting", "scraper"]:
        if detections.get(dtype) is True:
            detected_types.append(dtype)
    return {
        "anonymous": detections.get("anonymous", False),
        "proxy": detections.get("proxy", False),
        "vpn": detections.get("vpn", False),
        "tor": detections.get("tor", False),
        "hosting": detections.get("hosting", False),
        "scraper": detections.get("scraper", False),
        "risk": detections.get("risk", 0),
        "confidence": detections.get("confidence", 0),
        "type_str": ", ".join(detected_types) if detected_types else "none",
        "first_seen": detections.get("first_seen", "") or "",
        "last_seen": detections.get("last_seen", "") or "",
        "operator": operator if isinstance(operator, dict) else {},
        "attack_history": attack_hist if isinstance(attack_hist, dict) else {},
    }


def query_ipinfo(ip, api_key=""):
    # Query IPInfo.io for geolocation and organisation data.
    #
    # IPInfo provides city-level geolocation, ASN ownership, and
    # hostname information. Useful as a secondary geo source to
    # cross-reference against ip-api.com and AbuseIPDB.
    #
    # Inputs:
    #     ip      (str): IPv4 address to look up.
    #     api_key (str): IPInfo API token (optional). Free tier allows
    #                    50,000 requests/month without a token.
    #
    # Returns:
    #     dict with keys:
    #         city     (str): City name
    #         region   (str): State/province/region
    #         country  (str): ISO country code
    #         org      (str): Organisation / ASN owner
    #         hostname (str): Reverse DNS hostname
    #
    # Usage:
    #     Called from _scan_worker() when "IPInfo" is enabled.
    #     Data is stored in the ipinfo_data column as a JSON blob and
    #     also used to backfill city/country if not already populated.
    url = f"https://ipinfo.io/{quote(ip)}/json"
    if api_key:
        url += f"?token={api_key}"
    data = _api_get(url)
    if not data or "_error" in data:
        return data or {"_error": "empty"}
    # IPInfo returns {"error": "..."} for rate limits or invalid tokens
    if data.get("error"):
        return {"_error": f"IPInfo: {data['error']}"}
    return {
        "city": data.get("city", ""),
        "region": data.get("region", ""),
        "country": data.get("country", ""),
        "org": data.get("org", ""),
        "hostname": data.get("hostname", ""),
    }


def query_ipapi_free(ip):
    # Query ip-api.com for free geolocation, ISP, and proxy detection.
    #
    # This is a free API with no authentication required, but it has a
    # strict rate limit of 45 requests per minute. The scan worker
    # enforces a minimum 1.4-second delay after each call.
    #
    # Inputs:
    #     ip (str): IPv4 address to look up.
    #
    # Returns:
    #     dict – Raw JSON response from ip-api.com containing:
    #         status      (str):  "success" or "fail"
    #         country     (str):  Full country name
    #         countryCode (str):  ISO 3166-1 alpha-2 code
    #         city        (str):  City name
    #         isp         (str):  ISP name
    #         org         (str):  Organisation name
    #         as          (str):  ASN and owner (e.g. "AS13335 Cloudflare, Inc.")
    #         reverse     (str):  Reverse DNS hostname
    #         hosting     (bool): True if IP belongs to a hosting/data center
    #         proxy       (bool): True if IP is a known proxy/VPN/Tor exit
    #
    # Usage:
    #     Called from _scan_worker() when "ip-api (free)" is enabled.
    #     Provides baseline geolocation and ISP data. The hosting/proxy
    #     flags are useful additional context for threat assessment.
    url = f"http://ip-api.com/json/{quote(ip)}?fields=status,message,country,countryCode,city,isp,org,as,reverse,hosting,proxy"
    data = _api_get(url)
    if not data or "_error" in data:
        return data or {"_error": "empty"}
    # CRITICAL: ip-api.com returns HTTP 200 with {"status": "fail"} when
    # rate limited (45 req/min exceeded), or for invalid/reserved IPs.
    # Without this check, we'd store empty geo data and mark as scanned.
    if data.get("status") == "fail":
        msg = data.get("message", "unknown failure")
        return {"_error": f"ip-api: {msg}"}
    return data


def query_reverse_dns(ip):
    # Perform a DNS reverse lookup (PTR record) for the given IP address.
    #
    # Reverse DNS maps an IP back to a hostname, which can reveal the
    # hosting provider, device type, or organisation. For example,
    # "scan-42.shadowserver.org" immediately identifies the scanner.
    #
    # Inputs:
    #     ip (str): IPv4 address to resolve.
    #
    # Returns:
    #     dict with keys:
    #         reverse_dns (str):  The resolved hostname, or empty string
    #                             if no PTR record exists.
    #         _success    (bool): True if the lookup completed (even with
    #                             no result). False if it timed out or
    #                             encountered a network error.
    #
    # Behaviour:
    #     - First tries socket.getfqdn() for a fully-qualified domain name.
    #     - Falls back to socket.gethostbyaddr() if getfqdn returns the
    #       raw IP (meaning no FQDN was found).
    #     - On socket.herror (no PTR record): returns success=True with
    #       empty hostname — the lookup worked, there's just no record.
    #     - On socket.timeout or other exceptions: returns _error to
    #       indicate the lookup failed (should not mark as scanned).
    #
    # Usage:
    #     Called from _scan_worker() when "DNS Reverse Lookup" is enabled.
    #     This is a local network call (to the system's configured DNS
    #     resolver) and does not hit any external API, so no rate limiting
    #     or API key is needed.
    try:
        host = socket.getfqdn(ip)       # Try FQDN resolution first
        if host == ip:
            # getfqdn returned the raw IP – fall back to gethostbyaddr
            host, _, _ = socket.gethostbyaddr(ip)
        return {"reverse_dns": host, "_success": True}
    except socket.herror:
        # herror = "host not found" — no PTR record exists
        # This is a valid completed lookup, just with no result
        return {"reverse_dns": "", "_success": True}
    except socket.gaierror:
        # gaierror = address-related error — also means no PTR
        return {"reverse_dns": "", "_success": True}
    except socket.timeout:
        # DNS resolver timed out — genuine failure, should retry later
        return {"reverse_dns": "", "_error": "DNS lookup timed out"}
    except Exception as exc:
        # Other unexpected errors (network down, etc.)
        return {"reverse_dns": "", "_error": f"DNS error: {str(exc)}"}


# ─────────────────────────────────────────────────────────────────
# Rate-limit detection
# ─────────────────────────────────────────────────────────────────

# Number of consecutive rate-limit errors per platform before auto-stop
RATE_LIMIT_THRESHOLD = 5

def _is_rate_limit_error(result):
    # Determine if an API response indicates a rate-limit / quota error.
    #
    # Inputs:
    #     result (dict): The return value from a query_* function.
    #
    # Returns:
    #     bool: True if the response indicates the API quota was exceeded.
    #
    # Detection logic (platform-specific patterns):
    #     - HTTP 429 (Too Many Requests) — universal rate-limit indicator
    #     - VirusTotal: returns {"error":{"code":"QuotaExceededError"}} (sometimes HTTP 200)
    #     - ProxyCheck V3: returns {"status":"denied"} or {"status":"refused"} in body
    #     - ip-api.com: returns HTTP 200 + {"status":"fail"} for rate limits
    #
    # Non-rate-limit errors (network failures, auth errors, malformed responses)
    # return False so they don't count toward the auto-stop threshold.
    if not result or result.get("_skipped"):
        return False
    error = result.get("_error", "")
    if not error:
        return False
    status = result.get("_status", 0)
    # Universal: HTTP 429 Too Many Requests
    if status == 429:
        return True
    # VirusTotal: QuotaExceededError in body (sometimes HTTP 200)
    if "QuotaExceeded" in error:
        return True
    # ProxyCheck V3: body status "denied" or "refused" indicates quota
    if "ProxyCheck" in error and ("denied" in error.lower() or "refused" in error.lower()):
        return True
    # ip-api.com: HTTP 200 + status "fail" — check for rate-limit message
    # (vs reserved/private IP errors which also produce "fail")
    if "ip-api" in error and "rate" in error.lower():
        return True
    return False
