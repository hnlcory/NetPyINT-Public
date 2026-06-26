#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════╗
# ║              NetPyINT – Display Formatting Helpers               ║
# ║    Pure data-to-string converters for Treeview row display       ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# All functions are pure (no UI or DB dependencies) so they are
# independently testable and reusable by any display path.
#
# Public surface (imported by netpyint_main.py):
#     format_date(val)                             → str  (Treeview compact form)
#     format_detail_date(val)                      → str  (IP Details full form)
#     get_threat_tag(threat, colors)               → str
#     format_score_cols(abuse, vt, otx, pc_risk)   → (str, str, str, str)
#     parse_idb_tags(raw)                          → str
#     format_country(cc, cc_highlight)             → (str, bool)

from datetime import datetime

from utils import parse_json_list


def format_date(val):
    # Format a stored timestamp for compact Treeview column display.
    # Accepts ctime ("Mon Mar 23 13:16:46 2026"), ISO datetime, or ISO date.
    # Returns "–" for empty/None; raw val if no format matches.
    if not val or not val.strip():
        return "–"
    for fmt in ("%a %b %d %H:%M:%S %Y", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(val.strip(), fmt)
            return f"{dt.strftime('%a %b')} {dt.day} {dt.strftime('%y')}'"
        except ValueError:
            continue
    return val


def format_detail_date(val):
    # Format a stored timestamp for IP Details panel display.
    # Target: "Tue May 5 18:32 2026" — weekday abbrev, month abbrev,
    # un-padded day, HH:MM (no seconds), 4-digit year.
    # Returns "–" for empty/None; raw val if nothing parses.
    if not val or not val.strip():
        return "–"
    for fmt in (
        "%a %b %d %H:%M:%S %Y",   # ctime:       Mon Mar 23 13:16:46 2026
        "%Y-%m-%dT%H:%M:%S.%f",   # ISO + µs:    2026-06-09T14:32:15.123456
        "%Y-%m-%dT%H:%M:%S",      # ISO:         2026-06-09T14:32:15
        "%Y-%m-%dT%H:%M",         # ISO no-sec:  2026-06-09T14:32
        "%Y-%m-%d",               # date only:   2026-06-09
    ):
        try:
            dt = datetime.strptime(val.strip(), fmt)
            if fmt == "%Y-%m-%d":
                return f"{dt.strftime('%a %b')} {dt.day} {dt.strftime('%Y')}"
            return f"{dt.strftime('%a %b')} {dt.day} {dt.strftime('%H:%M %Y')}"
        except ValueError:
            continue
    return val


def get_threat_tag(threat, threat_colors):
    # Return the Treeview tag name for a threat level string.
    # Falls back to "Pending" if threat isn't a known colour key, guarding
    # against unexpected values stored in older DB rows.
    return threat if threat in threat_colors else "Pending"


def format_score_cols(abuse, vt, otx, pc_risk):
    # Format per-platform score values for Treeview display.
    # Converts -1 sentinel (never queried) to "–" em-dash.
    # Returns a 4-tuple of display strings: (abuse_s, vt_s, otx_s, pc_risk_s).
    abuse_s = f"{abuse:.0f}" if abuse >= 0 else "–"
    vt_s = f"{vt:.0f}" if vt >= 0 else "–"
    otx_s = str(otx) if otx >= 0 else "–"
    pc_risk_s = str(pc_risk) if pc_risk is not None and pc_risk >= 0 else "–"
    return abuse_s, vt_s, otx_s, pc_risk_s


def parse_idb_tags(raw):
    # Parse an InternetDB tags JSON array string into a comma-separated display string.
    # Returns "–" for empty/None/unparseable input.
    tags = parse_json_list(raw)
    return ", ".join(tags) if tags else "–"


def format_country(cc, cc_highlight):
    # Format a country code for Treeview display, appending ★ when the code
    # appears in the user's watchlist set.
    # Returns (display_string, is_highlighted) so the caller can apply cc_hl tag.
    cc_code = (cc or "").upper()
    highlighted = bool(cc_code and cc_code in cc_highlight)
    display = f"{cc}★" if highlighted else (cc or "–")
    return display, highlighted
