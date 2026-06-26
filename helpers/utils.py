#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════╗
# ║              NetPyINT – Shared Utilities                         ║
# ║    Small primitives shared across multiple helper modules        ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# Public surface (imported by scoring.py, log_parser.py, data_insights.py):
#     parse_json_list(value) → list
#     parse_ctime(s)         → datetime | None

import json
from datetime import datetime

_CTIME_FMT = "%a %b %d %H:%M:%S %Y"


def parse_json_list(value):
    # Safely decode a JSON array string into a Python list.
    # Returns [] on any parse failure, empty input, or non-array JSON.
    if not value:
        return []
    try:
        result = json.loads(value)
        return result if isinstance(result, list) else []
    except (json.JSONDecodeError, TypeError, ValueError):
        return []


def parse_ctime(s):
    # Parse a ctime-format timestamp string into a datetime object.
    # Handles both "Thu Apr  9 02:49:54 2026" (single-digit day) and
    # "Thu Apr 09 02:49:54 2026" forms via %d.
    # Returns None on any parse failure or empty/None input.
    if not s:
        return None
    try:
        return datetime.strptime(s.strip(), _CTIME_FMT)
    except (ValueError, TypeError, AttributeError):
        return None
