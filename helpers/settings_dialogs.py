#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════╗
# ║              NetPyINT – Settings Dialogs                         ║
# ║    Modal dialogs for API key and scan behavior configuration     ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# Public surface (imported by netpyint_main.py):
#     show_api_settings(parent, config, log_fn)
#     show_scan_settings(parent, config, log_fn, refresh_fn, update_cc_fn)

import tkinter as tk
from tkinter import messagebox, ttk

from config import save_config


def show_api_settings(parent, config, log_fn):
    # Open a modal dialog for configuring OSINT platform API keys.
    # Modifies config["api_keys"] in-place and persists to disk on Save.
    win = tk.Toplevel(parent)
    win.title("API Key Configuration")
    win.geometry("520x420")
    win.configure(bg="#0f172a")
    win.transient(parent)
    win.grab_set()

    ttk.Label(win, text="API Keys", style="Title.TLabel").pack(
        anchor="w", padx=16, pady=(12, 8))
    ttk.Label(win, text="Keys are stored locally in netpyint_config.json").pack(
        anchor="w", padx=16, pady=(0, 10))

    entries = {}
    keys_info = [
        ("abuseipdb",  "AbuseIPDB"),
        ("virustotal", "VirusTotal"),
        ("shodan",     "Shodan"),
        ("greynoise",  "GreyNoise"),
        ("proxycheck", "ProxyCheck"),
        ("ipinfo",     "IPInfo"),
    ]
    for key, label in keys_info:
        frame = ttk.Frame(win)
        frame.pack(fill="x", padx=16, pady=3)
        ttk.Label(frame, text=f"{label}:", width=14, anchor="e").pack(side="left")
        e = ttk.Entry(frame, width=48)
        e.pack(side="left", padx=(8, 0), fill="x", expand=True)
        e.insert(0, config["api_keys"].get(key, ""))
        entries[key] = e

    def save():
        for key, entry in entries.items():
            config["api_keys"][key] = entry.get().strip()
        save_config(config)
        log_fn("API keys saved.")
        win.destroy()

    btn_frame = ttk.Frame(win)
    btn_frame.pack(fill="x", padx=16, pady=16)
    ttk.Button(btn_frame, text="Save", style="Accent.TButton",
               command=save).pack(side="right")
    ttk.Button(btn_frame, text="Cancel",
               command=win.destroy).pack(side="right", padx=(0, 8))


def show_scan_settings(parent, config, log_fn, refresh_fn, update_cc_fn,
                       restart_auto_scan_fn=None):
    # Open a modal dialog for configuring scan behavior parameters.
    # update_cc_fn(set_of_codes) is called after save to update the app's
    # cc_highlight set without this module needing to know about app state.
    # restart_auto_scan_fn() is called after save when the auto-scan interval changes.
    win = tk.Toplevel(parent)
    win.title("Scan Settings")
    win.geometry("420x470")
    win.configure(bg="#0f172a")
    win.transient(parent)
    win.grab_set()

    ttk.Label(win, text="Scan Configuration", style="Title.TLabel").pack(
        anchor="w", padx=16, pady=(12, 12))

    f1 = ttk.Frame(win)
    f1.pack(fill="x", padx=16, pady=4)
    ttk.Label(f1, text="Delay between API calls (ms):", width=30, anchor="e").pack(side="left")
    delay_var = tk.StringVar(value=str(config.get("scan_delay_ms", 1100)))
    ttk.Entry(f1, textvariable=delay_var, width=8).pack(side="left", padx=8)

    f2 = ttk.Frame(win)
    f2.pack(fill="x", padx=16, pady=4)
    ttk.Label(f2, text="AbuseIPDB max days:", width=30, anchor="e").pack(side="left")
    days_var = tk.StringVar(value=str(config.get("max_abuseipdb_days", 90)))
    ttk.Entry(f2, textvariable=days_var, width=8).pack(side="left", padx=8)

    f3 = ttk.Frame(win)
    f3.pack(fill="x", padx=16, pady=4)
    ttk.Label(f3, text="Scanning Threads (1–8):", width=30, anchor="e").pack(side="left")
    workers_var = tk.StringVar(value=str(config.get("parallel_workers", 1)))
    ttk.Spinbox(f3, from_=1, to=8, textvariable=workers_var,
                width=6).pack(side="left", padx=8)

    ttk.Label(win, text="  Note: rate limits are enforced globally across all Scanning workers.",
              font=("Segoe UI", 8), foreground="#64748b").pack(anchor="w", padx=16)

    f_auto = ttk.Frame(win)
    f_auto.pack(fill="x", padx=16, pady=4)
    ttk.Label(f_auto, text="Auto Scan Interval (hours):", width=30, anchor="e").pack(side="left")
    auto_interval_var = tk.StringVar(value=str(config.get("auto_scan_interval_hours", 1)))
    ttk.Spinbox(f_auto, from_=1, to=24, textvariable=auto_interval_var,
                width=6).pack(side="left", padx=8)

    post_delay_var = tk.BooleanVar(value=config.get("auto_scan_post_delay", False))
    ttk.Checkbutton(win, text="Add 5-min delay after scan completes (post-scan buffer)",
                    variable=post_delay_var).pack(anchor="w", padx=52, pady=(0, 4))

    ttk.Separator(win, orient="horizontal").pack(fill="x", padx=16, pady=(8, 0))
    ttk.Label(win, text="Country Code Highlight", style="Title.TLabel").pack(
        anchor="w", padx=16, pady=(8, 2))
    ttk.Label(win,
              text="Comma-separated codes whose CC column is highlighted (e.g. CN, RU, NL)",
              font=("Segoe UI", 8), foreground="#64748b").pack(anchor="w", padx=16)

    current_codes = ", ".join(config.get("cc_highlight_codes", []))
    cc_var = tk.StringVar(value=current_codes)
    f4 = ttk.Frame(win)
    f4.pack(fill="x", padx=16, pady=(4, 0))
    ttk.Entry(f4, textvariable=cc_var, width=36).pack(side="left")

    def save():
        # Validate all fields before touching config so a bad third field
        # doesn't leave the first two partially written.
        try:
            delay         = max(200, int(delay_var.get()))
            days          = max(1,   int(days_var.get()))
            workers       = max(1,   min(8, int(workers_var.get())))
            auto_interval = max(1,   min(24, int(auto_interval_var.get())))
        except ValueError:
            messagebox.showerror("Error",
                                 "Enter valid integers for delay, days, threads, "
                                 "and auto scan interval.")
            return
        config["scan_delay_ms"]            = delay
        config["max_abuseipdb_days"]       = days
        config["parallel_workers"]         = workers
        config["auto_scan_interval_hours"] = auto_interval
        config["auto_scan_post_delay"]     = post_delay_var.get()
        codes = [c.strip().upper() for c in cc_var.get().split(",") if c.strip()]
        config["cc_highlight_codes"] = codes
        update_cc_fn(set(codes))
        save_config(config)
        if restart_auto_scan_fn:
            restart_auto_scan_fn()
        refresh_fn()
        log_fn(f"Scan settings saved.  Auto scan interval: {auto_interval}h. "
               f"CC highlight: {', '.join(codes) or '(none)'}")
        win.destroy()

    btn_frame = ttk.Frame(win)
    btn_frame.pack(fill="x", padx=16, pady=16)
    ttk.Button(btn_frame, text="Save", style="Accent.TButton",
               command=save).pack(side="right")
    ttk.Button(btn_frame, text="Cancel",
               command=win.destroy).pack(side="right", padx=(0, 8))
