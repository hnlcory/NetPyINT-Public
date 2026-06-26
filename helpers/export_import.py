#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════╗
# ║              NetPyINT – Export / Import                          ║
# ║    Blocklist export, JSON report export/import, DB clear         ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# All functions are UI-level only: they open Tkinter file dialogs or
# confirmation dialogs, perform I/O, then call the provided callbacks
# to update the UI.  No DB schema knowledge lives here — queries go
# through the IPRepository methods.
#
# Public surface (imported by netpyint_main.py):
#     export_blocklist(parent, repo, log_fn)
#     export_json(parent, repo, log_fn)
#     import_json(parent, repo, log_fn, refresh_fn, recalc_fn)
#     clear_database(parent, repo, log_fn, refresh_fn)

import json
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from datetime import date

from config import THREAT_COLORS


def export_blocklist(parent, repo, log_fn, cc_highlight=None):
    # Open a severity selection dialog, then export matching IPs as a blocklist.
    dialog = tk.Toplevel(parent)
    dialog.title("Export Blocklist – Select Severity Levels")
    dialog.geometry("420x480")
    dialog.configure(bg="#0f172a")
    dialog.transient(parent)
    dialog.grab_set()

    ttk.Label(dialog, text="Select Threat Levels to Export",
              style="Title.TLabel").pack(anchor="w", padx=16, pady=(12, 4))
    ttk.Label(dialog, text="Check the severity levels to include in the blocklist."
              ).pack(anchor="w", padx=16, pady=(0, 10))

    levels_config = [
        ("Critical",  True),
        ("High",      True),
        ("Medium",    True),
        ("Low",       False),
        ("Optional",  False),
        ("Partial",   False),
        ("No Threat", False),
        ("Pending",   False),
    ]

    level_vars = {}
    check_frame = ttk.Frame(dialog)
    check_frame.pack(fill="x", padx=16, pady=(0, 6))

    # Country: Highlighted section
    ttk.Separator(dialog, orient="horizontal").pack(fill="x", padx=16, pady=(4, 8))
    ttk.Label(dialog, text="Country Filter").pack(anchor="w", padx=16, pady=(0, 4))

    highlight_var = tk.BooleanVar(value=False)
    cc_codes = cc_highlight if cc_highlight else set()
    if cc_codes:
        cc_count = repo.count_ips_by_countries(cc_codes)
        hl_btn = ttk.Checkbutton(dialog,
                                 text=f"Country: Highlighted  ({cc_count} IPs)",
                                 variable=highlight_var)
        hl_btn.pack(anchor="w", padx=16, pady=(0, 2))
    else:
        hl_btn = ttk.Checkbutton(dialog,
                                 text="Country: Highlighted  (no highlight codes configured)",
                                 variable=highlight_var, state="disabled")
        hl_btn.pack(anchor="w", padx=16, pady=(0, 2))

    count_label = ttk.Label(dialog, text="", foreground="#38bdf8")
    count_label.pack(anchor="w", padx=16, pady=(4, 6))

    def update_count(*_args):
        selected_levels = [lv for lv, var in level_vars.items() if var.get()]
        use_highlight = highlight_var.get() and bool(cc_codes)
        if not selected_levels and not use_highlight:
            count_label.config(text="No levels selected (0 IPs)")
            return
        parts = []
        if selected_levels:
            n = repo.count_ips_by_levels(selected_levels)
            parts.append(f"{n} severity IPs")
        if use_highlight:
            n = repo.count_ips_by_countries(cc_codes)
            parts.append(f"{n} highlighted-country IPs")
        if len(parts) == 2:
            parts.append("duplicates removed on export")
        count_label.config(text=" + ".join(parts))

    for level_name, default_on in levels_config:
        var = tk.BooleanVar(value=default_on)
        var.trace_add("write", update_count)
        n = repo.count_ips_by_level(level_name)
        ttk.Checkbutton(check_frame, text=f"{level_name}  ({n} IPs)",
                        variable=var).pack(anchor="w", pady=2)
        level_vars[level_name] = var

    highlight_var.trace_add("write", update_count)
    update_count()

    sel_frame = ttk.Frame(dialog)
    sel_frame.pack(fill="x", padx=16, pady=(0, 10))
    ttk.Button(sel_frame, text="Select All",
               command=lambda: [v.set(True) for v in level_vars.values()]
               ).pack(side="left", padx=(0, 8))
    ttk.Button(sel_frame, text="Deselect All",
               command=lambda: [v.set(False) for v in level_vars.values()]
               ).pack(side="left")

    btn_frame = ttk.Frame(dialog)
    btn_frame.pack(fill="x", padx=16, pady=(10, 16))

    def on_ok():
        selected_levels = [lv for lv, var in level_vars.items() if var.get()]
        use_highlight = highlight_var.get() and bool(cc_codes)
        if not selected_levels and not use_highlight:
            messagebox.showwarning("Nothing selected",
                                   "Check at least one threat level or enable "
                                   "Country: Highlighted to export.",
                                   parent=dialog)
            return

        severity_rows = repo.get_ips_by_levels(selected_levels) if selected_levels else []
        country_rows = repo.get_ips_by_countries(cc_codes) if use_highlight else []

        # Deduplicate: severity labels take precedence; highlighted-only IPs appended after.
        seen: dict = {}
        for ip, level in severity_rows:
            seen[ip] = level
        country_only = 0
        for ip, country in country_rows:
            if ip not in seen:
                seen[ip] = f"Country: Highlighted ({country})"
                country_only += 1

        if not seen:
            messagebox.showinfo("Empty",
                                "No IPs match the selected filters.",
                                parent=dialog)
            return

        today = date.today().strftime("%Y-%m-%d")
        path = filedialog.asksaveasfilename(
            title="Save Blocklist",
            initialfile=f"blocklist_{today}.txt",
            filetypes=[("Text files", "*.txt"), ("All", "*.*")])
        if not path:
            return
        dialog.destroy()

        all_rows = list(seen.items())
        levels_str = ", ".join(selected_levels) if selected_levels else ""
        header_parts = []
        if levels_str:
            header_parts.append(f"Threat levels: {levels_str}")
        if use_highlight:
            header_parts.append(f"Country: Highlighted ({', '.join(sorted(cc_codes))})")

        with open(path, "w") as f:
            f.write(f"# NetPyINT Blocklist  –  Generated {today}\n")
            f.write(f"# Total entries: {len(all_rows)}\n")
            for part in header_parts:
                f.write(f"# {part}\n")
            f.write("\n")
            for ip, label in all_rows:
                f.write(f"{ip}  # {label}\n")

        log_parts = [f"{len(all_rows)} IPs"]
        if levels_str:
            log_parts.append(f"levels: {levels_str}")
        if use_highlight:
            log_parts.append(f"{country_only} highlighted-country only")
        log_fn(f"Blocklist exported: {path}  ({', '.join(log_parts)})")
        messagebox.showinfo("Exported", f"Saved {len(all_rows)} IPs to:\n{path}")

    ttk.Button(btn_frame, text="Export", style="Accent.TButton",
               command=on_ok).pack(side="right")
    ttk.Button(btn_frame, text="Cancel",
               command=dialog.destroy).pack(side="right", padx=(0, 8))


def export_json(parent, repo, log_fn):
    # Export the full IP database as a JSON file for external analysis.
    records = repo.get_all_for_export()
    today = date.today().strftime("%Y-%m-%d")
    path = filedialog.asksaveasfilename(
        title="Save Full Report",
        initialfile=f"netpyint_report_{today}.json",
        filetypes=[("JSON", "*.json"), ("All", "*.*")])
    if not path:
        return
    with open(path, "w") as f:
        json.dump(records, f, indent=2, default=str)
    log_fn(f"JSON report exported: {path}")


def import_json(parent, repo, log_fn, refresh_fn, recalc_fn):
    # Import IP records from a previously exported JSON report.
    path = filedialog.askopenfilename(
        title="Import Full Report (JSON)",
        filetypes=[("JSON", "*.json"), ("All", "*.*")])
    if not path:
        return
    try:
        with open(path, "r") as f:
            records = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        messagebox.showerror("Import Error", f"Could not read JSON file:\n{exc}")
        return
    if not isinstance(records, list):
        messagebox.showerror("Import Error",
                             "File does not contain a JSON array of records.")
        return
    existing_cols = repo.get_column_set()
    imported = 0
    skipped = 0
    for rec in records:
        if not isinstance(rec, dict):
            skipped += 1
            continue
        ip = rec.get("ip")
        if not ip:
            skipped += 1
            continue
        filtered = {k: v for k, v in rec.items() if k in existing_cols}
        if not filtered:
            skipped += 1
            continue
        repo.upsert_record(filtered)
        imported += 1
    repo.commit()
    refresh_fn()
    recalc_fn()
    msg = f"Imported {imported} record(s) from {path}"
    if skipped:
        msg += f" ({skipped} skipped – missing 'ip' or invalid)"
    log_fn(msg)
    messagebox.showinfo("Import Complete", msg)


def clear_database(parent, repo, log_fn, refresh_fn):
    # Delete all IP records and scan history after user confirmation.
    if messagebox.askyesno("Confirm", "Delete ALL IP records and scan history?"):
        repo.clear_all()
        repo.commit()
        refresh_fn()
        log_fn("Database cleared.")
