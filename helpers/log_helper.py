#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════╗
# ║              Log Helper                                          ║
# ║    Firewall log cleaner and blocklist processor                  ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# A two-tab utility for cleaning firewall logs and blocklists.
#
# Tab 1 — WAN Logs:
#     1. Browse for a .txt log file  —OR—  paste logs directly.
#     2. Filter out any lines that don't contain "banIP" or "reject wan".
#     3. Replace every occurrence of a configurable public IP with
#        "xxx.xxx.xx.xx (PrivNetwork)".
#     4. Save the cleaned file as  wanRejectsMMDDYYYY.txt .
#
# Tab 2 — Blocklist Logs:
#     1. Browse for a .txt blocklist file.
#     2. Keep only lines that start with a digit (assumed IPs).
#     3. Save the result as  banip.blocklist  in the same directory.
#     4. Display removed lines for sanity-checking.
#
# Settings (last-used IP, date filter state) are stored in
# netpyint_config.json under the "log_helper" key.

import json
import os
import re
import tkinter as tk
from tkinter import filedialog
from datetime import datetime
from pathlib import Path

from config import _config_write_lock, _CONFIG_LOCK_FILE

# ─────────────────────────────────────────────────────────────────
# Config persistence  (backed by netpyint_config.json → "log_helper" section)
# ─────────────────────────────────────────────────────────────────
_NETPYINT_CONFIG  = Path(__file__).parent.parent / "netpyint_config.json"
_LOG_HELPER_KEY   = "log_helper"
DEFAULT_IP        = "70.200.30.10"



def _load_netpyint() -> dict:
    try:
        with open(_NETPYINT_CONFIG, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def load_config() -> dict:
    return _load_netpyint().get(_LOG_HELPER_KEY, {"last_ip": DEFAULT_IP})


def save_config(cfg: dict) -> None:
    with _config_write_lock(lock_path=_CONFIG_LOCK_FILE):
        full = _load_netpyint()
        full[_LOG_HELPER_KEY] = cfg
        tmp = _NETPYINT_CONFIG.with_suffix(".tmp")
        tmp.write_text(json.dumps(full, indent=2), encoding="utf-8")
        tmp.replace(_NETPYINT_CONFIG)


def update_config(**kwargs) -> None:
    # Load existing config, merge in new keys, and save.
    cfg = load_config()
    cfg.update(kwargs)
    save_config(cfg)


# ─────────────────────────────────────────────────────────────────
# Core processing — WAN Logs  (operates on raw text)
# ─────────────────────────────────────────────────────────────────
REPLACEMENT     = "xxx.xxx.xx.xx (PrivNetwork)"
MAC_RE          = re.compile(r'MAC=[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2})+')
MAC_REPLACEMENT = "MAC=xx:xx:xx:xx (Redacted)"

# Date pattern for log lines: "Mon Mar 23 00:10:24 2026"
LOG_DATE_RE = re.compile(
    r'^[A-Za-z]{3}\s+'
    r'([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})'
)
LOG_DATE_FMT = "%b %d %H:%M:%S %Y"


def parse_log_date(line: str):
    # Extract datetime from the start of a log line, or None.
    m = LOG_DATE_RE.match(line.strip())
    if m:
        try:
            return datetime.strptime(m.group(1), LOG_DATE_FMT)
        except ValueError:
            return None
    return None


def process_wan_text(text: str, target_ip: str, cutoff_dt=None):
    # Filter and sanitise raw WAN log text.
    #
    # Inputs:
    #     text      (str):           Raw log text (file contents or pasted input).
    #     target_ip (str):           Public IP address to replace with REPLACEMENT.
    #     cutoff_dt (datetime|None): If set, lines at or before this time are skipped.
    #
    # Returns:
    #     tuple – (cleaned_text, ip_count, num_removed, num_kept,
    #              removed_lines, date_filtered_lines, changed, latest_dt, mac_count)
    #
    # Raises:
    #     RuntimeError – if no matching lines remain after filtering.
    raw_lines = text.splitlines()
    kept_lines = []
    removed_lines = []
    for line in raw_lines:
        if line.strip() and ("banIP" in line or "reject wan" in line):
            kept_lines.append(line)
        else:
            removed_lines.append(line)

    if not kept_lines:
        raise RuntimeError(
            'No lines containing "banIP" or "reject wan" were found.'
        )

    # Date filtering: remove lines at or before the cutoff
    date_filtered_lines = []
    if cutoff_dt:
        new_kept = []
        for line in kept_lines:
            line_dt = parse_log_date(line)
            if line_dt and line_dt <= cutoff_dt:
                date_filtered_lines.append(line)
            else:
                new_kept.append(line)
        kept_lines = new_kept

    if not kept_lines:
        raise RuntimeError(
            "All matching lines were already processed "
            "(filtered by date) — no new logs to save."
        )

    # Find latest date among final kept lines
    latest_dt = None
    for line in kept_lines:
        line_dt = parse_log_date(line)
        if line_dt and (latest_dt is None or line_dt > latest_dt):
            latest_dt = line_dt

    filtered_text = "\n".join(kept_lines) + "\n"

    pattern = re.escape(target_ip)
    new_text, count = re.subn(pattern, REPLACEMENT, filtered_text)
    new_text, mac_count = MAC_RE.subn(MAC_REPLACEMENT, new_text)

    meaningful_removed = [ln for ln in removed_lines if ln.strip()]
    changed = bool(meaningful_removed) or bool(date_filtered_lines) or count > 0 or mac_count > 0

    return (new_text, count, len(removed_lines), len(kept_lines),
            removed_lines, date_filtered_lines, changed, latest_dt, mac_count)


# ─────────────────────────────────────────────────────────────────
# Shared styling constants
# ─────────────────────────────────────────────────────────────────
BG       = "#0f172a"   # dark navy – main background
FG       = "#e2e8f0"   # light grey – primary text
ACCENT   = "#38bdf8"   # sky blue  – accent highlights
ENTRY_BG = "#1e293b"   # input field / panel background
BTN_BG   = "#334155"   # button background
BTN_FG   = "#e2e8f0"   # button text
FONT     = ("Segoe UI", 10)
FONT_SM  = ("Segoe UI", 9)
FONT_MON = ("Consolas", 10)

TAB_ACTIVE_BG   = BG          # active tab blends with panel background
TAB_INACTIVE_BG = "#0a111e"   # slightly darker than the panel
TAB_ACTIVE_FG   = ACCENT
TAB_INACTIVE_FG = "#475569"


# ─────────────────────────────────────────────────────────────────
# UI helpers
# ─────────────────────────────────────────────────────────────────
def _build_log_viewer(parent):
    # Build a scrollable "removed-lines" text viewer inside *parent*.
    # Returns (removed_label, log_frame, log_text).
    removed_label = tk.Label(
        parent, text="Lines removed (sanity check):", font=FONT_SM,
        bg=BG, fg="#94a3b8", anchor="w"
    )

    log_frame = tk.Frame(parent, bg=BG)

    log_text = tk.Text(
        log_frame, font=FONT_MON, wrap="none",
        bg="#0a111e", fg="#94a3b8", relief="flat",
        insertbackground=FG, highlightthickness=1,
        highlightbackground="#334155", highlightcolor=ACCENT,
        state="disabled"
    )
    y_scroll = tk.Scrollbar(
        log_frame, orient="vertical", command=log_text.yview
    )
    x_scroll = tk.Scrollbar(
        log_frame, orient="horizontal", command=log_text.xview
    )
    log_text.configure(
        yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set
    )
    log_text.grid(row=0, column=0, sticky="nsew")
    y_scroll.grid(row=0, column=1, sticky="ns")
    x_scroll.grid(row=1, column=0, sticky="ew")
    log_frame.rowconfigure(0, weight=1)
    log_frame.columnconfigure(0, weight=1)

    return removed_label, log_frame, log_text


def _show_status(status_var, status_label, msg, error=False, warn=False):
    status_var.set(msg)
    if warn:
        color = "#f59e0b"
    elif error:
        color = "#f87171"
    else:
        color = "#22c55e"
    status_label.config(fg=color)


def _clear_log(removed_label, log_frame, log_text):
    removed_label.pack_forget()
    log_frame.pack_forget()
    log_text.config(state="normal")
    log_text.delete("1.0", "end")
    log_text.config(state="disabled")


def _show_removed_lines(removed_label, log_frame, log_text, lines,
                       numbered=False):
    if not lines:
        _clear_log(removed_label, log_frame, log_text)
        return

    removed_label.pack(fill="x", padx=16, pady=(4, 2))
    log_frame.pack(fill="both", expand=True, padx=16, pady=(0, 12))

    if numbered:
        display = []
        for i, ln in enumerate(lines, 1):
            display.append(
                f"{i:>4}:  {ln}" if ln.strip() else f"{i:>4}:  (blank)"
            )
        content = "\n".join(display)
    else:
        display = [ln if ln.strip() else "(blank)" for ln in lines]
        content = "\n".join(display)

    log_text.config(state="normal")
    log_text.delete("1.0", "end")
    log_text.insert("1.0", content)
    log_text.config(state="disabled")


# ─────────────────────────────────────────────────────────────────
# GUI
# ─────────────────────────────────────────────────────────────────
class App(tk.Tk):

    H_COMPACT  = 420
    H_EXPANDED = 600

    def __init__(self):
        super().__init__()
        self.title("Log Helper")
        self.configure(bg=BG)
        self.minsize(540, self.H_COMPACT)

        cfg = load_config()

        # ── Tab bar ──────────────────────────────────────────────
        tab_bar = tk.Frame(self, bg=TAB_INACTIVE_BG)
        tab_bar.pack(fill="x")

        self._tab_buttons = []
        self._panels = []

        for idx, label in enumerate(("WAN Logs", "Blocklist Logs")):
            btn = tk.Label(
                tab_bar, text=f"  {label}  ", font=FONT,
                bg=TAB_INACTIVE_BG, fg=TAB_INACTIVE_FG,
                padx=14, pady=6, cursor="hand2"
            )
            btn.pack(side="left")
            btn.bind("<Button-1>", lambda _, i=idx: self._select_tab(i))
            self._tab_buttons.append(btn)

        # Filler to the right of tabs
        tk.Frame(tab_bar, bg=TAB_INACTIVE_BG).pack(side="left", fill="x",
                                                     expand=True)

        # Thin accent line under tab bar
        tk.Frame(self, bg="#334155", height=1).pack(fill="x")

        # ── Panel container ───────────────────────────────────────
        self._container = tk.Frame(self, bg=BG)
        self._container.pack(fill="both", expand=True)

        wan = tk.Frame(self._container, bg=BG)
        self._panels.append(wan)
        self._build_wan_panel(wan, cfg)

        bl = tk.Frame(self._container, bg=BG)
        self._panels.append(bl)
        self._build_blocklist_panel(bl)

        # Show first tab
        self._current_tab = -1
        self._select_tab(0)

        # Centre on screen
        self.update_idletasks()
        w, h = 540, self.H_COMPACT
        x = (self.winfo_screenwidth() - w) // 2
        y = (self.winfo_screenheight() - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    # ── Tab switching ─────────────────────────────────────────────

    def _select_tab(self, idx):
        if idx == self._current_tab:
            return
        self._current_tab = idx

        for i, btn in enumerate(self._tab_buttons):
            if i == idx:
                btn.config(bg=TAB_ACTIVE_BG, fg=TAB_ACTIVE_FG)
            else:
                btn.config(bg=TAB_INACTIVE_BG, fg=TAB_INACTIVE_FG)

        for panel in self._panels:
            panel.pack_forget()

        self._panels[idx].pack(in_=self._container, fill="both", expand=True)

        # Reset to compact height when switching tabs
        self.geometry(f"540x{self.H_COMPACT}")

    # ── WAN Logs panel ────────────────────────────────────────────

    def _build_wan_panel(self, parent, cfg):
        # --- IP field ---
        ip_frame = tk.Frame(parent, bg=BG)
        ip_frame.pack(fill="x", padx=16, pady=(14, 6))

        tk.Label(
            ip_frame, text="Public IP to replace:", font=FONT,
            bg=BG, fg=FG, anchor="w"
        ).pack(side="left")

        self.ip_var = tk.StringVar(value=cfg.get("last_ip", DEFAULT_IP))
        self.ip_entry = tk.Entry(
            ip_frame, textvariable=self.ip_var, width=20,
            font=FONT, bg=ENTRY_BG, fg=FG,
            insertbackground=FG, relief="flat", highlightthickness=1,
            highlightcolor=ACCENT, highlightbackground="#334155"
        )
        self.ip_entry.pack(side="left", padx=(10, 0))

        tk.Button(
            ip_frame, text="Update", font=FONT_SM,
            bg=BTN_BG, fg=BTN_FG, activebackground=ACCENT,
            activeforeground="#0f172a", relief="flat", cursor="hand2",
            command=self._wan_update_ip
        ).pack(side="left", padx=(6, 0))

        # --- Date filter checkbox ---
        date_frame = tk.Frame(parent, bg=BG)
        date_frame.pack(fill="x", padx=16, pady=(2, 4))

        self.date_filter_var = tk.BooleanVar(
            value=cfg.get("date_filter_enabled", False)
        )
        tk.Checkbutton(
            date_frame, text="Skip previously processed logs",
            variable=self.date_filter_var, font=FONT_SM,
            bg=BG, fg=FG, selectcolor="#1e293b",
            activebackground=BG, activeforeground=FG,
            command=self._toggle_date_filter
        ).pack(side="left")

        stored = cfg.get("last_log_date", "")
        if stored:
            try:
                display_dt = datetime.fromisoformat(stored).strftime(
                    "%b %d %H:%M:%S %Y"
                )
            except ValueError:
                display_dt = stored
            cutoff_text = f"(cutoff: {display_dt})"
        else:
            cutoff_text = "(no cutoff set)"
        self.date_cutoff_label = tk.Label(
            date_frame, text=cutoff_text, font=FONT_SM,
            bg=BG, fg="#475569"
        )
        self.date_cutoff_label.pack(side="left", padx=(8, 0))

        # --- Browse ---
        tk.Button(
            parent, text="Browse for log file…", font=FONT, width=24,
            bg=BTN_BG, fg=BTN_FG, activebackground=ACCENT,
            activeforeground="#0f172a", relief="flat", cursor="hand2",
            command=self._wan_browse
        ).pack(pady=(14, 4))

        tk.Label(
            parent, text="— or paste logs below —", font=FONT_SM,
            bg=BG, fg="#475569"
        ).pack(pady=(4, 4))

        # --- Paste box ---
        paste_frame = tk.Frame(parent, bg=BG)
        paste_frame.pack(fill="both", expand=True, padx=16, pady=(0, 4))

        self.wan_paste = tk.Text(
            paste_frame, font=FONT_MON, wrap="none", height=8,
            bg=ENTRY_BG, fg=FG, relief="flat",
            insertbackground=FG, highlightthickness=1,
            highlightcolor=ACCENT, highlightbackground="#334155"
        )
        scroll = tk.Scrollbar(
            paste_frame, orient="vertical", command=self.wan_paste.yview
        )
        self.wan_paste.configure(yscrollcommand=scroll.set)
        self.wan_paste.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        paste_frame.rowconfigure(0, weight=1)
        paste_frame.columnconfigure(0, weight=1)

        tk.Button(
            parent, text="Process pasted logs", font=FONT, width=24,
            bg=BTN_BG, fg=BTN_FG, activebackground=ACCENT,
            activeforeground="#0f172a", relief="flat", cursor="hand2",
            command=self._wan_submit_paste
        ).pack(pady=(4, 6))

        # --- Status ---
        self.wan_status_var = tk.StringVar(value="Ready.")
        self.wan_status_label = tk.Label(
            parent, textvariable=self.wan_status_var, font=FONT_SM,
            bg=BG, fg="#94a3b8", anchor="w", wraplength=500, justify="left"
        )
        self.wan_status_label.pack(fill="x", padx=16, pady=(0, 6))

        # --- Removed-lines viewer ---
        (self.wan_rm_label,
         self.wan_log_frame,
         self.wan_log_text) = _build_log_viewer(parent)

    # ── WAN handlers ─────────────────────────────────────────────

    def _validate_ip(self) -> str | None:
        target_ip = self.ip_var.get().strip()
        if not target_ip:
            _show_status(self.wan_status_var, self.wan_status_label,
                        "Please enter an IP address.", error=True)
            return None
        parts = target_ip.split(".")
        if len(parts) != 4 or not all(
            p.isdigit() and 0 <= int(p) <= 255 for p in parts
        ):
            _show_status(self.wan_status_var, self.wan_status_label,
                        "Invalid IPv4 address format.", error=True)
            return None
        return target_ip

    def _wan_update_ip(self):
        target_ip = self._validate_ip()
        if not target_ip:
            return
        update_config(last_ip=target_ip)
        _show_status(self.wan_status_var, self.wan_status_label,
                    f"Default IP updated to {target_ip}.")

    def _toggle_date_filter(self):
        update_config(date_filter_enabled=self.date_filter_var.get())

    def _get_cutoff_dt(self):
        # Return cutoff datetime if date filtering is enabled, else None.
        if not self.date_filter_var.get():
            return None
        cfg = load_config()
        date_str = cfg.get("last_log_date")
        if not date_str:
            return None
        try:
            return datetime.fromisoformat(date_str)
        except ValueError:
            return None

    def _save_latest_date(self, latest_dt):
        # Save latest log date to config if date filtering is enabled.
        if self.date_filter_var.get() and latest_dt:
            date_str = latest_dt.isoformat()
            update_config(last_log_date=date_str)
            display = latest_dt.strftime("%b %d %H:%M:%S %Y")
            self.date_cutoff_label.config(text=f"(cutoff: {display})")

    def _wan_browse(self):
        path = filedialog.askopenfilename(
            title="Select a log file",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if path:
            self._wan_run_file(path)

    def _wan_submit_paste(self):
        raw = self.wan_paste.get("1.0", "end").strip()
        if not raw:
            _show_status(self.wan_status_var, self.wan_status_label,
                        "Paste some log lines first.", error=True)
            return
        self._wan_run_paste(raw)

    def _wan_run_file(self, filepath):
        target_ip = self._validate_ip()
        if not target_ip:
            return

        src = Path(filepath)
        if not src.is_file():
            _show_status(self.wan_status_var, self.wan_status_label,
                        f"File not found:\n{src}", error=True)
            return
        if src.suffix.lower() != ".txt":
            _show_status(self.wan_status_var, self.wan_status_label,
                        "Please select a .txt file.", error=True)
            return

        cutoff_dt = self._get_cutoff_dt()

        try:
            text = src.read_text(encoding="utf-8", errors="replace")
            (new_text, count, num_removed, lines_kept,
             removed_lines, date_filtered, changed, latest_dt, mac_count) = \
                process_wan_text(text, target_ip, cutoff_dt)

            update_config(last_ip=target_ip)

            if not changed:
                _show_status(
                    self.wan_status_var, self.wan_status_label,
                    f"No changes — all {lines_kept} lines matched filters "
                    f"and no occurrences of {target_ip} found. File not saved.",
                    warn=True
                )
                _clear_log(self.wan_rm_label, self.wan_log_frame,
                          self.wan_log_text)
            else:
                out_path = src.parent / self._wan_out_name()
                out_path.write_text(new_text, encoding="utf-8")
                self._save_latest_date(latest_dt)
                self._wan_show_results(
                    lines_kept, num_removed, date_filtered,
                    count, mac_count, str(out_path), removed_lines
                )
        except Exception as exc:
            _show_status(self.wan_status_var, self.wan_status_label,
                        str(exc), error=True)
            _clear_log(self.wan_rm_label, self.wan_log_frame,
                      self.wan_log_text)

    def _wan_run_paste(self, raw_text):
        target_ip = self._validate_ip()
        if not target_ip:
            return

        cutoff_dt = self._get_cutoff_dt()

        try:
            (new_text, count, num_removed, lines_kept,
             removed_lines, date_filtered, changed, latest_dt, mac_count) = \
                process_wan_text(raw_text, target_ip, cutoff_dt)

            update_config(last_ip=target_ip)

            if not changed:
                _show_status(
                    self.wan_status_var, self.wan_status_label,
                    f"No changes — all {lines_kept} lines matched filters "
                    f"and no occurrences of {target_ip} found. File not saved.",
                    warn=True
                )
                _clear_log(self.wan_rm_label, self.wan_log_frame,
                          self.wan_log_text)
                return

            out_path = filedialog.asksaveasfilename(
                title="Save cleaned log as",
                initialfile=self._wan_out_name(),
                defaultextension=".txt",
                filetypes=[("Text files", "*.txt")]
            )
            if not out_path:
                _show_status(self.wan_status_var, self.wan_status_label,
                            "Save cancelled.", warn=True)
                return

            Path(out_path).write_text(new_text, encoding="utf-8")
            self._save_latest_date(latest_dt)
            self._wan_show_results(
                lines_kept, num_removed, date_filtered,
                count, mac_count, out_path, removed_lines
            )
        except Exception as exc:
            _show_status(self.wan_status_var, self.wan_status_label,
                        str(exc), error=True)
            _clear_log(self.wan_rm_label, self.wan_log_frame,
                      self.wan_log_text)

    def _wan_show_results(self, lines_kept, num_removed, date_filtered,
                          count, mac_count, out_path, removed_lines):
        # Build status message and populate the removed-lines viewer.
        parts = [f"Success — {lines_kept} log lines kept"]
        if num_removed:
            parts.append(f"{num_removed} removed")
        if date_filtered:
            parts.append(f"{len(date_filtered)} date-filtered")
        parts.append(f"{count} IP replacement(s)")
        if mac_count:
            parts.append(f"{mac_count} MAC address(es) redacted")
        _show_status(
            self.wan_status_var, self.wan_status_label,
            ", ".join(parts) + f".  Saved to: {out_path}"
        )

        # Combine removed lines + date-filtered lines for display
        display_lines = list(removed_lines)
        for ln in date_filtered:
            display_lines.append(f"*date filtered*: {ln}")

        _show_removed_lines(self.wan_rm_label, self.wan_log_frame,
                           self.wan_log_text, display_lines)
        self.geometry(f"540x{self.H_EXPANDED}")

    @staticmethod
    def _wan_out_name() -> str:
        return f"wanRejects{datetime.now().strftime('%m%d%Y')}.txt"

    # ── Blocklist Logs panel ──────────────────────────────────────

    def _build_blocklist_panel(self, parent):
        tk.Label(
            parent, text="Select a .txt blocklist file to clean:",
            font=FONT, bg=BG, fg=FG, anchor="w"
        ).pack(fill="x", padx=16, pady=(14, 6))

        path_frame = tk.Frame(parent, bg=BG)
        path_frame.pack(fill="x", padx=16)

        self.bl_path_var = tk.StringVar()
        tk.Entry(
            path_frame, textvariable=self.bl_path_var, font=FONT,
            bg=ENTRY_BG, fg=FG, insertbackground=FG,
            relief="flat", highlightthickness=1,
            highlightcolor=ACCENT, highlightbackground="#334155"
        ).pack(side="left", fill="x", expand=True, padx=(0, 8))

        tk.Button(
            path_frame, text="Browse…", font=FONT_SM,
            bg=BTN_BG, fg=BTN_FG, activebackground=ACCENT,
            activeforeground="#0f172a", relief="flat", cursor="hand2",
            command=self._bl_browse
        ).pack(side="left")

        tk.Button(
            parent, text="Process & Save", font=FONT, width=24,
            bg=BTN_BG, fg=BTN_FG, activebackground=ACCENT,
            activeforeground="#0f172a", relief="flat", cursor="hand2",
            command=self._bl_process
        ).pack(pady=(14, 6))

        # --- Status ---
        self.bl_status_var = tk.StringVar(value="Ready.")
        self.bl_status_label = tk.Label(
            parent, textvariable=self.bl_status_var, font=FONT_SM,
            bg=BG, fg="#94a3b8", anchor="w", wraplength=500, justify="left"
        )
        self.bl_status_label.pack(fill="x", padx=16, pady=(0, 6))

        # --- Removed-lines viewer ---
        (self.bl_rm_label,
         self.bl_log_frame,
         self.bl_log_text) = _build_log_viewer(parent)

    # ── Blocklist handlers ────────────────────────────────────────

    def _bl_browse(self):
        filepath = filedialog.askopenfilename(
            title="Select Blocklist File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filepath:
            self.bl_path_var.set(filepath)

    def _bl_process(self):
        filepath = self.bl_path_var.get().strip()
        if not filepath:
            _show_status(self.bl_status_var, self.bl_status_label,
                        "Please select a file first.", warn=True)
            return

        if not os.path.isfile(filepath):
            _show_status(self.bl_status_var, self.bl_status_label,
                        f"File not found:\n{filepath}", error=True)
            return

        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            kept = []
            removed = []
            for line in lines:
                stripped = line.strip()
                if stripped and stripped[0].isdigit():
                    kept.append(line)
                else:
                    removed.append(line.rstrip("\n\r"))

            if not kept:
                _show_status(self.bl_status_var, self.bl_status_label,
                            "No lines starting with a digit were found.",
                            error=True)
                _clear_log(self.bl_rm_label, self.bl_log_frame,
                          self.bl_log_text)
                return

            out_dir = os.path.dirname(filepath)
            out_path = os.path.join(out_dir, "banip.blocklist")

            with open(out_path, "w", encoding="utf-8") as f:
                f.writelines(kept)

            _show_status(
                self.bl_status_var, self.bl_status_label,
                f"Success — kept {len(kept)} of {len(lines)} lines, "
                f"removed {len(removed)}.  Saved to: {out_path}"
            )
            _show_removed_lines(self.bl_rm_label, self.bl_log_frame,
                               self.bl_log_text, removed, numbered=True)
            self.geometry(f"540x{self.H_EXPANDED}")

        except Exception as exc:
            _show_status(self.bl_status_var, self.bl_status_label,
                        str(exc), error=True)
            _clear_log(self.bl_rm_label, self.bl_log_frame,
                      self.bl_log_text)


# ─────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = App()
    app.mainloop()
