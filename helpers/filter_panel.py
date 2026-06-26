#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════╗
# ║              NetPyINT – Advanced Filter Controls Panel           ║
# ╚══════════════════════════════════════════════════════════════════╝
#
# Sidebar widget offering continuous-criteria filtering (score range,
# recency, ASN/ISP substring, country multi-select, hits threshold) that
# AND-combines with the existing "Filter by Coverage" Combobox in
# netpyint_main.py. Session-only — never persisted to netpyint_config.json,
# consistent with self.var_filter, which also resets to "All IPs" on every
# launch. Collapsed/expanded state is likewise session-only. Saved presets
# (named snapshots of this panel's criteria) are the one exception — those
# persist to config["filter_presets"].
#
# country_codes (this panel) vs cc_filter ("Country: Highlighted" combo
# option) are deliberately separate concepts/parameters — not merged. One
# is a fixed user-configured watchlist; the other is an ad hoc, session-only
# multi-select scoped to this panel.
#
# Tri-state note on the country Listbox: an empty selection is treated as
# "control not engaged" (no country filter), NOT as "zero codes active, show
# nothing" — unlike cc_filter's contract. The Listbox has no separate
# enable/disable toggle, so an empty selection is indistinguishable from
# "never touched"; the forgiving interpretation avoids a surprise empty
# table on first load.
#
# Public surface (imported by netpyint_main.py):
#     FilterPanel

import tkinter as tk
from tkinter import ttk, simpledialog, messagebox


class FilterPanel:
    DEFAULT_SCORE_MIN = 0
    DEFAULT_SCORE_MAX = 100
    DAY_PRESETS = (("1d", 1), ("7d", 7), ("30d", 30), ("90d", 90))

    def __init__(self, parent, repo, on_change, config, save_config_fn,
                start_collapsed=True):
        # parent (ttk.Frame):    the sidebar frame to pack widgets into.
        # repo (IPRepository):   used to populate the country Listbox.
        # on_change (callable):  no-arg callback fired after any control
        #                        settles (post-debounce for sliders/entries/
        #                        spinboxes, immediately for discrete controls).
        # config (dict):         app config dict; read/written in-place for
        #                        filter_presets (config["filter_presets"]).
        # save_config_fn:        called with `config` after a preset is saved
        #                        or deleted, to persist it to disk.
        # start_collapsed (bool): whether the panel should begin collapsed
        #                        on construction. Driven by
        #                        config["start_advanced_filters_hidden"] —
        #                        only affects initial state, not later
        #                        toggling within the same session.
        self._repo = repo
        self._on_change = on_change
        self._config = config
        self._save_config_fn = save_config_fn
        self._owner_after = parent.after
        self._owner_after_cancel = parent.after_cancel
        self._debounce_id = None
        self._collapsed = False

        # Header: click the triangle/label to show or hide everything below —
        # same expand/collapse idiom as the Treeview column sort arrows
        # (_update_sort_arrows in netpyint_main.py), just ▼/▶ instead of ↓/↑.
        # The "(N active)" suffix keeps the active criteria visible even
        # while collapsed.
        self.lbl_title = ttk.Label(parent, text="▼ Advanced Filters",
                                   style="Title.TLabel", cursor="hand2")
        self.lbl_title.pack(anchor="w", padx=8, pady=(4, 4))
        self.lbl_title.bind("<Button-1>", lambda e: self.toggle_collapsed())

        # Body: every actual control lives in here so the whole section can
        # be hidden/shown in one pack_forget()/pack() call.
        self._body = ttk.Frame(parent)
        self._body.pack(fill="x")
        body = self._body

        # ── Score range ──
        ttk.Label(body, text="Score min/max:", font=("Consolas", 9)).pack(
            anchor="w", padx=12)

        self.var_score_min = tk.DoubleVar(value=self.DEFAULT_SCORE_MIN)
        self.var_score_max = tk.DoubleVar(value=self.DEFAULT_SCORE_MAX)
        self.var_score_min_text = tk.StringVar(value=str(self.DEFAULT_SCORE_MIN))
        self.var_score_max_text = tk.StringVar(value=str(self.DEFAULT_SCORE_MAX))

        min_row = ttk.Frame(body)
        min_row.pack(fill="x", padx=12)
        entry_min = ttk.Entry(min_row, textvariable=self.var_score_min_text,
                              width=4, font=("Consolas", 9))
        entry_min.pack(side="right")
        entry_min.bind("<Return>", lambda e: self._on_score_entry_change("min"))
        entry_min.bind("<FocusOut>", lambda e: self._on_score_entry_change("min"))
        ttk.Scale(min_row, from_=0, to=100, orient="horizontal",
                  variable=self.var_score_min,
                  command=lambda v: self._on_score_scale_change("min", v)
                  ).pack(side="left", fill="x", expand=True)

        max_row = ttk.Frame(body)
        max_row.pack(fill="x", padx=12, pady=(0, 4))
        entry_max = ttk.Entry(max_row, textvariable=self.var_score_max_text,
                              width=4, font=("Consolas", 9))
        entry_max.pack(side="right")
        entry_max.bind("<Return>", lambda e: self._on_score_entry_change("max"))
        entry_max.bind("<FocusOut>", lambda e: self._on_score_entry_change("max"))
        ttk.Scale(max_row, from_=0, to=100, orient="horizontal",
                  variable=self.var_score_max,
                  command=lambda v: self._on_score_scale_change("max", v)
                  ).pack(side="left", fill="x", expand=True)

        # ── Date lookback (relative, no date-picker dependency) ──
        # Quick-pick buttons set the spinbox directly — handy presets instead
        # of dragging/typing for the common "last week/month/quarter" cases.
        ttk.Label(body, text="First seen ≤ N days ago (0=off):",
                  font=("Consolas", 9)).pack(anchor="w", padx=12)
        fs_row = ttk.Frame(body)
        fs_row.pack(fill="x", padx=12, pady=(0, 4))
        self.var_first_seen_days = tk.StringVar(value="0")
        ttk.Spinbox(fs_row, from_=0, to=3650, textvariable=self.var_first_seen_days,
                    width=6, font=("Consolas", 9),
                    command=self._on_input_changed).pack(side="left")
        self.var_first_seen_days.trace_add("write", lambda *_: self._on_input_changed())
        for label, n in self.DAY_PRESETS:
            ttk.Button(fs_row, text=label, width=3,
                      command=lambda n=n: self.var_first_seen_days.set(str(n))
                      ).pack(side="left", padx=(4, 0))

        ttk.Label(body, text="Last seen ≤ N days ago (0=off):",
                  font=("Consolas", 9)).pack(anchor="w", padx=12)
        ls_row = ttk.Frame(body)
        ls_row.pack(fill="x", padx=12, pady=(0, 4))
        self.var_last_seen_days = tk.StringVar(value="0")
        ttk.Spinbox(ls_row, from_=0, to=3650, textvariable=self.var_last_seen_days,
                    width=6, font=("Consolas", 9),
                    command=self._on_input_changed).pack(side="left")
        self.var_last_seen_days.trace_add("write", lambda *_: self._on_input_changed())
        for label, n in self.DAY_PRESETS:
            ttk.Button(ls_row, text=label, width=3,
                      command=lambda n=n: self.var_last_seen_days.set(str(n))
                      ).pack(side="left", padx=(4, 0))

        # ── Hits threshold ──
        hits_frame = ttk.Frame(body)
        hits_frame.pack(fill="x", padx=12, pady=(0, 4))
        ttk.Label(hits_frame, text="Hits ≥", font=("Consolas", 9)).pack(side="left")
        self.var_min_hits = tk.StringVar(value="0")
        ttk.Spinbox(hits_frame, from_=0, to=999999, textvariable=self.var_min_hits,
                    width=8, font=("Consolas", 9),
                    command=self._on_input_changed).pack(side="left", padx=(4, 0))
        self.var_min_hits.trace_add("write", lambda *_: self._on_input_changed())

        # ── ASN / ISP substring (comma-separated terms OR together) ──
        ttk.Label(body, text="ASN/ISP contains (comma = OR):",
                  font=("Consolas", 9)).pack(anchor="w", padx=12)
        self.var_asn_isp = tk.StringVar(value="")
        ttk.Entry(body, textvariable=self.var_asn_isp, font=("Consolas", 9)
                  ).pack(fill="x", padx=12, pady=(0, 4))
        self.var_asn_isp.trace_add("write", lambda *_: self._on_input_changed())

        # ── Country multi-select ──
        ttk.Label(body, text="Countries (none = all):", font=("Consolas", 9)).pack(
            anchor="w", padx=12)

        search_row = ttk.Frame(body)
        search_row.pack(fill="x", padx=12, pady=(0, 2))
        self.var_country_search = tk.StringVar(value="")
        ttk.Entry(search_row, textvariable=self.var_country_search,
                  font=("Consolas", 9)).pack(side="left", fill="x", expand=True)
        self.var_country_search.trace_add("write", lambda *_: self._render_country_list())

        cc_frame = ttk.Frame(body)
        cc_frame.pack(fill="x", padx=12, pady=(0, 2))
        self.lst_countries = tk.Listbox(cc_frame, selectmode=tk.MULTIPLE, height=6,
                                         exportselection=False,
                                         bg="#1e293b", fg="#e2e8f0",
                                         selectbackground="#334155",
                                         selectforeground="#38bdf8",
                                         highlightthickness=0, relief="flat",
                                         font=("Consolas", 9))
        self.lst_countries.pack(side="left", fill="both", expand=True)
        cc_scroll = ttk.Scrollbar(cc_frame, orient="vertical",
                                   command=self.lst_countries.yview)
        cc_scroll.pack(side="right", fill="y")
        self.lst_countries.configure(yscrollcommand=cc_scroll.set)
        self.lst_countries.bind("<<ListboxSelect>>", self._on_listbox_select)
        self._all_countries = []     # [(code, count), ...] — full set from the DB
        self._visible_codes = []     # parallel to Listbox rows after a search filter
        self._selected_codes = set()  # persists across search-filter changes
        self.refresh_countries()

        cc_btn_row = ttk.Frame(body)
        cc_btn_row.pack(fill="x", padx=12, pady=(0, 4))
        ttk.Button(cc_btn_row, text="Select All",
                  command=self._select_all_visible).pack(side="left")
        ttk.Button(cc_btn_row, text="Clear All", style="DangerHover.TButton",
                  command=self._clear_all_countries).pack(side="left", padx=(4, 0))

        # ── Reset button ──
        ttk.Separator(body, orient="horizontal").pack(fill="x", padx=12, pady=(4, 8))
        ttk.Button(body, text="Clear All Advanced Filters", style="DangerHover.TButton",
                  command=self.reset).pack(anchor="w", padx=12, pady=(0, 4))

        # ── Saved presets ──
        ttk.Separator(body, orient="horizontal").pack(fill="x", padx=12, pady=(4, 4))
        ttk.Label(body, text="Saved Presets:", font=("Consolas", 9)).pack(
            anchor="w", padx=12)
        self.var_preset = tk.StringVar(value="")
        self.combo_presets = ttk.Combobox(
            body, textvariable=self.var_preset, state="readonly",
            font=("Consolas", 9), values=self._preset_names())
        self.combo_presets.pack(fill="x", padx=12, pady=(0, 4))
        self.combo_presets.bind("<<ComboboxSelected>>", lambda e: self._load_preset())

        preset_btn_row = ttk.Frame(body)
        preset_btn_row.pack(fill="x", padx=12, pady=(0, 8))
        ttk.Button(preset_btn_row, text="Save As...",
                  command=self._save_preset).pack(side="left")
        ttk.Button(preset_btn_row, text="Delete", style="DangerHover.TButton",
                  command=self._delete_preset).pack(side="left", padx=(4, 0))

        # Starts collapsed by default — unlike "Filter by Coverage", which
        # always starts shown — but configurable via the Settings menu's
        # "Start with Advanced Filters Hidden" checkbutton.
        if start_collapsed:
            self.toggle_collapsed()

    def toggle_collapsed(self):
        # Show/hide the entire body in one call — the header label (with its
        # ▼/▶ triangle) stays visible either way.
        self._collapsed = not self._collapsed
        if self._collapsed:
            self._body.pack_forget()
        else:
            self._body.pack(fill="x")
        self._update_title()

    def _update_title(self):
        arrow = "▶" if self._collapsed else "▼"
        n = self._active_filter_count()
        suffix = f" ({n} active)" if n else ""
        self.lbl_title.config(text=f"{arrow} Advanced Filters{suffix}")

    def _active_filter_count(self):
        # score_min/score_max are always either both None or both set
        # together (see get_filter_kwargs), so checking score_min alone
        # is enough to count the score range as one active criterion.
        kw = self.get_filter_kwargs()
        return sum(1 for key in ("score_min", "first_seen_days", "last_seen_days",
                                  "asn_isp_term", "country_codes", "min_hits")
                   if kw[key] is not None)

    def _on_input_changed(self):
        self._update_title()
        self._schedule_refresh()

    def refresh_countries(self):
        # Repopulate the Listbox from current DB contents. Call this whenever
        # the dataset changes materially (e.g. after a log import). Selection
        # is tracked by code in self._selected_codes, independent of the
        # Listbox's own indices, so this never loses the user's selection.
        self._all_countries = self._repo.get_distinct_countries()
        self._render_country_list()

    def _render_country_list(self):
        # Redraw the Listbox from self._all_countries, filtered by the search
        # box text. Re-applies self._selected_codes to whichever rows are
        # visible — codes hidden by the current search keep their selection
        # state, they just aren't shown as selected until the search clears.
        query = self.var_country_search.get().strip().upper()
        self.lst_countries.delete(0, tk.END)
        self._visible_codes = []
        for code, count in self._all_countries:
            if query and query not in code.upper():
                continue
            self._visible_codes.append(code)
            self.lst_countries.insert(tk.END, f"{code} ({count:,})")
        for idx, code in enumerate(self._visible_codes):
            if code in self._selected_codes:
                self.lst_countries.selection_set(idx)

    def _on_listbox_select(self, event=None):
        # Sync self._selected_codes from the currently visible selection.
        # Only the visible (currently rendered) codes are updated — codes
        # hidden by an active search retain whatever selection state they
        # already had, since curselection() can't see them.
        visible_selected = {self._visible_codes[i] for i in self.lst_countries.curselection()}
        visible_set = set(self._visible_codes)
        self._selected_codes = (self._selected_codes - visible_set) | visible_selected
        self._update_title()
        self._on_change()

    def _select_all_visible(self):
        # "Select All" acts on the currently filtered/visible rows only —
        # the common case is narrowing via search, then grabbing everything
        # that matched.
        self._selected_codes |= set(self._visible_codes)
        self._render_country_list()
        self._update_title()
        self._on_change()

    def _clear_all_countries(self):
        self._selected_codes = set()
        self._render_country_list()
        self._update_title()
        self._on_change()

    def get_selected_countries(self):
        # Returns a tuple of selected country codes, or None when nothing is
        # selected — see the tri-state note in the module docstring for why
        # an empty selection means "not engaged" rather than "show nothing".
        if not self._selected_codes:
            return None
        return tuple(sorted(self._selected_codes))

    def _on_score_scale_change(self, which, value):
        v = round(float(value))
        if which == "min":
            self.var_score_min_text.set(str(v))
        else:
            self.var_score_max_text.set(str(v))
        self._on_input_changed()

    def _on_score_entry_change(self, which):
        # Manual numeric entry next to each slider — Return or focus-out
        # parses, clamps to [0, 100], and snaps the Scale to match.
        text_var = self.var_score_min_text if which == "min" else self.var_score_max_text
        num_var = self.var_score_min if which == "min" else self.var_score_max
        default = self.DEFAULT_SCORE_MIN if which == "min" else self.DEFAULT_SCORE_MAX
        try:
            v = round(float(text_var.get()))
        except ValueError:
            v = default
        v = max(0, min(100, v))
        text_var.set(str(v))
        num_var.set(v)
        self._on_input_changed()

    def _schedule_refresh(self):
        # Same 200ms debounce idiom as netpyint_main.py's
        # _schedule_search()/_apply_search(), reused here so dragging a
        # slider or typing into a field doesn't fire a DB query per tick.
        if self._debounce_id is not None:
            self._owner_after_cancel(self._debounce_id)
        self._debounce_id = self._owner_after(200, self._fire_on_change)

    def _fire_on_change(self):
        self._debounce_id = None
        self._on_change()

    def reset(self):
        self.var_score_min.set(self.DEFAULT_SCORE_MIN)
        self.var_score_max.set(self.DEFAULT_SCORE_MAX)
        self.var_score_min_text.set(str(self.DEFAULT_SCORE_MIN))
        self.var_score_max_text.set(str(self.DEFAULT_SCORE_MAX))
        self.var_first_seen_days.set("0")
        self.var_last_seen_days.set("0")
        self.var_asn_isp.set("")
        self.var_min_hits.set("0")
        self.var_country_search.set("")
        self._selected_codes = set()
        self._render_country_list()
        self.var_preset.set("")
        self._update_title()
        self._on_change()

    def get_filter_kwargs(self):
        # Translate current widget state into kwargs for
        # IPRepository._build_filter_where() (via get_ips_for_table /
        # get_scoring_data_for_filter / get_insights_records).
        score_min = self.var_score_min.get()
        score_max = self.var_score_max.get()
        # Default-range detection: if the user has not moved either handle
        # away from [0, 100], treat the score criterion as fully disabled
        # (None, None) so an untouched slider never adds a WHERE clause.
        if score_min <= self.DEFAULT_SCORE_MIN and score_max >= self.DEFAULT_SCORE_MAX:
            score_min = score_max = None

        def _parse_positive_int(var):
            try:
                n = int(var.get())
            except (ValueError, tk.TclError):
                return None
            return n if n > 0 else None

        return dict(
            score_min=score_min,
            score_max=score_max,
            first_seen_days=_parse_positive_int(self.var_first_seen_days),
            last_seen_days=_parse_positive_int(self.var_last_seen_days),
            asn_isp_term=self.var_asn_isp.get().strip() or None,
            country_codes=self.get_selected_countries(),
            min_hits=_parse_positive_int(self.var_min_hits),
        )

    def set_filter_kwargs(self, kwargs):
        # Restore widget state from a previously saved preset (or any dict
        # shaped like get_filter_kwargs()'s output). Missing/None keys reset
        # that control to its disabled default rather than leaving stale
        # values in place.
        score_min = kwargs.get("score_min")
        score_max = kwargs.get("score_max")
        score_min = self.DEFAULT_SCORE_MIN if score_min is None else score_min
        score_max = self.DEFAULT_SCORE_MAX if score_max is None else score_max
        self.var_score_min.set(score_min)
        self.var_score_max.set(score_max)
        self.var_score_min_text.set(str(round(score_min)))
        self.var_score_max_text.set(str(round(score_max)))

        self.var_first_seen_days.set(str(kwargs.get("first_seen_days") or 0))
        self.var_last_seen_days.set(str(kwargs.get("last_seen_days") or 0))
        self.var_asn_isp.set(kwargs.get("asn_isp_term") or "")
        self.var_min_hits.set(str(kwargs.get("min_hits") or 0))

        self.var_country_search.set("")
        self._selected_codes = set(kwargs.get("country_codes") or [])
        self._render_country_list()

        self._update_title()
        self._on_change()

    def _preset_names(self):
        return sorted(self._config.get("filter_presets", {}).keys())

    def _refresh_preset_list(self):
        self.combo_presets.configure(values=self._preset_names())

    def _save_preset(self):
        name = simpledialog.askstring("Save Preset", "Preset name:",
                                      parent=self.combo_presets)
        if not name or not name.strip():
            return
        name = name.strip()
        self._config.setdefault("filter_presets", {})[name] = self.get_filter_kwargs()
        self._save_config_fn(self._config)
        self._refresh_preset_list()
        self.var_preset.set(name)

    def _load_preset(self):
        name = self.var_preset.get()
        preset = self._config.get("filter_presets", {}).get(name)
        if preset is not None:
            self.set_filter_kwargs(preset)

    def _delete_preset(self):
        name = self.var_preset.get()
        presets = self._config.get("filter_presets", {})
        if name not in presets:
            return
        if not messagebox.askyesno("Delete Preset", f"Delete saved preset '{name}'?",
                                   parent=self.combo_presets):
            return
        del presets[name]
        self._save_config_fn(self._config)
        self._refresh_preset_list()
        self.var_preset.set("")
