"""yang_web.gui._panels_tools 子模块 _scripts（自 _panels_tools.py 拆分，请勿手工重排）。"""

from .._deps import (HAS_STEGO, JSChallengeSolver, _REPO_ROOT, analyze_file, analyze_png, extract_lsb, generate_reverse_shell, generate_webshell, identify_cipher_text, list_shell_languages, list_webshell_types, os, read_exif, scrolledtext, tk, ttk)
from .._theme import (ACCENT, BG, BORDER, DARK, FG, GREEN, INPUT_BG, RED, YELLOW)
from .._widgets import (_append, _clear_output, _label, _output_area)





class ScriptsPanel(tk.Frame):
    """CTF scripts panel with dependency management."""

    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        _label(self, "CTF Scripts", fg=ACCENT, font_size=16, bold=True, pady=8)
        _label(self, "D:\\CTF 41 scripts + dep management + Web Solver", fg=YELLOW, font_size=9)

        # Solve bar — input URL, one-click attack
        solve_bar = tk.Frame(self, bg=DARK)
        solve_bar.pack(fill=tk.X, padx=4, pady=(4, 0))
        tk.Label(solve_bar, text="Target:", bg=DARK, fg=ACCENT,
                 font=("Microsoft YaHei UI", 10, "bold")).pack(side=tk.LEFT, padx=(8, 4))
        self.url_entry = tk.Entry(solve_bar, bg=INPUT_BG, fg=FG,
                                   insertbackground=ACCENT, relief="flat",
                                   font=("Cascadia Code", 10),
                                   width=50)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4, ipady=3)
        self.url_entry.insert(0, "http://")
        self.solve_btn = tk.Button(solve_bar, text="Solve", command=self._solve_url,
                                    bg=ACCENT, fg=DARK, activebackground=GREEN,
                                    relief="flat", padx=16, pady=3, cursor="hand2",
                                    font=("Microsoft YaHei UI", 10, "bold"))
        self.solve_btn.pack(side=tk.LEFT, padx=(4, 8))

        # Search bar + dep buttons
        top_bar = tk.Frame(self, bg=BG)
        top_bar.pack(fill=tk.X, pady=(8, 4), padx=4)
        tk.Label(top_bar, text="Search", bg=BG, fg=ACCENT,
                 font=("Microsoft YaHei UI", 12)).pack(side=tk.LEFT)
        self.search_entry = tk.Entry(top_bar, bg=INPUT_BG, fg=FG,
                                      insertbackground=ACCENT, relief="flat",
                                      font=("Cascadia Code", 11), width=25)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8, ipady=4)
        self.search_entry.bind("<KeyRelease>", self._do_search)
        tk.Button(top_bar, text="Check Deps", command=self._check_deps,
                  bg=INPUT_BG, fg=YELLOW, activebackground=ACCENT, relief="flat",
                  padx=10, pady=4, cursor="hand2",
                  font=("Microsoft YaHei UI", 9)).pack(side=tk.LEFT, padx=2)
        tk.Button(top_bar, text="Install All", command=self._install_all_deps,
                  bg=INPUT_BG, fg=GREEN, activebackground=ACCENT, relief="flat",
                  padx=10, pady=4, cursor="hand2",
                  font=("Microsoft YaHei UI", 9)).pack(side=tk.LEFT, padx=2)
        cat_frame = tk.Frame(self, bg=BG)
        cat_frame.pack(fill=tk.X, pady=4, padx=4)
        self.cat_buttons = {}
        for cat_key, cat_label in [("all", "All"), ("crypto", "Crypto"),
                                    ("web", "Web"), ("reverse", "Reverse"),
                                    ("misc", "Misc")]:
            btn = tk.Button(cat_frame, text=cat_label, relief="flat",
                           bg=INPUT_BG, fg=FG, activebackground=ACCENT,
                           activeforeground=DARK, padx=12, pady=4,
                           cursor="hand2", font=("Microsoft YaHei UI", 9),
                           command=lambda c=cat_key: self._filter_cat(c))
            btn.pack(side=tk.LEFT, padx=2)
            self.cat_buttons[cat_key] = btn
        self.dep_status_label = tk.Label(cat_frame, text="", bg=BG, fg=YELLOW,
                                          font=("Microsoft YaHei UI", 8))
        self.dep_status_label.pack(side=tk.RIGHT, padx=8)
        panes = tk.PanedWindow(self, bg=BG, sashwidth=3)
        panes.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        list_frame = tk.Frame(panes, bg=BG)
        panes.add(list_frame, width=340)
        _label(list_frame, "Scripts:", pady=4)
        self.script_list = tk.Listbox(list_frame, bg=INPUT_BG, fg=FG,
                                       selectbackground=ACCENT,
                                       selectforeground=DARK,
                                       relief="flat", borderwidth=0,
                                       font=("Microsoft YaHei UI", 10),
                                       height=20)
        self.script_list.pack(fill=tk.BOTH, expand=True, pady=(0, 4))
        self.script_list.bind("<<ListboxSelect>>", self._on_select)
        detail_frame = tk.Frame(panes, bg=BG)
        panes.add(detail_frame, width=580)
        _label(detail_frame, "Details:", pady=4)
        self.detail_frame, self.detail_output = _output_area(detail_frame, 18)
        self.detail_frame.pack(fill=tk.BOTH, expand=True)
        btn_bar = tk.Frame(detail_frame, bg=BG)
        btn_bar.pack(fill=tk.X, pady=4)
        tk.Button(btn_bar, text="Run", command=self._run_selected,
                  bg=GREEN, fg=DARK, activebackground=ACCENT, relief="flat",
                  padx=20, pady=6, cursor="hand2",
                  font=("Microsoft YaHei UI", 11, "bold")).pack(side=tk.LEFT, padx=(0, 8))
        self.install_btn = tk.Button(btn_bar, text="Install Script Deps",
                                      command=self._install_script_deps,
                                      bg=INPUT_BG, fg=YELLOW, activebackground=ACCENT,
                                      relief="flat", padx=12, pady=6, cursor="hand2",
                                      font=("Microsoft YaHei UI", 10))
        self.install_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.install_btn.pack_forget()
        tk.Button(btn_bar, text="Clear", command=lambda: _clear_output(self.detail_output),
                  bg=RED, fg=DARK, activebackground="#ff6b6b", relief="flat",
                  padx=16, pady=6, cursor="hand2",
                  font=("Microsoft YaHei UI", 10)).pack(side=tk.LEFT)
        self._all_scripts = []
        self._current_key = None
        self._dep_status = {}
        self._populate_list()

    def _populate_list(self, category=None, query=None):
        self.script_list.delete(0, tk.END)
        self._all_scripts = []
        try:
            from ...scripts.registry import SCRIPTS, CATEGORIES
            from ...scripts.deps import check_dep
            for key, meta in sorted(SCRIPTS.items(), key=lambda x: x[0]):
                if category and category != "all" and meta["category"] != category:
                    continue
                if query and query.lower() not in key.lower() and query.lower() not in meta["title"].lower() and query.lower() not in meta["description"].lower():
                    continue
                cat_icon = CATEGORIES.get(meta["category"], "?")
                if meta["deps"]:
                    all_ok = all(check_dep(d) for d in meta["deps"])
                    dep_icon = " [OK]" if all_ok else " [MISS]"
                else:
                    dep_icon = ""
                display = cat_icon + " " + meta['title'] + dep_icon
                self.script_list.insert(tk.END, display)
                self._all_scripts.append((key, meta))
        except Exception as e:
            self.script_list.insert(tk.END, "err: " + str(e))

    def _filter_cat(self, cat):
        for k, btn in self.cat_buttons.items():
            if k == cat:
                btn.configure(bg=ACCENT, fg=DARK)

            else:
                btn.configure(bg=INPUT_BG, fg=FG)

        self._populate_list(category=cat)

    def _do_search(self, event):
        q = self.search_entry.get().strip()

        self._populate_list(query=q if q else None)

    def _on_select(self, event):
        sel = self.script_list.curselection()
        if not sel:
            return
        idx = sel[0]
        if idx >= len(self._all_scripts):
            return
        key, meta = self._all_scripts[idx]
        self._current_key = key
        _clear_output(self.detail_output)
        _append(self.detail_output, "title: " + meta['title'] + "\n")
        _append(self.detail_output, "=" * 50 + "\n")
        _append(self.detail_output, "category: " + meta['category'] + "\n")
        _append(self.detail_output, "desc: " + meta['description'] + "\n")
        _append(self.detail_output, "usage: " + meta['usage'] + "\n")
        _append(self.detail_output, "input: " + meta['input_type'] + " -> output: " + meta['output_type'] + "\n")
        if meta["deps"]:
            from ...scripts.deps import check_dep
            _append(self.detail_output, "\ndep status:\n")
            all_ok = True
            for d in meta["deps"]:
                ok = check_dep(d)
                icon = "  ok" if ok else "  MISS"
                _append(self.detail_output, icon + " " + d + "\n")
                if not ok:
                    all_ok = False
            if all_ok:
                self.install_btn.pack_forget()
            else:
                self.install_btn.pack(side=tk.LEFT, padx=(0, 8))
        else:
            _append(self.detail_output, "\nzero deps\n")
            self.install_btn.pack_forget()

    def _run_selected(self):
        if not self._current_key:
            _clear_output(self.detail_output)
            _append(self.detail_output, "select a script first")
            return
        try:
            from ...scripts.runner import run_script as _run
            meta = None
            for k, m in self._all_scripts:
                if k == self._current_key:
                    meta = m
                    break
            _clear_output(self.detail_output)
            title = meta['title'] if meta else self._current_key
            _append(self.detail_output, "running: " + title + "\n")
            _append(self.detail_output, "=" * 50 + "\n\n")
            result = _run(self._current_key)
            if result["stdout"]:
                _append(self.detail_output, result["stdout"])
            if result["stderr"]:
                _append(self.detail_output, "\nerr:\n" + result['stderr'])
            if result["success"]:
                _append(self.detail_output, "\n" + "=" * 50 + "\nOK")
            else:
                _append(self.detail_output, "\n" + "=" * 50 + "\nFAIL code=" + str(result['exit_code']))
        except Exception as e:
            _clear_output(self.detail_output)
            _append(self.detail_output, "error: " + str(e))

    def _check_deps(self):
        _clear_output(self.detail_output)
        _append(self.detail_output, "checking deps...\n")
        _append(self.detail_output, "=" * 50 + "\n\n")
        try:
            from ...scripts.deps import check_all_deps
            status = check_all_deps()
            if not status:
                _append(self.detail_output, "all zero-dependency\n")
                self.dep_status_label.configure(text="all zero-deps", fg=GREEN)
                return
            total = 0
            missing = 0
            for key, info in status.items():
                ok = "OK" if info["all_ok"] else "MISS"
                _append(self.detail_output, ok + " " + info['meta']['title'] + "\n")
                total += 1
                for d in info["deps"]:
                    icon = "    ok" if d["installed"] else "    MISS"
                    _append(self.detail_output, icon + " " + d['name'] + "\n")
                if not info["all_ok"]:
                    missing += 1
                _append(self.detail_output, "\n")
            if missing == 0:
                _append(self.detail_output, "\nall " + str(total) + " OK")
                self.dep_status_label.configure(text="all " + str(total) + " OK", fg=GREEN)
            else:
                _append(self.detail_output, "\n" + str(missing) + "/" + str(total) + " MISS")
                self.dep_status_label.configure(text=str(missing) + "/" + str(total) + " MISS", fg=YELLOW)
        except Exception as e:
            _append(self.detail_output, "check failed: " + str(e))

    def _install_all_deps(self):
        _clear_output(self.detail_output)
        _append(self.detail_output, "installing missing deps...\n")
        _append(self.detail_output, "=" * 50 + "\n\n")
        import threading

        def run():
            try:
                from ...scripts.deps import get_missing_deps, install_all_missing
                missing = get_missing_deps()
                if not missing:
                    _append(self.detail_output, "all installed\n")
                    self.dep_status_label.configure(text="all installed", fg=GREEN)
                    return
                pkgs = ", ".join(sorted(missing))
                _append(self.detail_output, "installing " + str(len(missing)) + ": " + pkgs + "\n\n")
                _append(self.detail_output, "please wait... pip is running\n")
                results = install_all_missing()
                ok_count = 0
                for r in results:
                    icon = "OK" if r["success"] else "FAIL"
                    msg = r['message']
                    if isinstance(msg, bytes):
                        msg = msg.decode('utf-8', errors='replace')
                    _append(self.detail_output, icon + " " + r['dep'] + ": " + msg + "\n")
                    if r["success"]:
                        ok_count += 1
                _append(self.detail_output, "\n" + "=" * 50 + "\n")
                if ok_count == len(results):
                    _append(self.detail_output, "all " + str(ok_count) + " installed")
                    self.dep_status_label.configure(text="all installed", fg=GREEN)
                else:
                    _append(self.detail_output, str(ok_count) + "/" + str(len(results)) + " OK")
                self._populate_list()
            except Exception as e:
                _append(self.detail_output, "install failed: " + str(e))
        t = threading.Thread(target=run, daemon=True)
        t.start()

    def _install_script_deps(self):
        if not self._current_key:
            return
        try:
            from ...scripts.deps import install_deps_for_script
            from ...scripts.registry import get_script
            meta = get_script(self._current_key)
            if not meta or not meta["deps"]:
                return
            _clear_output(self.detail_output)
            _append(self.detail_output, "installing '" + meta['title'] + "' deps: " + ", ".join(meta['deps']) + "\n")
            _append(self.detail_output, "=" * 50 + "\n\n")
            _append(self.detail_output, "please wait... pip is running\n")
        except Exception as e:
            _append(self.detail_output, "prep error: " + str(e))
            return
        import threading

        def run():
            try:
                from ...scripts.deps import install_deps_for_script
                results = install_deps_for_script(self._current_key)
                ok_count = 0
                for r in results:
                    icon = "OK" if r["success"] else "FAIL"
                    msg = r['message']
                    if isinstance(msg, bytes):
                        msg = msg.decode('utf-8', errors='replace')
                    _append(self.detail_output, icon + " " + r['dep'] + ": " + msg + "\n")
                    if r["success"]:
                        ok_count += 1
                _append(self.detail_output, "\n" + "=" * 50 + "\n")
                if ok_count == len(results):
                    _append(self.detail_output, "done, ready to run")
                sel = self.script_list.curselection()
                if sel:
                    self._on_select(None)
                self._populate_list()
            except Exception as e:
                _append(self.detail_output, "install failed: " + str(e))
        t = threading.Thread(target=run, daemon=True)
        t.start()

    def _solve_url(self):
        url = self.url_entry.get().strip()
        if not url or url == "http://":
            _clear_output(self.detail_output)
            _append(self.detail_output, "Enter a target URL and click Solve\n")
            return
        self.solve_btn.configure(text="Running...", state="disabled", bg=RED)
        _clear_output(self.detail_output)
        _append(self.detail_output, "Target: " + url + "\n")
        _append(self.detail_output, "=" * 50 + "\n\n")
        import threading

        def run():
            try:
                from ...scripts.solver import solve_web

                def progress(step, status, detail):
                    if status == "flag!":
                        _append(self.detail_output, "\nFLAG: " + detail + "\n")

                    elif status == "running":
                        _append(self.detail_output, step + " " + detail + "\n")

                    else:
                        s = "> " if status == "ok" else "x "

                        _append(self.detail_output, s + step + ": " + detail + "\n")
                result = solve_web(url, progress_callback=progress)
                _append(self.detail_output, "\n" + "=" * 50 + "\n")
                if result["flag"]:
                    _append(self.detail_output, "FLAG: " + result["flag"] + "\n")
                else:
                    _append(self.detail_output, "No flag found - try other tabs or manual scripts\n")
            except Exception as e:
                _append(self.detail_output, "Error: " + str(e) + "\n")
            self.solve_btn.configure(text="Solve", state="normal", bg=ACCENT)
        t = threading.Thread(target=run, daemon=True)
        t.start()
