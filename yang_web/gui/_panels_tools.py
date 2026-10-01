# -*- coding: utf-8 -*-
"""gui._panels_tools -- Shell/stego/scripts/docs panels and the JS challenge game.

从 yang_web/gui.py 机械拆分而来（相对导入升一层）, 行为等价。
"""

from ._deps import (HAS_STEGO, JSChallengeSolver, _REPO_ROOT, analyze_file, analyze_png, extract_lsb, generate_reverse_shell, generate_webshell, identify_cipher_text, list_shell_languages, list_webshell_types, os, read_exif, scrolledtext, tk, ttk)
from ._theme import (ACCENT, BG, BORDER, DARK, FG, GREEN, INPUT_BG, RED, YELLOW)
from ._widgets import (_append, _clear_output, _label, _output_area)



# ═══════════════════════════════════════════════════════════
#  v2.0 新面板: Shell 生成器
# ═══════════════════════════════════════════════════════════

class ShellPanel(tk.Frame):
    """Reverse Shell & WebShell 生成器."""
    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        _label(self, "Shell 生成器", fg=ACCENT, font_size=16, bold=True, pady=8)
        _label(self, "反弹Shell (12种语言) | WebShell (PHP/ASP/JSP/Node.js)", fg=YELLOW, font_size=9)

        rev_frame = tk.LabelFrame(self, text=" 反弹Shell ", bg=BG, fg=ACCENT,
                                   font=("Microsoft YaHei UI", 11))
        rev_frame.pack(fill=tk.X, padx=4, pady=4)

        row1 = tk.Frame(rev_frame, bg=BG)
        row1.pack(fill=tk.X, padx=4, pady=4)
        tk.Label(row1, text="语言:", bg=BG, fg=ACCENT).pack(side=tk.LEFT)
        self.shell_lang = ttk.Combobox(row1,
            values=list_shell_languages() if HAS_STEGO else [], state="readonly", width=12)
        self.shell_lang.pack(side=tk.LEFT, padx=4)
        if HAS_STEGO and list_shell_languages():
            self.shell_lang.set(list_shell_languages()[0])
        tk.Label(row1, text="IP:", bg=BG, fg=ACCENT).pack(side=tk.LEFT, padx=(8, 0))
        self.shell_ip = tk.Entry(row1, bg=INPUT_BG, fg=FG, insertbackground=ACCENT,
            relief="flat", font=("Cascadia Code", 10), width=18)
        self.shell_ip.pack(side=tk.LEFT, padx=4)
        self.shell_ip.insert(0, "10.0.0.1")
        tk.Label(row1, text="Port:", bg=BG, fg=ACCENT).pack(side=tk.LEFT, padx=(8, 0))
        self.shell_port = tk.Entry(row1, bg=INPUT_BG, fg=FG, insertbackground=ACCENT,
            relief="flat", font=("Cascadia Code", 10), width=7)
        self.shell_port.pack(side=tk.LEFT, padx=4)
        self.shell_port.insert(0, "4444")
        tk.Button(row1, text="Generate", command=self._gen_rev, bg=GREEN, fg=DARK,
            relief="flat", padx=12, pady=3, cursor="hand2",
            font=("Microsoft YaHei UI", 9, "bold")).pack(side=tk.LEFT, padx=(8, 0))

        ws_frame = tk.LabelFrame(self, text=" WebShell ", bg=BG, fg=ACCENT,
                                  font=("Microsoft YaHei UI", 11))
        ws_frame.pack(fill=tk.X, padx=4, pady=4)

        ws_row = tk.Frame(ws_frame, bg=BG)
        ws_row.pack(fill=tk.X, padx=4, pady=4)
        tk.Label(ws_row, text="类型:", bg=BG, fg=ACCENT).pack(side=tk.LEFT)
        ws_types = list_webshell_types() if HAS_STEGO else []
        self.ws_type = ttk.Combobox(ws_row, values=ws_types, state="readonly", width=20)
        self.ws_type.pack(side=tk.LEFT, padx=4)
        if ws_types:
            self.ws_type.set(ws_types[0])
        tk.Button(ws_row, text="Generate", command=self._gen_ws, bg=GREEN, fg=DARK,
            relief="flat", padx=12, pady=3, cursor="hand2",
            font=("Microsoft YaHei UI", 9, "bold")).pack(side=tk.LEFT, padx=(8, 0))

        _label(self, "输出:", pady=4)
        self.output_frame, self.output = _output_area(self, 18)
        self.output_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))

    def _gen_rev(self):
        _clear_output(self.output)
        if not HAS_STEGO:
            _append(self.output, "Shell 生成器未加载"); return
        lang = self.shell_lang.get()
        ip = self.shell_ip.get().strip()
        port_str = self.shell_port.get().strip()
        if not lang or not ip or not port_str:
            _append(self.output, "请填写语言/IP/端口"); return
        try:
            port = int(port_str)
        except ValueError:
            _append(self.output, "端口必须是数字"); return
        r = generate_reverse_shell(lang, ip, port)
        _append(self.output, r)

    def _gen_ws(self):
        _clear_output(self.output)
        if not HAS_STEGO:
            _append(self.output, "Shell 生成器未加载"); return
        ws = self.ws_type.get()
        if not ws:
            _append(self.output, "请选择WebShell类型"); return
        r = generate_webshell(ws)
        _append(self.output, r)



# ═══════════════════════════════════════════════════════════
#  v2.0 新面板: 隐写 & 文件分析
# ═══════════════════════════════════════════════════════════

class StegoPanel(tk.Frame):
    """隐写 & 文件分析面板."""
    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        _label(self, "隐写 & 文件分析", fg=ACCENT, font_size=16, bold=True, pady=8)
        _label(self, "PNG分析 | LSB提取 | EXIF | 文件头识别 | 密文特征检测",
               fg=YELLOW, font_size=9)

        file_frame = tk.Frame(self, bg=DARK)
        file_frame.pack(fill=tk.X, padx=4, pady=4)
        tk.Label(file_frame, text="文件路径:", bg=DARK, fg=ACCENT,
            font=("Microsoft YaHei UI", 10)).pack(side=tk.LEFT, padx=6, pady=6)
        self.file_path = tk.Entry(file_frame, bg=INPUT_BG, fg=FG, insertbackground=ACCENT,
            relief="flat", font=("Cascadia Code", 10))
        self.file_path.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4, ipady=3)

        btn_row = tk.Frame(self, bg=BG)
        btn_row.pack(anchor="w", padx=4, pady=4)
        for lbl, cmd in [
            ("PNG分析", self._png), ("LSB提取", self._lsb),
            ("EXIF", self._exif), ("文件分析", self._file_analyze),
        ]:
            tk.Button(btn_row, text=lbl, command=cmd, bg=INPUT_BG, fg=FG,
                relief="flat", padx=10, pady=4, cursor="hand2",
                font=("Microsoft YaHei UI", 9)).pack(side=tk.LEFT, padx=2)

        ident_frame = tk.LabelFrame(self, text=" 密文特征识别 ", bg=BG, fg=ACCENT)
        ident_frame.pack(fill=tk.X, padx=4, pady=4)
        _label(ident_frame, "粘贴密文自动识别:", pady=2)
        self.ident_text = scrolledtext.ScrolledText(ident_frame, height=3, bg=INPUT_BG, fg=FG,
            insertbackground=ACCENT, relief="flat", font=("Cascadia Code", 11), wrap=tk.WORD)
        self.ident_text.pack(fill=tk.X, padx=4, pady=(0, 4))
        tk.Button(ident_frame, text="识别", command=self._identify, bg=ACCENT, fg=DARK,
            relief="flat", padx=12, pady=3, cursor="hand2",
            font=("Microsoft YaHei UI", 9, "bold")).pack(anchor="w", padx=4, pady=(0, 4))

        _label(self, "结果:", pady=4)
        self.output_frame, self.output = _output_area(self, 16)
        self.output_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))

    def _get_path(self):
        return self.file_path.get().strip()

    def _png(self):
        _clear_output(self.output)
        if not HAS_STEGO:
            _append(self.output, "分析引擎未加载"); return
        _append(self.output, analyze_png(self._get_path()))

    def _lsb(self):
        _clear_output(self.output)
        if not HAS_STEGO:
            _append(self.output, "分析引擎未加载"); return
        _append(self.output, extract_lsb(self._get_path()))

    def _exif(self):
        _clear_output(self.output)
        if not HAS_STEGO:
            _append(self.output, "分析引擎未加载"); return
        _append(self.output, read_exif(self._get_path()))

    def _file_analyze(self):
        _clear_output(self.output)
        if not HAS_STEGO:
            _append(self.output, "分析引擎未加载"); return
        _append(self.output, analyze_file(self._get_path()))

    def _identify(self):
        _clear_output(self.output)
        if not HAS_STEGO:
            _append(self.output, "分析引擎未加载"); return
        text = self.ident_text.get("1.0", tk.END).strip()
        if not text:
            _append(self.output, "请先粘贴密文"); return
        _append(self.output, identify_cipher_text(text))



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
            from ..scripts.registry import SCRIPTS, CATEGORIES
            from ..scripts.deps import check_dep
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
            from ..scripts.deps import check_dep
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
            from ..scripts.runner import run_script as _run
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
            from ..scripts.deps import check_all_deps
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
                from ..scripts.deps import get_missing_deps, install_all_missing
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
            from ..scripts.deps import install_deps_for_script
            from ..scripts.registry import get_script
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
                from ..scripts.deps import install_deps_for_script
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
                from ..scripts.solver import solve_web

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



# ═══════════════════════════════════════════════════════════

#  CTF 知识文档面板

# ═══════════════════════════════════════════════════════════


class DocsPanel(tk.Frame):
    """CTF 解题指南：分类速查 + 邪修心法."""
    _DOCS_ROOT = os.path.join(_REPO_ROOT, "docs", "ctf-guide")
    _DOCS = [
        ("📋 索引导航", "README.md", ""),
        ("🏴‍☠️ 邪修速查", "CTF-CheatSheet.md", ""),
        ("", "", ""),  # separator
        ("🔵 Web 安全", "ctf-web.md", "源码泄露·文件包含·SQL注入·SSTI·SSRF·JWT·反序列化"),
        ("🟡 密码学", "ctf-crypto.md", "RSA攻击·AES模式·ECC·Lattice·古典密码·编码识别"),
        ("🔴 逆向工程", "ctf-reverse.md", "IDA·angr·Z3·脱壳·APK·反调试"),
        ("🟣 Pwn", "ctf-pwn.md", "栈溢出·ROP·堆利用·格式化字符串·ret2libc"),
        ("🟠 取证隐写", "ctf-forensics.md", "LSB·频谱图·Wireshark·Volatility·文件修复"),
        ("🟢 Misc", "ctf-misc.md", "PyJail·条件竞争·网络协议隐写·编码解码"),
        ("⚫ OSINT", "ctf-osint.md", "Google Dorks·图片反查·Maltego·地理位置"),
        ("🔴 恶意软件", "ctf-malware.md", "LOLBAS·Cobalt Strike·DLL劫持·无文件"),
        ("🤖 AI/ML", "ctf-aiml.md", "模型逆向·对抗样本·LangChain·GGUF"),
    ]

    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self._content_cache = {}

        # ── 标题 ──
        _label(self, "📚 CTF 解题指南  ·  九大方向 + 邪修速查",
               fg=ACCENT, font_size=16, bold=True, pady=8)

        # ── 左右分割面板 ──
        panes = tk.PanedWindow(self, orient=tk.HORIZONTAL,
                               bg=BORDER, sashwidth=3)
        panes.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        # ── 左侧 — 文档列表 ──
        list_frame = tk.Frame(panes, bg=DARK)
        panes.add(list_frame, width=200)

        tk.Label(list_frame, text="文档列表", bg=DARK, fg=FG,
                 font=("Microsoft YaHei UI", 10, "bold")).pack(
                     anchor="w", padx=10, pady=(8, 4))

        # 可滚动的按钮列表
        list_canvas = tk.Canvas(list_frame, bg=DARK, highlightthickness=0)
        list_sb = tk.Scrollbar(list_frame, orient="vertical",
                               command=list_canvas.yview)
        self._list_inner = tk.Frame(list_canvas, bg=DARK)
        self._list_inner.bind("<Configure>",
            lambda e: list_canvas.configure(
                scrollregion=list_canvas.bbox("all")))
        list_canvas.create_window((0, 0), window=self._list_inner,
                                   anchor="nw", width=190)
        list_canvas.configure(yscrollcommand=list_sb.set)
        list_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        list_sb.pack(side=tk.RIGHT, fill=tk.Y)

        def _mw_list(event):
            list_canvas.yview_scroll(int(-event.delta / 120), "units")
        list_canvas.bind("<Enter>", lambda e: list_canvas.bind_all(
            "<MouseWheel>", _mw_list))
        list_canvas.bind("<Leave>", lambda e: list_canvas.unbind_all(
            "<MouseWheel>"))

        self._doc_buttons = []
        for name, filename, desc in self._DOCS:
            if not name:
                # 分隔线
                tk.Frame(self._list_inner, bg=BORDER,
                         height=1).pack(fill=tk.X, padx=8, pady=8)
                continue
            btn = tk.Button(self._list_inner, text=name,
                            bg=DARK, fg=FG, anchor="w", relief="flat",
                            font=("Microsoft YaHei UI", 10),
                            padx=12, pady=5, cursor="hand2",
                            activebackground=INPUT_BG, activeforeground=ACCENT)
            btn.pack(fill=tk.X, padx=4, pady=1)
            btn.bind("<Button-1>", lambda e, fn=filename: self._load_doc(fn))
            btn.bind("<Enter>", lambda e, b=btn: b.configure(
                bg=INPUT_BG, fg=ACCENT))
            btn.bind("<Leave>", lambda e, b=btn: b.configure(
                bg=DARK, fg=FG))
            self._doc_buttons.append(btn)

        # ── 右侧 — 文档内容 ──
        detail_frame = tk.Frame(panes, bg=BG)
        panes.add(detail_frame, width=650)

        # 当前文档标题
        self._doc_title = tk.Label(detail_frame, text="",
                                   bg=BG, fg=ACCENT,
                                   font=("Microsoft YaHei UI", 13, "bold"))
        self._doc_title.pack(anchor="w", padx=12, pady=(6, 2))

        # 可滚动的文本区
        detail_bg = "#1e1e2e"
        self._doc_area = scrolledtext.ScrolledText(
            detail_frame, wrap=tk.WORD, bg=detail_bg,
            fg=FG, insertbackground=ACCENT,
            font=("Cascadia Code", 10),
            relief="flat", bd=0,
            selectbackground=ACCENT, selectforeground=DARK,
            padx=14, pady=10)
        self._doc_area.pack(fill=tk.BOTH, expand=True)
        self._doc_area.configure(state=tk.DISABLED)

        # 右侧鼠标滚轮
        def _mw_right(event):
            self._doc_area.yview_scroll(int(-event.delta / 120), "units")
        self._doc_area.bind("<Enter>", lambda e: self._doc_area.bind_all(
            "<MouseWheel>", _mw_right))
        self._doc_area.bind("<Leave>", lambda e: self._doc_area.unbind_all(
            "<MouseWheel>"))

        # 默认加载速查表
        self.after(200, lambda: self._load_doc("CTF-CheatSheet.md"))

    def _load_doc(self, filename):
        """加载并显示文档内容."""
        if filename in self._content_cache:
            content = self._content_cache[filename]
        else:
            path = os.path.join(self._DOCS_ROOT, filename)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                self._content_cache[filename] = content
            except FileNotFoundError:
                content = f"# 文件未找到\n\n{path}"

        self._doc_area.configure(state=tk.NORMAL)
        self._doc_area.delete("1.0", tk.END)
        self._doc_area.insert("1.0", content)

        # 标题
        for name, fn, desc in self._DOCS:
            if fn == filename:
                self._doc_title.configure(text=f"📖 {name}")
                break
        else:
            self._doc_title.configure(text=f"📖 {filename}")

        self._doc_area.configure(state=tk.DISABLED)

        # 高亮当前按钮
        for btn in self._doc_buttons:
            btn.configure(bg=DARK, fg=FG)



class JSGamePanel(tk.Frame):
    """JS/游戏挑战分析面板 — URL→自动提取Flag+作弊码+控制台命令."""

    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self._analyzing = False

        _label(self, "🎮 JS/游戏挑战分析器  —  Flag提取+作弊码+控制台命令",
               fg=ACCENT, font_size=16, bold=True, pady=8)

        # URL输入
        url_row = tk.Frame(self, bg=BG)
        url_row.pack(fill=tk.X, padx=10, pady=(4, 2))
        tk.Label(url_row, text="URL:", bg=BG, fg=FG, font=("Microsoft YaHei UI", 11)).pack(side=tk.LEFT, padx=(0, 6))
        self.url_entry = tk.Entry(url_row, bg=INPUT_BG, fg=FG, insertbackground=FG,
            font=("Cascadia Code", 10), relief="flat", bd=1)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.url_entry.bind("<Return>", lambda e: self._analyze())
        tk.Button(url_row, text="📋 Paste", command=self._paste,
            bg=INPUT_BG, fg=FG, font=("Microsoft YaHei UI", 9),
            padx=10, cursor="hand2", relief="flat").pack(side=tk.LEFT, padx=(6, 4))
        tk.Button(url_row, text="🔍 分析", command=self._analyze,
            bg=ACCENT, fg=DARK, font=("Microsoft YaHei UI", 10, "bold"),
            padx=16, pady=4, cursor="hand2", relief="flat").pack(side=tk.LEFT)

        self.status_label = tk.Label(self, text="💡 粘贴JS/游戏题URL，点「分析」或按Enter",
            bg=BG, fg=BORDER, font=("Microsoft YaHei UI", 9))
        self.status_label.pack(anchor="w", padx=12, pady=(2, 0))

        # 结果区
        result_outer = tk.Frame(self, bg=BG)
        result_outer.pack(fill=tk.BOTH, expand=True, padx=4)
        self.result_text = scrolledtext.ScrolledText(result_outer,
            bg=DARK, fg=FG, insertbackground=FG,
            font=("Cascadia Code", 9), wrap=tk.WORD, relief="flat", bd=0)
        self.result_text.pack(fill=tk.BOTH, expand=True)

    def _paste(self):
        try:
            text = self.clipboard_get()
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, text.strip())
        except Exception:
            pass

    def _log(self, msg):
        self.result_text.insert(tk.END, msg + "\n")
        self.result_text.see(tk.END)
        self.result_text.update_idletasks()

    def _analyze(self):
        if self._analyzing:
            return
        url = self.url_entry.get().strip()
        if not url:
            self._log("⚠ 请输入URL")
            return

        self._analyzing = True
        self.result_text.delete("1.0", tk.END)
        self.status_label.config(text="🔍 正在分析JS...", fg=YELLOW)

        import threading
        def _run():
            try:
                solver = JSChallengeSolver(verbose=False)
                report = solver.analyze(url)
                self.after(0, lambda: self._show_result(report))
            except Exception as e:
                import traceback as _tb
                self.after(0, lambda: self._on_error(str(e) + "\n" + _tb.format_exc()))
        threading.Thread(target=_run, daemon=True).start()

    def _show_result(self, report):
        self._log("=" * 60)
        if report.title:
            self._log(f"  页面: {report.title}")
        if report.game_type != "unknown":
            self._log(f"  游戏类型: {report.game_type}")
        self._log(f"  摘要: {report.summary}")
        self._log("=" * 60)

        if report.flags_found:
            self._log(f"\n🏁 Flag ({len(report.flags_found)}):")
            for f in report.flags_found:
                self._log(f"  ✅ {f}")

        if report.cheat_codes:
            self._log(f"\n🎮 作弊码:")
            for c in report.cheat_codes:
                self._log(f"  🔑 {c}")

        if report.console_commands:
            self._log(f"\n💻 浏览器控制台命令 (F12 → Console 粘贴):")
            for c in report.console_commands:
                # 不显示注释行
                if not c.strip().startswith("//"):
                    self._log(f"  > {c}")
            self._log(f"\n  # 也可复制全部命令自动执行")
            for c in report.console_commands:
                self._log(f"  {c}")

        if report.js_files:
            self._log(f"\n📜 JS 文件:")
            for f in report.js_files:
                self._log(f"  {f.split('/')[-1]}")

        if report.api_endpoints:
            self._log(f"\n🌐 API 端点:")
            for e in report.api_endpoints:
                self._log(f"  {e}")

        self._analyzing = False
        ok = bool(report.flags_found)
        self.status_label.config(
            text=f"{'✅' if ok else '⚠'} 分析完成 | {'Flag已获取' if ok else '未发现Flag'}",
            fg=GREEN if ok else YELLOW)

    def _on_error(self, msg):
        self._log(f"\n❌ 错误: {msg[:500]}")
        self._analyzing = False
        self.status_label.config(text="❌ 分析异常", fg=RED)
