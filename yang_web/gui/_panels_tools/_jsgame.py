"""yang_web.gui._panels_tools 子模块 _jsgame（自 _panels_tools.py 拆分，请勿手工重排）。"""

from .._deps import (HAS_STEGO, JSChallengeSolver, _REPO_ROOT, analyze_file, analyze_png, extract_lsb, generate_reverse_shell, generate_webshell, identify_cipher_text, list_shell_languages, list_webshell_types, os, read_exif, scrolledtext, tk, ttk)
from .._theme import (ACCENT, BG, BORDER, DARK, FG, GREEN, INPUT_BG, RED, YELLOW)
from .._widgets import (_append, _clear_output, _label, _output_area)





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
