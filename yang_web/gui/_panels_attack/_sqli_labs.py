"""yang_web.gui._panels_attack 子模块 _sqli_labs（自 _panels_attack.py 拆分，请勿手工重排）。"""

from .._deps import (LESSON_DB, SQLLabsEngine, scrolledtext, time, tk, ttk)
from .._theme import (ACCENT, BG, BORDER, DARK, FG, GREEN, INPUT_BG, RED, YELLOW)
from .._widgets import (_label)





class SQLLabsPanel(tk.Frame):
    """SQLi-LABS 靶场专项面板：关卡选择→自动注入→提取数据."""

    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self.engine = None
        self._solving = False

        # ── 标题 ──
        _label(self, "🔫 SQLi-LABS 专项求解器  —  65+关卡自动注入+数据提取",
               fg=ACCENT, font_size=16, bold=True, pady=8)

        # ── 靶场URL配置 ──
        url_row = tk.Frame(self, bg=BG)
        url_row.pack(fill=tk.X, padx=10, pady=(4, 2))
        tk.Label(url_row, text="靶场:", bg=BG, fg=FG, font=("Microsoft YaHei UI", 11)).pack(side=tk.LEFT, padx=(0, 6))
        self.url_entry = tk.Entry(url_row, bg=INPUT_BG, fg=FG, insertbackground=FG,
            font=("Cascadia Code", 10), relief="flat", bd=1)
        self.url_entry.insert(0, "http://80-d81dd610-1f3d-45b2-bccd-cf64012932fd.challenge.ctfplus.cn")
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # ── 关卡选择行 ──
        select_row = tk.Frame(self, bg=BG)
        select_row.pack(fill=tk.X, padx=10, pady=(6, 2))

        tk.Label(select_row, text="关卡:", bg=BG, fg=FG, font=("Microsoft YaHei UI", 11)).pack(side=tk.LEFT, padx=(0, 6))
        self.lesson_entry = tk.Entry(select_row, bg=INPUT_BG, fg=FG, insertbackground=FG,
            font=("Cascadia Code", 11), width=6, relief="flat", bd=1)
        self.lesson_entry.insert(0, "1")
        self.lesson_entry.pack(side=tk.LEFT, padx=(0, 6))
        self.lesson_entry.bind("<Return>", lambda e: self._solve_one())

        tk.Label(select_row, text="~", bg=BG, fg=FG, font=("Microsoft YaHei UI", 11)).pack(side=tk.LEFT, padx=(0, 6))
        self.end_entry = tk.Entry(select_row, bg=INPUT_BG, fg=FG, insertbackground=FG,
            font=("Cascadia Code", 11), width=6, relief="flat", bd=1)
        self.end_entry.insert(0, "65")
        self.end_entry.pack(side=tk.LEFT, padx=(0, 12))

        # 按钮
        self.solve_btn = tk.Button(select_row, text="🚀 求解当前关", command=self._solve_one,
            bg=ACCENT, fg=DARK, font=("Microsoft YaHei UI", 10, "bold"),
            padx=14, pady=4, cursor="hand2", relief="flat")
        self.solve_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.batch_btn = tk.Button(select_row, text="📦 批量求解", command=self._solve_batch,
            bg="#9933CC", fg="#ffffff", font=("Microsoft YaHei UI", 10, "bold"),
            padx=14, pady=4, cursor="hand2", relief="flat")
        self.batch_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.list_btn = tk.Button(select_row, text="📋 关卡列表", command=self._list_lessons,
            bg=INPUT_BG, fg=FG, font=("Microsoft YaHei UI", 10),
            padx=12, pady=4, cursor="hand2", relief="flat")
        self.list_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.stop_btn = tk.Button(select_row, text="⏹ 停止", command=self._stop,
            bg="#CC3333", fg="#ffffff", font=("Microsoft YaHei UI", 10),
            padx=12, pady=4, cursor="hand2", relief="flat", state="disabled")
        self.stop_btn.pack(side=tk.LEFT)

        # ── 状态栏 ──
        self.status_label = tk.Label(self, text="💡 输入关卡号，点「求解当前关」或按Enter开始",
            bg=BG, fg=BORDER, font=("Microsoft YaHei UI", 9))
        self.status_label.pack(anchor="w", padx=12, pady=(4, 0))

        # ── 进度条 ──
        self.progress = ttk.Progressbar(self, mode="determinate", length=800)
        self.progress.pack(fill=tk.X, padx=12, pady=(4, 0))

        # ── 结果区 ──
        result_outer = tk.Frame(self, bg=BG)
        result_outer.pack(fill=tk.BOTH, expand=True, padx=4)
        self.result_text = scrolledtext.ScrolledText(result_outer,
            bg=DARK, fg=FG, insertbackground=FG,
            font=("Cascadia Code", 9), wrap=tk.WORD, relief="flat", bd=0)
        self.result_text.pack(fill=tk.BOTH, expand=True)

    def _get_engine(self):
        url = self.url_entry.get().strip()
        if not self.engine or self.engine.base_url != url.rstrip("/"):
            self.engine = SQLLabsEngine(url, verbose=False)
        return self.engine

    def _log(self, msg):
        self.result_text.insert(tk.END, msg + "\n")
        self.result_text.see(tk.END)
        self.result_text.update_idletasks()

    def _solve_one(self):
        if self._solving:
            return
        try:
            num = int(self.lesson_entry.get().strip())
        except ValueError:
            self._log("⚠ 请输入有效的关卡号")
            return

        self._start_solve()
        import threading
        def _run():
            try:
                engine = self._get_engine()
                # Override verbose for GUI output
                original_verbose = engine.verbose
                engine.verbose = False
                r = engine.solve_lesson(num)
                engine.verbose = original_verbose
                self.after(0, lambda: self._show_single_result(r))
            except Exception as e:
                import traceback as _tb
                self.after(0, lambda: self._on_error(str(e) + "\n" + _tb.format_exc()))
        threading.Thread(target=_run, daemon=True).start()

    def _solve_batch(self):
        if self._solving:
            return
        try:
            start = int(self.lesson_entry.get().strip())
            end = int(self.end_entry.get().strip())
        except ValueError:
            self._log("⚠ 请输入有效的关卡范围")
            return

        self._start_solve()
        import threading
        def _run():
            results = []
            total_lessons = [n for n in range(start, end + 1) if n in LESSON_DB]
            engine = self._get_engine()
            for i, num in enumerate(total_lessons):
                if not self._solving:
                    break
                pct = int((i / len(total_lessons)) * 100)
                self.after(0, lambda p=pct, n=num, idx=i+1, tot=len(total_lessons):
                    self._update_progress(f"Less-{n} ({idx}/{tot})...", p))
                try:
                    engine.verbose = False
                    r = engine.solve_lesson(num)
                    results.append(r)
                except Exception as e:
                    results.append({"lesson": num, "success": False, "error": str(e)})
                if not self._solving:
                    break
                time.sleep(0.3)
            solved = sum(1 for r in results if r.get("success"))
            flags = [r.get("flag") for r in results if r.get("flag")]
            self.after(0, lambda: self._show_batch_result(results, solved, flags))
        threading.Thread(target=_run, daemon=True).start()

    def _list_lessons(self):
        self._log("=" * 80)
        self._log(f"{'ID':>4}  {'类型':<18} {'方法':<7} {'难度':<6}  {'标题'}")
        self._log("-" * 80)
        for num in sorted(LESSON_DB.keys()):
            if num % 10 == 0:
                self._log("-" * 80)
            l = LESSON_DB[num]
            diff = "⭐" * l.difficulty
            self._log(f"{num:>4}  {l.injection_type:<18} {l.method:<7} {diff:<7} {l.title}")
        self._log("=" * 80)

    def _start_solve(self):
        self._solving = True
        self.solve_btn.config(state="disabled", text="⏳ 求解中...")
        self.batch_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.progress["value"] = 0
        self.status_label.config(text="⏳ 正在求解...", fg=YELLOW)

    def _stop(self):
        self._solving = False
        self.solve_btn.config(state="normal", text="🚀 求解当前关")
        self.batch_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_label.config(text="⏹ 已停止", fg=BORDER)
        self._log("\n⏹ 求解已停止")

    def _update_progress(self, msg, pct):
        self.progress["value"] = pct
        self.status_label.config(text=msg, fg=YELLOW)

    def _finish_solve(self, msg, ok=True):
        self._solving = False
        self.solve_btn.config(state="normal", text="🚀 求解当前关")
        self.batch_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.progress["value"] = 100
        self.status_label.config(text=msg, fg=GREEN if ok else RED)

    def _show_single_result(self, r):
        self._log("=" * 60)
        self._log(f"  Lesson: Less-{r.get('lesson', '?')}")
        self._log(f"  Title: {r.get('title', '?')}")
        self._log(f"  Success: {'✅' if r.get('success') else '❌'}")
        self._log(f"  Quote Type: {r.get('quote_type', '?')}")
        self._log("-" * 60)
        if r.get("flag"):
            self._log(f"  🏁 Flag: {r['flag']}")
        if r.get("database"):
            self._log(f"  📦 Database: {r['database']}")
        if r.get("tables"):
            tables = r["tables"]
            self._log(f"  📊 Tables ({len(tables)}): {', '.join(tables[:15])}" + ("..." if len(tables) > 15 else ""))
        if r.get("data"):
            self._log("  📋 Data:")
            for k, v in r["data"].items():
                self._log(f"    {k}: {v[:120]}")
        if r.get("columns"):
            self._log("  🗂 Columns:")
            for tbl, cols in r["columns"].items():
                self._log(f"    {tbl}: {', '.join(cols)}")
        if r.get("error"):
            self._log(f"  ⚠ Error: {r['error']}")
        self._log("=" * 60)
        ok = r.get("success", False)
        flag = r.get("flag", "")
        msg = f"✅ Less-{r.get('lesson','?')} 完成" + (f" | Flag: {flag}" if flag else "")
        self._finish_solve(msg, ok)

    def _show_batch_result(self, results, solved, flags):
        self._log("=" * 60)
        self._log(f"  批量求解完成: {solved}/{len(results)} 成功")
        self._log("-" * 60)
        for r in results:
            icon = "✅" if r.get("success") else "❌"
            flag = r.get("flag", "")
            db = r.get("database", "")
            extra = f" | DB={db}" if db else ""
            extra += f" | Flag={flag}" if flag else ""
            self._log(f"  {icon} Less-{r.get('lesson','?'):>3}  {extra}")
        if flags:
            self._log("-" * 60)
            self._log(f"  🏁 Flags ({len(flags)}):")
            for f in flags:
                self._log(f"    {f}")
        self._log("=" * 60)
        msg = f"✅ 批量完成: {solved}/{len(results)} 成功"
        if flags:
            msg += f" | {len(flags)} flags"
        self._finish_solve(msg, solved > 0)

    def _on_error(self, msg):
        self._log(f"\n❌ 错误: {msg[:500]}")
        self._finish_solve("❌ 求解异常", False)
