"""yang_web.gui._panels_attack 子模块 _url_attack（自 _panels_attack.py 拆分，请勿手工重排）。"""

from .._deps import (LESSON_DB, SQLLabsEngine, scrolledtext, time, tk, ttk)
from .._theme import (ACCENT, BG, BORDER, DARK, FG, GREEN, INPUT_BG, RED, YELLOW)
from .._widgets import (_label)






# ═══════════════════════════════════════════════════════════

#  主窗口

# ═══════════════════════════════════════════════════════════


class UrlAttackPanel(tk.Frame):
    """智能攻击面板：粘贴URL→自动分析→一键解题+读Flag."""

    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self._last_analyze_result = None

        # ── 标题 ──
        _label(self, "★ v10 ★ 粘贴URL→分析→🚀一键解题", fg=ACCENT, font_size=16, bold=True, pady=8)

        # ── URL输入行 ──
        url_row = tk.Frame(self, bg=BG)
        url_row.pack(fill=tk.X, padx=10, pady=(4, 2))
        tk.Label(url_row, text="URL:", bg=BG, fg=FG, font=("Microsoft YaHei UI", 11)).pack(side=tk.LEFT, padx=(0, 6))
        self.url_entry = tk.Entry(url_row, bg=INPUT_BG, fg=FG, insertbackground=FG,
            font=("Cascadia Code", 10), relief="flat", bd=1)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.url_entry.bind("<Return>", lambda e: self._analyze())
        tk.Button(url_row, text="📋 Paste", command=self._paste_url,
            bg=INPUT_BG, fg=FG, font=("Microsoft YaHei UI", 9),
            padx=10, cursor="hand2", relief="flat").pack(side=tk.LEFT, padx=(6, 4))
        tk.Button(url_row, text="🔍 分析", command=self._analyze,
            bg=ACCENT, fg=DARK, font=("Microsoft YaHei UI", 10, "bold"),
            padx=16, pady=4, cursor="hand2", relief="flat").pack(side=tk.LEFT)

        # ── 状态栏 ──
        self.status_label = tk.Label(self, text="💡 粘贴CTF题目URL，点「分析」或按Enter",
            bg=BG, fg=BORDER, font=("Microsoft YaHei UI", 9))
        self.status_label.pack(anchor="w", padx=12, pady=(2, 0))

        # ── 操作按钮行 (初始隐藏) ──
        self._btn_row = tk.Frame(self, bg=BG)
        self.auto_solve_btn = tk.Button(self._btn_row, text="🚀 一键解题 — 自动攻击+升级+读Flag",
            bg="#FF6600", fg="#ffffff", relief="flat", padx=18, pady=8, cursor="hand2",
            font=("Microsoft YaHei UI", 12, "bold"),
            command=self._auto_solve_clicked)
        self.auto_solve_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.deep_scan_btn = tk.Button(self._btn_row, text="🔬 深度扫描 — 字典爆破+端口+攻击链升级",
            bg="#9933CC", fg="#ffffff", relief="flat", padx=14, pady=8, cursor="hand2",
            font=("Microsoft YaHei UI", 11, "bold"),
            command=self._deep_scan_clicked)
        self.deep_scan_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.multi_stage_btn = tk.Button(self._btn_row, text="🔄 多阶段解题 — 弱口令→跳转→XXE→...全自动",
            bg="#009966", fg="#ffffff", relief="flat", padx=14, pady=8, cursor="hand2",
            font=("Microsoft YaHei UI", 11, "bold"),
            command=self._multi_stage_clicked)
        self.multi_stage_btn.pack(side=tk.LEFT)

        # ── Canvas结果区 ──
        canvas_outer = tk.Frame(self, bg=BG)
        canvas_outer.pack(fill=tk.BOTH, expand=True, padx=4)
        self.result_canvas = tk.Canvas(canvas_outer, bg=BG, highlightthickness=0)
        sb = tk.Scrollbar(canvas_outer, orient="vertical", command=self.result_canvas.yview)
        self.result_frame = tk.Frame(self.result_canvas, bg=BG)
        self.result_frame._canvas_win = self.result_canvas.create_window(
            (0, 0), window=self.result_frame, anchor="nw", width=800)
        self.result_frame.bind("<Configure>",
            lambda e: self.result_canvas.configure(scrollregion=self.result_canvas.bbox("all")))
        self.result_canvas.configure(yscrollcommand=sb.set)
        self.result_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        def _mw(event):
            self.result_canvas.yview_scroll(int(-event.delta / 120), "units")
        self.result_canvas.bind("<Enter>", lambda e: self.result_canvas.bind_all("<MouseWheel>", _mw))
        self.result_canvas.bind("<Leave>", lambda e: self.result_canvas.unbind_all("<MouseWheel>"))

    def _paste_url(self):
        try:
            text = self.clipboard_get()
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, text.strip())
            self.status_label.config(text="📋 已粘贴，点「分析」或按Enter", fg=YELLOW)
        except Exception:
            self.status_label.config(text="⚠️ 剪贴板为空", fg=RED)

    def _analyze(self):
        """分析URL."""
        url = self.url_entry.get().strip()
        if not url:
            self.status_label.config(text="⚠️ 请输入URL", fg=RED)
            return
        self.status_label.config(text="🔍 正在分析... (爬取+漏洞检测)", fg=YELLOW)
        self.url_entry.config(state="disabled")
        for w in self.result_frame.winfo_children():
            w.destroy()
        self._btn_row.pack_forget()
        self._refresh_canvas()

        import threading
        def _run():
            try:
                from ...core.url_analyzer import analyze_url
                result = analyze_url(url)
                self.after(0, lambda: self._on_analyze_done(result))
            except Exception as e:
                import traceback as _tb
                self.after(0, lambda: self._on_analyze_error(str(e) + "\n" + _tb.format_exc()))
        threading.Thread(target=_run, daemon=True).start()

    def _on_analyze_done(self, result):
        self.url_entry.config(state="normal")
        results = result.get("results", [])
        error = result.get("error")
        self._last_analyze_result = result
        if error:
            self.status_label.config(text=f"❌ {error}", fg=RED)
            _label(self.result_frame, f"分析失败: {error}", fg=RED, font_size=12, pady=20)
            self._refresh_canvas()
            return
        if not results:
            self.status_label.config(text="⚠️ 未检测到明显漏洞特征", fg=YELLOW)
            _label(self.result_frame, "未检测到明显漏洞特征\n\n可能原因:\n  · 页面无参数/表单\n  · 纯静态页面\n  · 不在支持范围内\n\n👇 仍可尝试一键解题（静态扫描Flag）",
                   fg=YELLOW, font_size=11, pady=20)
            self._refresh_canvas()
        else:
            self.status_label.config(text=f"✅ 发现 {len(results)} 种漏洞特征", fg=GREEN)
            self._render_results(result)
            self._refresh_canvas()

        # Always show action buttons (v3.5 supports deep scan)
        self._btn_row.pack(pady=(4, 12))
        self._refresh_canvas()

    def _on_analyze_error(self, msg):
        self.url_entry.config(state="normal")
        self.status_label.config(text="❌ 分析异常", fg=RED)
        _label(self.result_frame, f"分析异常:\n{msg[:500]}", fg=RED, font_size=10, pady=20)
        self._refresh_canvas()

    def _render_results(self, result):
        """渲染漏洞卡片."""
        for w in self.result_frame.winfo_children():
            w.destroy()
        results = result.get("results", [])
        url = result.get("url", "")
        for r in results:
            vtype = r.get("type", "???")
            conf = r.get("confidence", 50)
            params = r.get("params", [])
            payloads = r.get("payloads", [])
            tip = r.get("tip", "")
            # 卡片外框
            fc = tk.Frame(self.result_frame, bg=INPUT_BG,
                highlightthickness=1, highlightbackground=BORDER)
            fc.pack(fill=tk.X, padx=8, pady=(4, 2), ipady=6)
            # 标题行
            hf = tk.Frame(fc, bg=INPUT_BG)
            hf.pack(fill=tk.X, padx=10, pady=(6, 2))
            conf_color = "#00FF00" if conf >= 80 else ("#FFD700" if conf >= 50 else "#FF6600")
            conf_icon = "🔴" if conf >= 80 else ("🟡" if conf >= 50 else "🟢")
            tk.Label(hf, text=f"{conf_icon} {vtype}", bg=INPUT_BG, fg=conf_color,
                font=("Microsoft YaHei UI", 13, "bold")).pack(side=tk.LEFT)
            tk.Label(hf, text=f"  置信度: {conf}%", bg=INPUT_BG, fg=BORDER,
                font=("Microsoft YaHei UI", 9)).pack(side=tk.LEFT)
            param_str = ", ".join(params[:4]) if params else "自动"
            tk.Label(hf, text=f"  参数: {param_str}", bg=INPUT_BG, fg=FG,
                font=("Cascadia Code", 9)).pack(side=tk.LEFT, padx=(12, 0))
            # 说明
            if tip:
                tk.Label(fc, text=tip[:120], bg=INPUT_BG, fg=BORDER,
                    font=("Microsoft YaHei UI", 8), wraplength=740).pack(anchor="w", padx=14, pady=(0, 4))
            # Payload按钮行
            if payloads:
                pf = tk.Frame(fc, bg=INPUT_BG)
                pf.pack(fill=tk.X, padx=10, pady=(0, 6))
                for pdef in payloads[:10]:
                    self._make_payload_row(pf, pdef, url, params)
        # 显示操作按钮
        self._btn_row.pack(fill=tk.X, padx=12, pady=(4, 2))

    def _make_payload_row(self, parent, pdef, attack_url, params):
        """创建单个Payload的测试按钮行."""
        name = pdef.get("name", "payload")
        payload = pdef.get("payload", "")
        param = params[0] if params else ""
        row = tk.Frame(parent, bg=INPUT_BG)
        row.pack(fill=tk.X, pady=(2, 1))
        # 名称
        tk.Label(row, text=f"  💉 {name}", bg=INPUT_BG, fg=FG,
            font=("Microsoft YaHei UI", 9)).pack(side=tk.LEFT)
        # 复制
        def _cp(p=payload):
            self.clipboard_clear()
            self.clipboard_append(p)
            self.status_label.config(text="📋 Payload已复制", fg=GREEN)
        tk.Button(row, text="📋", command=_cp,
            bg=INPUT_BG, fg=FG, font=("Microsoft YaHei UI", 8),
            padx=8, cursor="hand2", relief="flat", bd=1).pack(side=tk.RIGHT, padx=(2, 0))
        # 发送 (保存引用防闭包bug)
        row._attack_url = attack_url
        row._attack_param = param
        row._attack_pdef = pdef
        tk.Button(row, text="🔍 发送",
            command=lambda r=row: self._do_attack(r._attack_pdef, r._attack_url, r._attack_param),
            bg="#FF6600", fg="#ffffff", font=("Microsoft YaHei UI", 8, "bold"),
            padx=10, pady=1, cursor="hand2", relief="flat").pack(side=tk.RIGHT, padx=(2, 8))

    def _do_attack(self, pdef, url, param):
        """执行单个攻击请求 + 显示结果."""
        name = pdef.get("name", "payload")
        payload_text = pdef.get("payload", "")
        if not param:
            # 尝试从URL提取
            from urllib.parse import urlparse, parse_qs
            qs = urlparse(url).query
            if qs:
                first_key = list(parse_qs(qs).keys())[0] if parse_qs(qs) else ""
                param = first_key
        if not url:
            self.status_label.config(text="❌ 无目标URL", fg=RED)
            return
        self.status_label.config(text=f"🚀 攻击中: {name}...", fg=YELLOW)
        import threading
        def _run():
            try:
                from ...core.url_analyzer import execute_attack
                rv = execute_attack(url, {"type": "", "params": [param], "payloads": [pdef]})
                attacks = rv.get("attacks", [])
                result_text = ""
                for a in attacks:
                    body = a.get("body", "")[:2000]
                    result_text += f"=== {a.get('payload_name', name)} ===\n"
                    result_text += f"HTTP {a.get('status', '?')} | {a.get('size', 0)}B | {a.get('time_ms', 0)}ms\n"
                    result_text += f"URL: {a.get('url', '')[:200]}\n"
                    result_text += body + "\n"
                self.after(0, lambda: self._show_attack_result(name, result_text))
            except Exception as e:
                self.after(0, lambda: self._show_attack_result(name, f"攻击异常: {e}"))
        threading.Thread(target=_run, daemon=True).start()

    def _show_attack_result(self, name, text):
        """在Canvas中显示单次攻击结果."""
        self.status_label.config(text=f"✅ 攻击完成: {name}", fg=GREEN)
        # 清除旧攻击结果
        kids = list(self.result_frame.winfo_children())
        for w in kids:
            if getattr(w, '_is_attack_resp', False):
                w.destroy()
        # 响应框
        rf = tk.Frame(self.result_frame, bg=INPUT_BG,
            highlightthickness=1, highlightbackground=ACCENT)
        rf._is_attack_resp = True
        rf.pack(fill=tk.X, padx=8, pady=4)
        # 标题栏
        hf = tk.Frame(rf, bg=ACCENT)
        hf.pack(fill=tk.X)
        tk.Label(hf, text=f"  📡 {name}", bg=ACCENT, fg=DARK,
            font=("Microsoft YaHei UI", 10, "bold")).pack(side=tk.LEFT, padx=8, pady=3)
        tk.Button(hf, text="⬅️ 返回漏洞列表", command=self._go_back,
            bg=DARK, fg=FG, font=("Microsoft YaHei UI", 9),
            padx=10, pady=2, cursor="hand2", relief="flat").pack(side=tk.RIGHT, padx=6, pady=2)
        # 响应正文
        tv = tk.Text(rf, bg=BG, fg=FG, font=("Cascadia Code", 8),
            height=12, wrap=tk.WORD, bd=0, padx=8, pady=6)
        tv.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))
        tv.insert("1.0", text or "(empty response)")
        tv.config(state="disabled")
        # 滚动到底部
        def _scroll():
            try:
                tv.see(tk.END)
                self.result_canvas.yview_moveto(1.0)
            except Exception:
                pass
        self.after(100, _scroll)
        self._refresh_canvas()

    def _go_back(self):
        """返回漏洞列表."""
        self._gui_done = True  # Stop any running queue drain
        kids = list(self.result_frame.winfo_children())
        for w in kids:
            if getattr(w, '_is_attack_resp', False) or getattr(w, '_is_solve_ui', False):
                w.destroy()
        if self._last_analyze_result:
            self._render_results(self._last_analyze_result)
            self.status_label.config(text="✅ 已返回漏洞列表", fg=GREEN)
        else:
            self.status_label.config(text="⚠️ 无分析结果可返回", fg=RED)
        self._refresh_canvas()

    # ═══════════════════════════════════════════
    #  一键解题
    # ═══════════════════════════════════════════
    def _auto_solve_clicked(self):
        if self._last_analyze_result is None:
            self.status_label.config(text="⚠️ 请先分析URL", fg=YELLOW)
            return
        self._btn_row.pack_forget()
        self._auto_solve(self._last_analyze_result, mode="quick")

    def _deep_scan_clicked(self):
        """🔬 深度扫描按钮."""
        if self._last_analyze_result is None:
            self.status_label.config(text="⚠️ 请先分析URL", fg=YELLOW)
            return
        self._btn_row.pack_forget()
        self._auto_solve(self._last_analyze_result, mode="deep")

    def _multi_stage_clicked(self):
        """🔄 多阶段解题按钮."""
        if self._last_analyze_result is None:
            self.status_label.config(text="⚠️ 请先分析URL", fg=YELLOW)
            return
        self._btn_row.pack_forget()
        self._auto_solve(self._last_analyze_result, mode="multi")

    def _auto_solve(self, result, mode="quick"):
        """v3.5 智能解题：快速/深度/多阶段 三种模式."""
        try:
            self._auto_solve_inner(result, mode=mode)
        except Exception as e:
            import traceback
            err = str(e) + "\n" + str(traceback.format_exc())
            try:
                import time as _t2
                with open('solve_debug.log', 'a', encoding='utf-8') as _f:
                    _f.write(f"=== OUTER_CRASH {_t2.strftime('%H:%M:%S')} mode={mode} ===\n")
                    _f.write(err + '\n')
            except Exception:
                pass
            with open('solve_debug.log', 'a', encoding='utf-8') as _f:
                _f.write(f"\n=== EXCEPTION in _auto_solve ===\n{err}\n")
            err = err.replace('\x00', '').replace('\r', '')[:800]
            try:
                for w in list(self.result_frame.winfo_children()):
                    w.destroy()
            except Exception:
                pass
            try:
                _label(self.result_frame,
                    f"❌ 引擎启动失败: {err}",
                    fg=RED, font_size=11, pady=20)
            except Exception:
                tk.Label(self.result_frame, text=f"引擎失败: {e}",
                    bg=BG, fg=RED).pack(pady=20)

    def _auto_solve_inner(self, result, mode="quick"):
        """Inner implementation — wrapped by _auto_solve with error handling."""
        url = result.get("url", "")
        results = result.get("results", [])
        fingerprint = result.get("fingerprint", {})

        import time as _t
        is_deep = (mode == "deep")
        is_multi = (mode == "multi")
        if is_multi:
            mode_label = "🔄 多阶段解题"
        elif is_deep:
            mode_label = "🔬 深度扫描"
        else:
            mode_label = "🚀 快速解题"
        _log = [f"_auto_solve v3.6 {_t.time():.0f} mode={mode}", f"url={url[:80]}", f"results={len(results)}"]
        def _dlog(msg):
            _log.append(f"{msg}")

        # IMMEDIATE write to disk for diagnosis
        with open('solve_debug.log', 'w', encoding='utf-8') as _f:
            _f.write(f"ENTER _auto_solve_inner {_t.strftime('%H:%M:%S')}\nurl={url}\nresults_count={len(results)}\nfingerprint={fingerprint}\n")

        _dlog("start")

        # 清除 + 进度UI
        for w in list(self.result_frame.winfo_children()):
            w.destroy()
        _dlog("cleared children")

        # Show fingerprint info
        fp_info = ""
        if fingerprint:
            cms = fingerprint.get('cms', '')
            waf = fingerprint.get('waf', '')
            php_vulns = fingerprint.get('php_vulns', [])
            php_params = fingerprint.get('php_params', [])
            if cms and cms != 'Unknown':
                fp_info += f"CMS: {cms} | "
            if waf:
                fp_info += f"WAF: {waf} | "
            if php_vulns:
                top = php_vulns[0]
                fp_info += f"源码: {top['reason']} ({top['confidence']}%)"
            if php_params:
                methods = set(p['method'] for p in php_params)
                fp_info += f" | 方法: {','.join(methods)}"

        _label(self.result_frame,
            f"{mode_label} v3.6\n\n目标: {url[:80]}\n{fp_info}\n" +
            (f"🔄 多阶段: 弱口令爆破→JS跳转→页面识别→对应攻击" if is_multi else
             f"🗂 字典扫描 + 并发攻击 + 攻击链升级" if is_deep else
             f"{len(results)} 种漏洞 → 并发攻击"),
            fg=ACCENT, font_size=11, pady=(8, 4))
        self._solve_status = tk.Label(self.result_frame, text="⏳ 构建攻击计划...",
            bg=BG, fg=YELLOW, font=("Microsoft YaHei UI", 11, "bold"))
        self._solve_status.pack(pady=(4, 4))
        self._solve_progress = tk.Text(self.result_frame, bg=INPUT_BG, fg=FG,
            font=("Cascadia Code", 9), height=6, wrap=tk.WORD, bd=0, padx=10, pady=6)
        self._solve_progress.pack(fill=tk.X, padx=6, pady=(0, 4))
        self._solve_progress.insert(tk.END, "⏳ 指纹识别完成，构建攻击计划...\n")
        # 进度条
        bar_frame = tk.Frame(self.result_frame, bg=BG)
        bar_frame.pack(fill=tk.X, padx=10, pady=(0, 4))
        self._solve_bar_label = tk.Label(bar_frame, text="准备中...", bg=BG, fg=BORDER,
            font=("Microsoft YaHei UI", 9))
        self._solve_bar_label.pack(anchor="w")
        self._solve_bar = ttk.Progressbar(bar_frame, mode='determinate', length=740, maximum=100)
        self._solve_bar.pack(fill=tk.X)
        self._solve_bar['value'] = 0
        self._cancel_flag = False
        self._stop_btn = tk.Button(self.result_frame, text="⏹ 停止",
            command=self._cancel_attack,
            bg="#553333", fg="#ffffff", font=("Microsoft YaHei UI", 9),
            padx=10, pady=2, cursor="hand2", relief="flat")
        self._stop_btn.pack(pady=(0, 6))
        self._refresh_canvas()
        _dlog("progress UI created")

        # ⚠️ tkinter is NOT thread-safe. All callbacks from worker threads
        # MUST use self.after() to marshal to the main thread.
        import queue
        self._gui_queue = queue.Queue()
        self._gui_done = False

        def _process_queue():
            """Drain the thread-safe GUI update queue."""
            try:
                while True:
                    msg = self._gui_queue.get_nowait()
                    if msg[0] == 'progress':
                        _, stage, item, status = msg
                        try:
                            if hasattr(self, '_solve_progress') and self._solve_progress.winfo_exists():
                                self._solve_progress.insert(tk.END, f"[{stage}] {str(item)[:35]}: {str(status)[:70]}\n")
                                self._solve_progress.see(tk.END)
                        except Exception:
                            pass
                    elif msg[0] == 'progress_bar':
                        _, pct, label = msg
                        try:
                            if hasattr(self, '_solve_bar') and self._solve_bar.winfo_exists():
                                self._solve_bar['value'] = pct
                                self._solve_bar_label.config(text=label)
                        except Exception:
                            pass
                    elif msg[0] == 'flag':
                        _, flag = msg
                        try:
                            if hasattr(self, '_solve_status') and self._solve_status.winfo_exists():
                                self._solve_status.config(text=f"🎉 找到Flag: {flag}", fg="#00FF00")
                            if hasattr(self, '_solve_bar') and self._solve_bar.winfo_exists():
                                self._solve_bar['value'] = 100
                                self._solve_bar_label.config(text="✅ 完成！")
                            self.after(100, lambda f=flag: tk.messagebox.showinfo(
                                "🎉 FLAG 已找到！", f"{f}", parent=self))
                        except Exception:
                            pass
            except queue.Empty:
                pass
            if not getattr(self, '_gui_done', False):
                self._gui_poll_id = self.after(50, _process_queue)

        _process_queue()  # Start periodic queue drain

        def _progress(stage, item, status):
            """Thread-safe progress: enqueue update for main thread."""
            if self._cancel_flag:
                return
            self._gui_queue.put(('progress', stage, item, status))

        def _bar(pct, label=""):
            """Thread-safe progress bar update: set percentage + label."""
            if self._cancel_flag:
                return
            self._gui_queue.put(('progress_bar', pct, label))

        _bar(5, "🔍 启动扫描引擎...")  # Initial progress

        def _found(flag):
            """Thread-safe flag found: enqueue update for main thread."""
            _dlog(f"FLAG callback: {flag}")
            self._gui_queue.put(('flag', flag))

        import threading
        def _run():
            final = None
            try:
                _bar(10, "🔍 指纹识别完成，构建攻击计划...")

                # ── Multi-Stage Mode: 全自动多阶段解题 ──
                if is_multi:
                    from ...core.multi_stage import MultiStageEngine
                    _dlog("thread: MultiStageEngine imported")
                    _bar(15, "🔄 多阶段解题: 识别页面类型...")
                    self.after(0, lambda: self._solve_status.config(
                        text=f"🔄 多阶段解题: 弱口令→跳转→识别→攻击...", fg=GREEN))
                    ms_engine = MultiStageEngine(timeout=8, max_stages=5)
                    def _ms_progress(stage, item, status):
                        _progress(stage, item, status)
                        stage_pct_map = {
                            'multi': 10, 'stage': 25, 'page_type': 30,
                            'attack': 45, 'cred_try': 55, 'cred_found': 65,
                            'redirect': 75, 'xxe_hit': 85, 'xxe_confirmed': 90,
                            'sqli_hint': 60, 'ssti_hit': 85, 'rce_hit': 95,
                            'flag': 100,
                        }
                        if stage in stage_pct_map:
                            _bar(stage_pct_map[stage], f"{stage}: {str(item)[:30]}")
                    ms_result = ms_engine.solve(url, on_progress=_ms_progress, on_flag=_found) or {}
                    _dlog(f"thread: multi_stage done flag={str(ms_result.get('flag',''))[:20]}")
                    flag_val = ms_result.get('flag')
                    if flag_val:
                        stages_ms = [f"S{e['stage']}:{e['type']}→{e['result']}" for e in ms_result.get('attack_log', [])]
                        final = {
                            'flag': flag_val, 'vuln_confirmed': [],
                            'attacks_run': 0,
                            'stages': stages_ms,
                            'timing_ms': ms_result.get('timing_ms', 0),
                            'source': 'multi_stage',
                        }
                    else:
                        _dlog("thread: multi_stage no flag, trying auto_exploit")

                # ── Deep Scan Mode: AdvancedSolver first ──
                if is_deep:
                    from ...core.advanced_scanner import AdvancedSolver
                    _dlog("thread: AdvancedSolver imported")
                    _bar(15, "🔬 深度扫描: 端口发现中...")
                    self.after(0, lambda: self._solve_status.config(
                        text=f"🔬 深度扫描中: 端口+字典+对比+攻击链...", fg=GREEN))
                    solver = AdvancedSolver()
                    # Wrap progress callback to also update progress bar
                    def _deep_progress(stage, item, status):
                        _progress(stage, item, status)
                        stage_pct = {
                            'ports': 20, 'dict_scan': 35, 'method': 50,
                            'diff': 60, 'chain': 70, 'chain_stage': 75,
                            'chain_flag': 95, 'flag': 100,
                        }
                        if stage in stage_pct:
                            _bar(stage_pct[stage], f"{stage}: {str(item)[:30]}")
                    deep_result = solver.deep_scan(url, analysis_result=result,
                        on_progress=_deep_progress, on_flag=_found) or {}
                    _dlog(f"thread: deep_scan done flag={str(deep_result.get('flag',''))[:20]}")
                    flag_val = deep_result.get('flag')
                    if flag_val:
                        final = {
                            'flag': flag_val, 'vuln_confirmed': [],
                            'attacks_run': 0,
                            'stages': deep_result.get('stages', []),
                            'timing_ms': deep_result.get('timing_ms', 0),
                            'source': deep_result.get('source', 'deep_scan'),
                        }
                    else:
                        _dlog("thread: deep_scan no flag, trying auto_exploit")

                if final is None:
                    _bar(80, "⚡ 并发攻击...")
                    from ...core.url_analyzer import auto_exploit
                    _dlog("thread: auto_exploit imported")
                    self.after(0, lambda: self._solve_status.config(
                        text=f"🔍 并发攻击中...", fg=GREEN))
                    final = auto_exploit(url, results,
                        on_progress=_progress, on_found=_found,
                        fingerprint=fingerprint)
                    _dlog(f"thread: auto_exploit done flag={final.get('flag')[:20] if final.get('flag') else None}")
                # DUMP full debug log for diagnosis
                try:
                    with open('solve_debug.log', 'a', encoding='utf-8') as _f:
                        _f.write(f"=== {_t.strftime('%H:%M:%S')} ===\n")
                        _f.write('\n'.join(_log) + '\n')
                        _f.write(f"final keys: {list(final.keys())}\n")
                        _f.write(f"stages: {final.get('stages')}\n")
                        _f.write(f"flag: {final.get('flag')}\n")
                        _f.write(f"confirmed: {final.get('vuln_confirmed')}\n\n")
                except Exception:
                    pass
                flag = final.get("flag")
                confirmed = final.get("vuln_confirmed", [])
                attacks = final.get("attacks_run", 0)
                stages = final.get("stages", [])
                timing = final.get("timing_ms", 0)
                _dlog(f"thread: about to call _show_solve_result via after(0)")
                self.after(0, lambda: self._show_solve_result(
                    flag, confirmed, attacks, stages, timing=timing))
            except Exception as e:
                import traceback as _tb2
                _dlog(f"thread: EXCEPTION {e}")
                err_text = str(e) + "\n" + str(_tb2.format_exc())
                # Flush debug log to disk for diagnosis
                try:
                    with open('solve_debug.log', 'a', encoding='utf-8') as _f:
                        _f.write(f"=== EXCEPTION {_t.strftime('%H:%M:%S')} ===\n")
                        _f.write('\n'.join(_log) + '\n')
                        _f.write(err_text + '\n')
                except Exception:
                    pass
                # Sanitize for Tcl: remove null bytes and truncate
                err_text = err_text.replace('\x00', '').replace('\r', '')[:800]
                self.after(0, lambda et=err_text: self._show_solve_result(
                    None, [], 0, [], error=et))
        threading.Thread(target=_run, daemon=True).start()
        _dlog("thread started")

    def _cancel_attack(self):
        """Cancel the running attack."""
        self._cancel_flag = True
        try:
            from ...core.url_analyzer import ConcurrentEngine
            # Signal all engines to stop
        except Exception:
            pass
        self._stop_btn.config(text="⏸ 已停止", state="disabled", bg="#333333")
        self._solve_status.config(text="⏸ 攻击已取消", fg=YELLOW)

    def _show_solve_result(self, flag, confirmed, attacks, stages, error=None, timing=None):
        """展示解题结果."""
        # Stop the GUI queue drain
        self._gui_done = True
        try:
            self._show_solve_result_inner(flag, confirmed, attacks, stages, error, timing)
        except Exception as e2:
            # Absolute last-resort fallback
            try:
                for w in list(self.result_frame.winfo_children()):
                    w.destroy()
                tk.Label(self.result_frame, text=f"显示结果失败: {e2}",
                    bg=BG, fg=RED, font=("Microsoft YaHei UI", 11)).pack(pady=20)
            except Exception:
                pass  # Completely broken, give up

    def _show_solve_result_inner(self, flag, confirmed, attacks, stages, error=None, timing=None):
        """Inner — already protected by wrapper."""
        # 清除所有子组件
        for w in list(self.result_frame.winfo_children()):
            w.destroy()
        rf = tk.Frame(self.result_frame, bg=BG)
        rf._is_solve_ui = True
        rf.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        if error:
            _label(rf, f"错误: {error[:300]}", fg=RED, font_size=11, pady=20)
            tk.Button(rf, text="⬅️ 返回漏洞列表", command=self._go_back,
                bg=ACCENT, fg=DARK, font=("Microsoft YaHei UI", 10, "bold"),
                padx=14, pady=6, cursor="hand2", relief="flat").pack(pady=(20, 5))
            self._refresh_canvas()
            return

        if flag:
            self.status_label.config(text=f"🎉 FLAG: {flag}", fg="#00FF00")
            # ★ MessageBox确保一定看到
            self.after(150, lambda f=flag: tk.messagebox.showinfo("🎉 FLAG!", f"{f}", parent=self))
            # Flag卡片
            fc = tk.Frame(rf, bg="#0A1A0A", highlightthickness=2, highlightbackground="#00FF00")
            fc.pack(fill=tk.X, padx=10, pady=10, ipady=10)
            _label(fc, "🎉 FLAG 已找到！", fg="#00FF00", font_size=16, pady=(8, 0))
            fv = tk.Text(fc, bg=INPUT_BG, fg="#00FF00",
                font=("Cascadia Code", 14, "bold"), height=2, wrap=tk.WORD, bd=0, padx=14, pady=8)
            fv.pack(fill=tk.X, padx=14, pady=8)
            fv.insert("1.0", flag)
            fv.config(state="disabled")
            def _copy_flag(f=flag):
                self.clipboard_clear()
                self.clipboard_append(f)
                self.status_label.config(text="📋 Flag已复制!", fg=GREEN)
            tk.Button(fc, text="📋 复制Flag", command=_copy_flag,
                bg=ACCENT, fg=DARK, font=("Microsoft YaHei UI", 11, "bold"),
                padx=18, pady=6, cursor="hand2", relief="flat").pack(pady=(0, 8))
            # 攻击详情
            if confirmed:
                df = tk.Frame(rf, bg=INPUT_BG)
                df.pack(fill=tk.X, padx=6, pady=6)
                timing_str = f" | ⏱ {timing/1000:.1f}s" if timing else ""
                tk.Label(df, text=f"🔍 攻击详情 | 共 {attacks} 次{timing_str} | {', '.join(stages)}",
                    bg=INPUT_BG, fg=GREEN, font=("Microsoft YaHei UI", 10)).pack(anchor="w", padx=14, pady=(6, 2))
                for vc in confirmed[:6]:
                    p = vc.get('param', vc.get('location', ''))
                    pl = vc.get('payload', vc.get('location', ''))
                    tk.Label(df, text=f"  ✅ {vc['type']}/{p}: {pl[:40]}",
                        bg=INPUT_BG, fg=FG, font=("Cascadia Code", 8)).pack(anchor="w", padx=18)
        else:
            timing_str = f" | ⏱ {timing/1000:.1f}s" if timing else ""
            self.status_label.config(
                text=f"⚠️ 未找到Flag | {attacks}次攻击{timing_str} | 确认: {len(confirmed)}个", fg=YELLOW)
            _label(rf,
                f"⚠️ 自动解题未找到Flag\n\n共 {attacks} 次攻击{timing_str} | 确认 {len(confirmed)} 个漏洞\n阶段: {', '.join(stages) or '基础攻击'}",
                fg=YELLOW, font_size=12, pady=15)
            if confirmed:
                vf = tk.Frame(rf, bg=INPUT_BG)
                vf.pack(fill=tk.X, padx=6, pady=6)
                tk.Label(vf, text="✅ 已确认漏洞:", bg=INPUT_BG, fg=GREEN,
                    font=("Microsoft YaHei UI", 10, "bold")).pack(anchor="w", padx=14, pady=(6, 2))
                for vc in confirmed[:8]:
                    p = vc.get('param', vc.get('location', ''))
                    pl = vc.get('payload', vc.get('location', ''))
                    tk.Label(vf, text=f"  {vc['type']}/{p}: {pl[:40]}",
                        bg=INPUT_BG, fg=FG, font=("Cascadia Code", 9)).pack(anchor="w", padx=18)

        tk.Button(rf, text="⬅️ 返回漏洞列表", command=self._go_back,
            bg=ACCENT, fg=DARK, font=("Microsoft YaHei UI", 10, "bold"),
            padx=14, pady=6, cursor="hand2", relief="flat").pack(pady=(16, 8))
        self._refresh_canvas()

    def _refresh_canvas(self):
        """强制刷新Canvas滚动区域."""
        try:
            self.result_frame.update_idletasks()
            self.result_canvas.update_idletasks()
            self.result_canvas.configure(scrollregion=self.result_canvas.bbox("all"))
            self.result_canvas.yview_moveto(0)
        except Exception:
            pass
