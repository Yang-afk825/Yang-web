# -*- coding: utf-8 -*-
"""gui._panels_crypto -- Hash, JWT and misc-crypto panels plus the payload generator panel.

从 yang_web/gui.py 机械拆分而来（相对导入升一层）, 行为等价。
"""

from ._deps import (analyze_jwt, brute_jwt, decode_jwt, get_categories, get_image2_path, get_image_path, get_text_content, hash_identify, list_ciphers, mc_decode, mc_encode, none_attack, os, search_ciphers, tk, ttk)
from ._routing import (_SendBar)
from ._theme import (ACCENT, BG, BORDER, DARK, FG, GREEN, INPUT_BG, YELLOW)
from ._widgets import (_append, _clear_output, _combo, _entry, _label, _output_area, _pretty_json)



class PayloadPanel(tk.Frame):
    """通用 Payload 面板"""

    def __init__(self, parent, title, emoji, get_data_fn, search_fn=None, analyzer_fn=None):
        super().__init__(parent, bg=BG)
        self.get_data = get_data_fn
        self.search_fn = search_fn
        self.analyzer_fn = analyzer_fn
        _label(self, f"{emoji} {title}", fg=ACCENT, font_size=16, bold=True, pady=8)

        # 靶场分析条 (Upload 专用)
        if analyzer_fn:
            analyze_frame = tk.Frame(self, bg=DARK)
            analyze_frame.pack(fill=tk.X, padx=4, pady=(0,4))
            _label(analyze_frame, "🎯 分析:", fg=ACCENT, pady=0, font_size=11)
            self.analyze_entry = tk.Entry(analyze_frame, bg=INPUT_BG, fg=FG,
                insertbackground=ACCENT, relief="flat", borderwidth=0,
                font=("Cascadia Code", 11))
            self.analyze_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6, ipady=4)
            self.analyze_entry.bind("<Return>", lambda e: self._do_analyze())
            tk.Button(analyze_frame, text="分析", command=self._do_analyze,
                bg=ACCENT, fg=DARK, relief="flat", padx=14, pady=4,
                cursor="hand2", font=("Microsoft YaHei UI", 9)).pack(side=tk.LEFT, padx=(2,0))

        # 搜索
        search_frame = tk.Frame(self, bg=BG)
        search_frame.pack(fill=tk.X, pady=4)
        _label(search_frame, "🔍 搜索:", pady=0)
        self.search_entry = tk.Entry(search_frame, bg=INPUT_BG, fg=FG, insertbackground=ACCENT,
                                     relief="flat", borderwidth=0, font=("Cascadia Code", 11))
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 4), ipady=4)
        tk.Button(search_frame, text="搜索", command=self._search, bg=ACCENT, fg=DARK,
                  relief="flat", padx=12, pady=4, cursor="hand2",
                  font=("Microsoft YaHei UI", 9)).pack(side=tk.LEFT)

        # 分类选择 (搜索下方)
        top = tk.Frame(self, bg=BG)
        top.pack(fill=tk.X, pady=4)
        _label(top, "分类:", pady=0)
        self.category_var = tk.StringVar(value="-- 选择分类 --")
        self.category_combo = _combo(top, ["-- 选择分类 --"], textvariable=self.category_var)
        self.category_combo.bind("<<ComboboxSelected>>", lambda e: self._refresh())
        self.top_frame = top
        self.output_frame, self.output = _output_area(self, 22)
        self.output_frame.pack(fill=tk.BOTH, expand=True)
        _append(self.output, "👆 请在上方选择一个分类查看 Payload")

    def _refresh(self):
        _clear_output(self.output)

        cat = self.category_var.get()

        if not cat or cat == "-- 选择分类 --":
            _append(self.output, "👆 请在上方选择一个分类查看 Payload")

            return

        try:
            data = self.get_data(cat)

            self._display(data)

        except Exception as e:
            _append(self.output, f"❌ 错误: {e}")

    def _do_analyze(self):
        """运行靶场分析."""
        if not self.analyzer_fn:
            return
        blacklist = self.analyze_entry.get().strip()
        if not blacklist:
            _clear_output(self.output)
            _append(self.output, "👆 请在上方输入靶场黑名单 (如: php,php3,php5)")
            return
        _clear_output(self.output)
        try:
            result = self.analyzer_fn(blacklist)
            _append(self.output, result)
        except Exception as e:
            _append(self.output, f"❌ 分析出错: {e}")

    def _display(self, data):
        if isinstance(data, dict):
            for key, items in data.items():
                _append(self.output, f"\n▸ {key}\n")
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, str):
                            _append(self.output, f"  • {item}")
                        elif isinstance(item, dict):
                            _append(self.output, f"  • {item.get('name','?')}")
                            if 'payload' in item:
                                _append(self.output, f"    {item['payload'][:150]}")
                            if 'tip' in item:
                                _append(self.output, f"    💡 {item['tip'][:120]}")
                elif isinstance(items, dict):
                    for sub_key, sub_items in items.items():
                        if isinstance(sub_items, list):
                            _append(self.output, f"  ▸ {sub_key}:")
                            for item in sub_items:
                                _append(self.output, f"    • {str(item)[:200]}")
                        else:
                            _append(self.output, f"  ▸ {sub_key}: {sub_items}")
                else:
                    _append(self.output, f"  {items}")

    def _search(self):
        kw = self.search_entry.get().strip()
        if not kw or not self.search_fn:
            return
        _clear_output(self.output)
        results = self.search_fn(kw)
        if results:
            _append(self.output, f"🔍 '{kw}' 的搜索结果 ({len(results)} 条):\n")
            for r in results[:30]:
                cat = r.get("category", "")
                nm = r.get("name", "")
                payload = r.get("payload", r.get("content", ""))
                _append(self.output, f"\n  [{cat}] {nm}")
                if payload:
                    _append(self.output, f"  {str(payload)[:200]}")
        else:
            _append(self.output, f"未找到包含 '{kw}' 的结果")

    def set_categories(self, categories):
        self.category_combo["values"] = ["-- 选择分类 --"] + list(categories)

        self.category_combo.set("-- 选择分类 --")



class HashPanel(tk.Frame):
    """Hash 识别面板"""

    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        _label(self, "🔍 Hash 类型识别", fg=ACCENT, font_size=16, bold=True, pady=8)
        _label(self, "支持 40+ 种 Hash 算法自动匹配", fg=YELLOW, font_size=9)
        _label(self, "📥 输入 Hash:", pady=8)
        self.hash_entry = _entry(self, 70)
        self.hash_entry.bind("<Return>", lambda e: self._identify())
        tk.Button(self, text="🔍 识别", command=self._identify, bg=ACCENT, fg=DARK,
                  relief="flat", padx=20, pady=6, cursor="hand2",
                  font=("Microsoft YaHei UI", 11, "bold")).pack(anchor="w", pady=4)
        _label(self, "📤 识别结果:", pady=8)
        self.output_frame, self.output = _output_area(self, 14)
        self.output_frame.pack(fill=tk.BOTH, expand=True)

    def _identify(self):
        _clear_output(self.output)
        h = self.hash_entry.get().strip()
        if not h:
            _append(self.output, "⚠ 请先输入 Hash 值")
            return
        try:
            result = hash_identify(h)
            _append(self.output, f"📋 输入: {h[:80]}")
            _append(self.output, f"📏 长度: {len(h)} 字符")
            _append(self.output, f"\n📊 可能的算法:")
            if isinstance(result, list):
                for r in result:
                    _append(self.output, f"  • {r}")
            elif isinstance(result, dict):
                for algo, confidence in result.items():
                    _append(self.output, f"  • {algo} (置信度: {confidence})")
            else:
                _append(self.output, f"  {result}")
        except Exception as e:
            _append(self.output, f"❌ 错误: {e}")



class JWTPanel(tk.Frame):
    """JWT 分析面板"""

    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        _label(self, "🔑 JWT 分析与攻击", fg=ACCENT, font_size=16, bold=True, pady=8)
        _label(self, "解析 → 分析 → None 攻击 → 弱密钥爆破 → 伪造", fg=YELLOW, font_size=9)
        _label(self, "📥 JWT Token:", pady=8)
        self.jwt_entry = _entry(self, 70)
        btn_frame = tk.Frame(self, bg=BG)
        btn_frame.pack(anchor="w", pady=4)
        for label, cmd in [("📋 解析", self._decode), ("🔍 分析", self._analyze),
                           ("⚡ None攻击", self._none), ("💣 弱密钥爆破", self._brute)]:
            tk.Button(btn_frame, text=label, command=cmd, bg=INPUT_BG, fg=FG,
                      activebackground=ACCENT, relief="flat", padx=12, pady=5,
                      cursor="hand2", font=("Microsoft YaHei UI", 10)).pack(side=tk.LEFT, padx=2)
        _label(self, "📤 结果:", pady=8)
        self.output_frame, self.output = _output_area(self, 16)
        self.output_frame.pack(fill=tk.BOTH, expand=True)

    def _get_token(self):
        return self.jwt_entry.get().strip()

    def _decode(self):
        _clear_output(self.output)
        t = self._get_token()
        if not t:
            _append(self.output, "⚠ 请输入 JWT")
            return
        try:
            header, payload = decode_jwt(t)
            _append(self.output, f"📋 Header:\n{_pretty_json(header)}\n")
            _append(self.output, f"📋 Payload:\n{_pretty_json(payload)}")
        except Exception as e:
            _append(self.output, f"❌ 错误: {e}")

    def _analyze(self):
        _clear_output(self.output)

        t = self._get_token()

        if not t: return

        try:
            r = analyze_jwt(t)

            for k, v in r.items():
                _append(self.output, f"{k}: {v}\n")

        except Exception as e:
            _append(self.output, f"❌ 错误: {e}")

    def _none(self):
        _clear_output(self.output)

        t = self._get_token()

        if not t: return

        try:
            r = none_attack(t)

            _append(self.output, f"⚡ None 算法攻击:\n{r}")

        except Exception as e:
            _append(self.output, f"❌ 错误: {e}")

    def _brute(self):
        _clear_output(self.output)
        t = self._get_token()
        if not t: return
        _append(self.output, "💣 弱密钥爆破中... (使用内置词库)\n")
        try:
            r = brute_jwt(t)
            if r:
                _append(self.output, f"✅ 密钥找到: {r}")
            else:
                _append(self.output, "❌ 内置词库未匹配")
        except Exception as e:
            _append(self.output, f"❌ 错误: {e}")



class MiscCryptoPanel(tk.Frame):
    """Misc Crypto – 20+ common cipher types with encode/decode + reference images."""

    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        _label(self, "🔐 Misc Crypto Knowledge Base", fg=ACCENT, font_size=16, bold=True, pady=8)
        _label(self, "20+ CTF Misc 密码类型 — 编码/解码 + 参考图/说明文本", fg=YELLOW, font_size=9)

        # ── Top bar: category + search ──
        top = tk.Frame(self, bg=BG)
        top.pack(fill=tk.X, padx=4, pady=(8, 4))
        tk.Label(top, text="分类:", bg=BG, fg=ACCENT,
                 font=("Microsoft YaHei UI", 11)).pack(side=tk.LEFT, padx=(0, 4))
        cats = ["全部"] + get_categories()
        self.cat_var = tk.StringVar(value="全部")
        self.cat_cb = ttk.Combobox(top, textvariable=self.cat_var, values=cats,
                                    state="readonly", width=16)
        self.cat_cb.pack(side=tk.LEFT, padx=2)
        self.cat_cb.bind("<<ComboboxSelected>>", self._on_cat_change)
        tk.Label(top, text="搜索:", bg=BG, fg=ACCENT,
                 font=("Microsoft YaHei UI", 11)).pack(side=tk.LEFT, padx=(12, 4))
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(top, textvariable=self.search_var,
                                      bg=INPUT_BG, fg=FG, insertbackground=ACCENT,
                                      relief="flat", font=("Cascadia Code", 11),
                                      width=20)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4, ipady=3)
        self.search_entry.bind("<KeyRelease>", self._on_search)

        # ── Main area: list + detail ──
        panes = tk.PanedWindow(self, bg=BG, sashwidth=3)
        panes.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # Left: cipher list
        list_frame = tk.Frame(panes, bg=BG)
        panes.add(list_frame, width=260)
        _label(list_frame, "密码类型:", pady=4)
        self.cipher_list = tk.Listbox(list_frame, bg=INPUT_BG, fg=FG,
                                       selectbackground=ACCENT, selectforeground=DARK,
                                       relief="flat", borderwidth=0,
                                       font=("Microsoft YaHei UI", 10), height=18)
        self.cipher_list.pack(fill=tk.BOTH, expand=True, pady=(0, 4))
        self.cipher_list.bind("<<ListboxSelect>>", self._on_cipher_select)

        # Right: detail + io + reference
        right = tk.Frame(panes, bg=BG)
        panes.add(right, width=550)

        # Detail info
        self.info_var = tk.StringVar(value="")
        _label(right, "详情:", pady=4)
        self.info_label = tk.Label(right, textvariable=self.info_var, bg=BG, fg=FG,
                                    anchor="nw", justify="left",
                                    font=("Microsoft YaHei UI", 10),
                                    wraplength=520)
        self.info_label.pack(fill=tk.X, pady=(0, 4))

        # Reference area (image button + text content)
        ref_header = tk.Frame(right, bg=BG)
        ref_header.pack(fill=tk.X, pady=(2, 2))
        tk.Label(ref_header, text="参考内容:", bg=BG, fg=YELLOW,
                 font=("Microsoft YaHei UI", 10, "bold")).pack(side=tk.LEFT)
        self.view_img_btn = tk.Button(ref_header, text="🖼 查看原图",
                                       command=self._open_image,
                                       bg=INPUT_BG, fg=ACCENT,
                                       activebackground=ACCENT, activeforeground=DARK,
                                       relief="flat", padx=12, pady=3,
                                       cursor="hand2",
                                       font=("Microsoft YaHei UI", 9, "bold"))
        self.view_img2_btn = tk.Button(ref_header, text="🖼 图2",
                                        command=self._open_image2,
                                        bg=INPUT_BG, fg=YELLOW,
                                        activebackground=YELLOW, activeforeground=DARK,
                                        relief="flat", padx=10, pady=3,
                                        cursor="hand2",
                                        font=("Microsoft YaHei UI", 9, "bold"))
        self.img_path_var = tk.StringVar(value="")
        tk.Label(ref_header, textvariable=self.img_path_var, bg=BG, fg=DARK,
                 font=("Cascadia Code", 7)).pack(side=tk.RIGHT, padx=4)

        # Reference text content
        self.ref_frame, self.ref_text = _output_area(right, 10)
        self.ref_frame.pack(fill=tk.BOTH, expand=True, pady=(2, 4))

        # IO area
        io_bar = tk.Frame(right, bg=BG)
        io_bar.pack(fill=tk.X, pady=4)
        tk.Label(io_bar, text="输入:", bg=BG, fg=ACCENT,
                 font=("Microsoft YaHei UI", 10)).pack(side=tk.LEFT, padx=(0, 4))
        self.io_entry = tk.Entry(io_bar, bg=INPUT_BG, fg=FG, insertbackground=ACCENT,
                                  relief="flat", font=("Cascadia Code", 11))
        self.io_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4, ipady=3)
        self.io_entry.bind("<Return>", lambda e: self._do_encode())
        tk.Button(io_bar, text="Encode", command=self._do_encode,
                  bg=ACCENT, fg=DARK, activebackground=GREEN, relief="flat",
                  padx=12, pady=3, cursor="hand2",
                  font=("Microsoft YaHei UI", 9, "bold")).pack(side=tk.LEFT, padx=2)
        tk.Button(io_bar, text="Decode", command=self._do_decode,
                  bg=INPUT_BG, fg=ACCENT, activebackground=BORDER, relief="flat",
                  padx=12, pady=3, cursor="hand2",
                  font=("Microsoft YaHei UI", 9, "bold")).pack(side=tk.LEFT, padx=2)

        # Key entry (for vigenere etc.)
        key_bar = tk.Frame(right, bg=BG)
        key_bar.pack(fill=tk.X, pady=(0, 4))
        tk.Label(key_bar, text="密钥:", bg=BG, fg=YELLOW,
                 font=("Microsoft YaHei UI", 9)).pack(side=tk.LEFT, padx=(0, 4))
        self.key_entry = tk.Entry(key_bar, bg=INPUT_BG, fg=FG, insertbackground=ACCENT,
                                   relief="flat", font=("Cascadia Code", 11), width=20)
        self.key_entry.pack(side=tk.LEFT, padx=4, ipady=2)

        # Output
        _label(right, "输出:", pady=4)
        self.output_frame, self.output = _output_area(right, 6)
        self.output_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 4))
        self._last_result = ""
        _SendBar(self, self, input_attr="io_entry").pack(anchor="w", padx=4, pady=(0, 4))

        # Store state
        self._selected_cid = None
        self._current_image_path = ""

        # Load initial data
        self._ciphers = list_ciphers()
        self._refresh_list()

    def _refresh_list(self):
        """Rebuild the cipher listbox."""

        self.cipher_list.delete(0, tk.END)

        for c in self._ciphers:
            tag = "🔧" if c.get("encode") else "📖"

            self.cipher_list.insert(tk.END, tag + " " + c["name"])

    def _on_cat_change(self, event=None):
        cat = self.cat_var.get()

        if cat == "全部":
            self._ciphers = list_ciphers()

        else:
            self._ciphers = list_ciphers(cat)

        self._refresh_list()

        self._clear_detail()

    def _on_search(self, event=None):
        q = self.search_var.get().strip()

        if q:
            self._ciphers = search_ciphers(q)

        else:
            cat = self.cat_var.get()

            self._ciphers = list_ciphers() if cat == "全部" else list_ciphers(cat)

        self._refresh_list()

    def _on_cipher_select(self, event=None):
        sel = self.cipher_list.curselection()
        if not sel:
            return
        idx = sel[0]
        if idx >= len(self._ciphers):
            return
        info = self._ciphers[idx]
        cid = info.get("id", "")
        _clear_output(self.output)

        # Build info lines
        lines = [
            "名称: " + info["name"],
            "ID:   " + cid,
            "分类: " + info["category"],
            "别名: " + ", ".join(info.get("aliases", []) or ["无"]),
            "描述: " + info["description"],
        ]
        if info.get("features"):
            lines.append("特征: " + ", ".join(info["features"]))
        if info.get("encode"):
            lines.append("状态: 支持编码/解码")
        else:
            lines.append("状态: 仅提供参考图/说明")
        self.info_var.set("\n".join(lines))

        # Show reference: image button + text content
        img = get_image_path(cid)
        img2 = get_image2_path(cid)
        self._current_image_path = img if img else ""
        self._current_image2_path = img2 if img2 else ""
        if img:
            self.view_img_btn.configure(state="normal", bg=INPUT_BG, fg=ACCENT)
            self.img_path_var.set(os.path.basename(img))
            self.view_img_btn.pack(side=tk.LEFT, padx=(8, 0))
        else:
            self.view_img_btn.pack_forget()
        if img2:
            self.view_img2_btn.configure(state="normal")
            self.view_img2_btn.pack(side=tk.LEFT, padx=4)
        else:
            self.view_img2_btn.pack_forget()
        if not img and not img2:
            self.img_path_var.set("")

        # Load and show text content
        _clear_output(self.ref_text)
        txt_content = get_text_content(cid)
        if txt_content:
            _append(self.ref_text, txt_content)
        elif not img and not img2:
            # No image, no text — show algorithm note
            _append(self.ref_text, "[此密码为经典算法，无需参考图/说明文件]")
        else:
            tips = []
            if img:
                tips.append("查看原图")
            if img2:
                tips.append("图2")
            _append(self.ref_text, f"[点击 {', '.join(tips)} 按钮查看参考图片]")

        # Store selected cipher id
        self._selected_cid = cid

    def _clear_detail(self):
        self.info_var.set("")

        self.img_path_var.set("")

        self.view_img_btn.pack_forget()

        self.view_img2_btn.pack_forget()

        _clear_output(self.ref_text)

        self._selected_cid = None

        self._current_image_path = ""

        self._current_image2_path = ""

    def _open_image(self):
        """Open reference image with system viewer."""

        if self._current_image_path and os.path.exists(self._current_image_path):
            try:
                os.startfile(self._current_image_path)

            except Exception as e:
                _clear_output(self.ref_text)

                _append(self.ref_text, "无法打开图片: " + str(e))

    def _open_image2(self):
        """Open second reference image."""

        if self._current_image2_path and os.path.exists(self._current_image2_path):
            try:
                os.startfile(self._current_image2_path)

            except Exception as e:
                _clear_output(self.ref_text)

                _append(self.ref_text, "无法打开图片: " + str(e))

    def _do_encode(self):
        text = self.io_entry.get().strip()
        cid = self._selected_cid
        if not cid:
            _clear_output(self.output)
            _append(self.output, "⚠ 请先选择密码类型")
            return
        if not text:
            _clear_output(self.output)
            _append(self.output, "⚠ 请输入文本")
            return
        key = self.key_entry.get().strip()
        _clear_output(self.output)
        try:
            result = mc_encode(cid, text, key=key)
            _append(self.output, "🔒 " + cid + " 编码:\n" + result)
        except Exception as e:
            _append(self.output, "❌ 错误: " + str(e))

    def _do_decode(self):
        text = self.io_entry.get().strip()
        cid = self._selected_cid
        if not cid:
            _clear_output(self.output)
            _append(self.output, "⚠ 请先选择密码类型")
            return
        if not text:
            _clear_output(self.output)
            _append(self.output, "⚠ 请输入文本")
            return
        key = self.key_entry.get().strip()
        _clear_output(self.output)
        try:
            result = mc_decode(cid, text, key=key)
            _append(self.output, "🔓 " + cid + " 解码:\n" + result)
        except Exception as e:
            _append(self.output, "❌ 错误: " + str(e))
