"""yang_web.gui._panels_tools 子模块 _docs（自 _panels_tools.py 拆分，请勿手工重排）。"""

from .._deps import (HAS_STEGO, JSChallengeSolver, _REPO_ROOT, analyze_file, analyze_png, extract_lsb, generate_reverse_shell, generate_webshell, identify_cipher_text, list_shell_languages, list_webshell_types, os, read_exif, scrolledtext, tk, ttk)
from .._theme import (ACCENT, BG, BORDER, DARK, FG, GREEN, INPUT_BG, RED, YELLOW)
from .._widgets import (_append, _clear_output, _label, _output_area)





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
