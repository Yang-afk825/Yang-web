"""yang_web.gui._panels_tools 子模块 _stego（自 _panels_tools.py 拆分，请勿手工重排）。"""

from .._deps import (HAS_STEGO, JSChallengeSolver, _REPO_ROOT, analyze_file, analyze_png, extract_lsb, generate_reverse_shell, generate_webshell, identify_cipher_text, list_shell_languages, list_webshell_types, os, read_exif, scrolledtext, tk, ttk)
from .._theme import (ACCENT, BG, BORDER, DARK, FG, GREEN, INPUT_BG, RED, YELLOW)
from .._widgets import (_append, _clear_output, _label, _output_area)





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
