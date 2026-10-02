"""yang_web.gui._panels_tools 子模块 _shell（自 _panels_tools.py 拆分，请勿手工重排）。"""

from .._deps import (HAS_STEGO, JSChallengeSolver, _REPO_ROOT, analyze_file, analyze_png, extract_lsb, generate_reverse_shell, generate_webshell, identify_cipher_text, list_shell_languages, list_webshell_types, os, read_exif, scrolledtext, tk, ttk)
from .._theme import (ACCENT, BG, BORDER, DARK, FG, GREEN, INPUT_BG, RED, YELLOW)
from .._widgets import (_append, _clear_output, _label, _output_area)






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
