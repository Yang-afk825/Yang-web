# -*- coding: utf-8 -*-
"""gui._theme -- Palette constants and the ttk theme setup.

从 yang_web/gui.py 机械拆分而来（相对导入升一层）, 行为等价。
"""

from ._deps import (ttk)

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
