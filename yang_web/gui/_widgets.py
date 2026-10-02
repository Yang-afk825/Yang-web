# -*- coding: utf-8 -*-
"""gui._widgets -- Small widget factories and text-area helpers shared by all panels.

从 yang_web/gui.py 机械拆分而来（相对导入升一层）, 行为等价。
"""

from ._deps import (tk, ttk)
from ._theme import (ACCENT, BG, BORDER, DARK, FG, INPUT_BG, RED)



# ── 辅助 ──


def _scrollable_text(parent, height=12, width=80):
    frame = tk.Frame(parent, bg=BG)
    txt = tk.Text(frame, height=height, width=width, bg=INPUT_BG, fg=FG,

                  insertbackground=ACCENT, relief="flat", borderwidth=0,
                  font=("Microsoft YaHei UI", 10), padx=10, pady=8,
                  wrap=tk.WORD)
    scroll = tk.Scrollbar(frame, command=txt.yview)
    txt.configure(yscrollcommand=scroll.set)
    txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    scroll.pack(side=tk.RIGHT, fill=tk.Y)
    return frame, txt



def _label(parent, text, fg=FG, font_size=10, bold=False, pady=4):
    try:
        safe_text = str(text).replace('\x00', '')
        w = tk.Label(parent, text=safe_text, bg=BG, fg=fg,
                     font=("Microsoft YaHei UI", font_size, "bold" if bold else "normal"))
        w.pack(anchor="w", pady=(int(pady), 0))
        return w
    except Exception:
        # Last-resort: plain Label
        w = tk.Label(parent, text=str(text)[:200], bg=BG, fg=RED)
        w.pack(anchor="w")
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



def _pretty_json(obj):
    import json
    return json.dumps(obj, indent=2, ensure_ascii=False)
