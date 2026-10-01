# -*- coding: utf-8 -*-
"""gui._routing -- The "send to next step" routing bus: route registry + _SendBar.

从 yang_web/gui.py 机械拆分而来（相对导入升一层）, 行为等价。
"""

from ._deps import (tk)
from ._theme import (ACCENT, BG, BORDER, INPUT_BG, YELLOW)
from ._widgets import (_append)



# ═══════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════
#  v2.0 新面板: 高级编码
# ═══════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════
#  面板间数据流 —— "送到下一步"
# ═══════════════════════════════════════════════════════════

#: 路由名 -> 接收函数；由 run_gui() 在各面板创建后注册。
_ROUTES = {}


#: 已创建的发送条；注册新路由时统一点亮它们的按钮。
_SEND_BARS = []



def register_route(name, handler):
    """注册一个可接收文本的面板。handler(text) 负责填入内容并切到该面板。"""
    _ROUTES[name] = handler
    for bar in list(_SEND_BARS):
        try:
            bar.rebuild()
        except tk.TclError:
            pass



def available_routes():
    """当前已注册的目标面板名。"""
    return list(_ROUTES)



def route_text(name, text):
    """把文本送到指定面板，返回 (是否成功, 提示信息)。"""
    text = (text or "").strip()
    if not text:
        return False, "没有可送出的内容"
    handler = _ROUTES.get(name)
    if handler is None:
        return False, "目标面板未注册: " + str(name)
    try:
        handler(text)
    except Exception as exc:  # noqa: BLE001
        return False, "送出失败: " + type(exc).__name__ + ": " + str(exc)
    return True, "已送到「" + str(name) + "」"



def _set_input(widget, text):
    """把文本写入输入控件；自动区分 ScrolledText / Entry。"""
    if widget is None:
        return False
    try:
        widget.delete("1.0", tk.END)
        widget.insert("1.0", text)
        return True
    except tk.TclError:
        pass
    try:
        widget.delete(0, tk.END)
        widget.insert(0, text)
        return True
    except tk.TclError:
        return False



def _last_output_line(txt_widget):
    """取输出区最后一行有效文本，作为"送出内容"的兜底。

    纯分隔线（── / ══ 等）不算有效内容。
    """
    try:
        raw = txt_widget.get("1.0", tk.END)
    except Exception:  # noqa: BLE001
        return ""
    for line in reversed(raw.splitlines()):
        stripped = line.strip()
        if stripped and not set(stripped) <= set("─═-—= "):
            return stripped
    return ""



class _SendBar(tk.Frame):
    """一排「送到 →」按钮，把当前结果推进另一个面板。"""

    def __init__(self, parent, panel, input_attr="input_text", default_getter=None):
        super().__init__(parent, bg=BG)
        self._panel = panel
        self._input_attr = input_attr
        self._default_getter = default_getter
        tk.Label(self, text="送到 →", bg=BG, fg=YELLOW,
                 font=("Microsoft YaHei UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 6))
        self._btn_area = tk.Frame(self, bg=BG)
        self._btn_area.pack(side=tk.LEFT)
        _SEND_BARS.append(self)
        self.rebuild()

    def _payload(self):
        """要送出的文本：显式结果 → 输出区末行 → 输入框原文。"""
        text = getattr(self._panel, "_last_result", "") or ""
        if text:
            return text
        out = getattr(self._panel, "output", None)
        if out is not None:
            text = _last_output_line(out)
            if text:
                return text
        if self._default_getter is not None:
            return self._default_getter() or ""
        widget = getattr(self._panel, self._input_attr, None)
        try:
            return widget.get("1.0", tk.END).strip()
        except Exception:  # noqa: BLE001
            return ""

    def _go(self, name):
        _ok, message = route_text(name, self._payload())
        out = getattr(self._panel, "output", None)
        if out is not None:
            _append(out, "[→] " + message)

    def rebuild(self):
        for widget in self._btn_area.winfo_children():
            widget.destroy()
        for name in available_routes():
            tk.Button(self._btn_area, text=name,
                      command=lambda n=name: self._go(n),
                      bg=INPUT_BG, fg=ACCENT, activebackground=BORDER,
                      relief="flat", padx=10, pady=2, cursor="hand2",
                      font=("Microsoft YaHei UI", 9)).pack(side=tk.LEFT, padx=2)
