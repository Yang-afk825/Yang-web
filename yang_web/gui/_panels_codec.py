# -*- coding: utf-8 -*-
"""gui._panels_codec -- Encoding / classical-cipher panels.

从 yang_web/gui.py 机械拆分而来（相对导入升一层）, 行为等价。
"""

from ._deps import (ADV_ENC, CHN_CIPHERS, DECODERS, HAS_CRYPTO, _decode_buddha, aes_string_decrypt, aes_string_encrypt, bear_decode, beast_decode, brute_decode, calc_crc32_hex, calc_md5, calc_sha1, calc_sha256, calc_sha512, chain_decode, core_values_decode, decode_base16, decode_base32, decode_base58, decode_base64, decode_base85, decode_base91, decode_base92, decode_binary, decode_brainfuck, decode_decimal, decode_html, decode_morse, decode_octal, decode_ook, decode_punycode, decode_quoted_printable, decode_rot13, decode_rot47, decode_shellcode, decode_unicode_escape, decode_url, decode_utf7, decode_uuencode, decode_xxencode, detect_encoding, hex_to_text, num_base_convert, rc4_decrypt, rc4_encrypt, scrolledtext, surnames_decode, telegraph_decode, text_to_hex, tk, ttk, xor_brute_single, xor_decrypt, xor_encrypt)
from ._routing import (_SendBar)
from ._theme import (ACCENT, BG, BORDER, DARK, FG, GREEN, INPUT_BG, RED, YELLOW)
from ._widgets import (_append, _clear_output, _label, _output_area)



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
        self._last_result = ""
        _SendBar(self, self).pack(anchor="w", padx=4, pady=(0, 4))

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
        self._last_result = ""
        _SendBar(self, self).pack(anchor="w", padx=4, pady=(0, 4))

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
        self._last_result = ""
        _SendBar(self, self).pack(anchor="w", padx=4, pady=(0, 4))

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
        self._last_result = ""
        _SendBar(self, self).pack(anchor="w", padx=4, pady=(0, 4))

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
            self._last_result = result
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
            self._last_result = result
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
            self._last_result = steps[-1][2]
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
            self._last_result = results[0][2]
            for r in results:
                enc_id, enc_desc, decoded = r[0], r[1], r[2]
                confidence = r[3] if len(r) > 3 else 50
                marker = "⭐" if confidence >= 80 else "  "
                _append(self.output, f"\n{marker} {enc_desc} ({enc_id}): {decoded[:200]}")
        except Exception as e:
            _append(self.output, f"❌ 错误: {e}")
