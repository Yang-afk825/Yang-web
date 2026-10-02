# -*- coding: utf-8 -*-
"""Yang-Web 图形界面 (tkinter).

零外部依赖，Python 自带 tkinter。
布局: 顶部标题栏 + Notebook 标签页切换功能模块。
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import sys
import os


# 导入核心模块
from ..core.decoder import (chain_decode, brute_decode, detect_encoding, DECODERS,
    decode_base64, decode_base32, decode_base16, decode_base58, decode_base85,
    decode_url, decode_html, decode_rot13, decode_binary, decode_octal,
    decode_decimal, decode_morse, decode_unicode_escape,
    decode_base91, decode_base92, decode_rot47, decode_shellcode,
    decode_brainfuck, decode_ook, decode_quoted_printable,
    decode_uuencode, decode_xxencode, decode_utf7, decode_punycode,
    _decode_buddha, core_values_decode, beast_decode,
    bear_decode, surnames_decode, telegraph_decode)
from ..core.hashid import identify as hash_identify
from ..core.jwt import decode_jwt, analyze_jwt, none_attack, brute_jwt, BUILTIN_WORDLIST
from ..core.misc_crypto import (
    CIPHER_TYPES, list_ciphers, search_ciphers, get_cipher,
    get_image_path, get_image2_path, get_text_content, get_categories,
    encode as mc_encode, decode as mc_decode,
)
from ..payloads import ssti, sqli, lfi, ssrf, xss, php, upload
try:
    from ..payloads.rce import RCE_CMD, RCE_BYPASS
except Exception:
    RCE_CMD = {}
    RCE_BYPASS = {}

# ★ v2.0 新引擎导入
try:
    from ..core.advanced_engines import ADVANCED_ENCODERS as ADV_ENC
except ImportError:
    ADV_ENC = {}
try:
    from ..core.chinese_ciphers import CHINESE_CIPHERS as CHN_CIPHERS
except ImportError:
    CHN_CIPHERS = {}
try:
    from ..core.crypto_engine import (
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
    from ..core.shell_stego import (
        generate_reverse_shell, list_shell_languages,
        generate_webshell, list_webshell_types,
        analyze_png, extract_lsb, read_exif,
        analyze_file, identify_cipher_text,
    )
    HAS_STEGO = True
except ImportError:
    HAS_STEGO = False
try:
    from ..core.sqli_labs_solver import (
        SQLLabsEngine, LESSON_DB, solve_sqli_labs,
    )
    HAS_SQLI_LABS = True
except ImportError:
    HAS_SQLI_LABS = False
try:
    from ..core.js_challenge_solver import JSChallengeSolver, solve_js_challenge
    HAS_JS_SOLVER = True
except ImportError:
    HAS_JS_SOLVER = False

# 子模块顶层名统一重导出, 保证 `from yang_web.gui import X` 与拆分前一致。
from ._theme import (BG, FG, ACCENT, GREEN, RED, YELLOW, DARK, INPUT_BG, BORDER, apply_theme)
from ._widgets import (_scrollable_text, _label, _button, _entry, _combo, _output_area, _append, _clear_output, _pretty_json)
from ._routing import (_ROUTES, _SEND_BARS, register_route, available_routes, route_text, _set_input, _last_output_line, _SendBar)
from ._panels_codec import (AdvancedEncodePanel, ChineseCipherPanel, CryptoPanel, DecodePanel)
from ._panels_crypto import (HashPanel, JWTPanel, MiscCryptoPanel, PayloadPanel)
from ._panels_tools import (ShellPanel, StegoPanel, ScriptsPanel, DocsPanel, JSGamePanel)
from ._panels_attack import (UrlAttackPanel, SQLLabsPanel)
from ._app import (run_gui)
