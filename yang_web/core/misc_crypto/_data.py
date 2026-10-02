"""yang_web.core.misc_crypto 子模块 _data（自 misc_crypto.py 拆分，请勿手工重排）。"""

import os
import re
import base64 as b64
import binascii
import html as html_mod
import codecs
import urllib.parse
from pathlib import Path



DATA_DIR = Path(__file__).resolve().parent.parent / "wordlists" / "data" / "misc_crypto"

try:
    from .. import cipher_classic, cipher_keyed, chinese_ciphers2, esoteric_lang, binary_codes
except ImportError:
    import cipher_classic, cipher_keyed, chinese_ciphers2, esoteric_lang, binary_codes

# 扩展模块列表：encode/decode/list_ciphers 等统一 fallback 遍历
EXTRA_MODULES = [cipher_classic, cipher_keyed, chinese_ciphers2, esoteric_lang, binary_codes]

# ═══════════════════════════════════════════
# 数据表 / 常量
# ═══════════════════════════════════════════

# 猪圈密码 (Pigpen) — 4 宫格变体
PIGPEN_ENCODE = {
    'A': '🞟', 'B': '🞞', 'C': '🞜', 'D': '🞝', 'E': '⊞',
    'F': '⊟', 'G': '⊠', 'H': '⊡', 'I': '🞥', 'J': '🞧',
    'K': '🞤', 'L': '⊟', 'M': '⊠', 'N': '⊡', 'O': '🞢',
    'P': '🞣', 'Q': '🞦', 'R': '⊞', 'S': '⊟', 'T': '⊡',
    'U': '≻🞭', 'V': '≻⊞', 'W': '≻⊟', 'X': '≻⊡', 'Y': '≻🞤', 'Z': '≻🞧',
}

# 培根密码 (Bacon) — 24 字母 A/B 编码
BACON_24 = {
    'A': 'AAAAA', 'B': 'AAAAB', 'C': 'AAABA', 'D': 'AAABB', 'E': 'AABAA',
    'F': 'AABAB', 'G': 'AABBA', 'H': 'AABBB', 'I': 'ABAAA', 'J': 'ABAAB',
    'K': 'ABABA', 'L': 'ABABB', 'M': 'ABBAA', 'N': 'ABBAB', 'O': 'ABBBA',
    'P': 'ABBBB', 'Q': 'BAAAA', 'R': 'BAAAB', 'S': 'BAABA', 'T': 'BAABB',
    'U': 'BABAA', 'V': 'BABAB', 'W': 'BABBA', 'X': 'BABBB', 'Y': 'BBAAA',
    'Z': 'BBAAB',
}

# Polybius 方阵 (5x5, I/J merged)
POLYBIUS_GRID = [
    ['A', 'B', 'C', 'D', 'E'],
    ['F', 'G', 'H', 'I', 'K'],
    ['L', 'M', 'N', 'O', 'P'],
    ['Q', 'R', 'S', 'T', 'U'],
    ['V', 'W', 'X', 'Y', 'Z'],
]

# 键盘坐标 (标准 QWERTY 行)
KEYBOARD_ROWS = {
    'row1': 'QWERTYUIOP',
    'row2': 'ASDFGHJKL',
    'row3': 'ZXCVBNM',
}

# QWE 加密法 (Q=A, W=B, E=C...)
_QWE_ORDER = "QWERTYUIOPASDFGHJKLZXCVBNM"
_ABC_ORDER  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
QWE_ENCODE = dict(zip(_ABC_ORDER, _QWE_ORDER))
QWE_DECODE = dict(zip(_QWE_ORDER, _ABC_ORDER))

# 键盘棋盘密码 (1-9宫格映射)
KEYBOARD_CHESSBOARD = {
    'Q': '11', 'W': '12', 'E': '13', 'R': '14', 'T': '15', 'Y': '16', 'U': '17', 'I': '18', 'O': '19', 'P': '10',
    'A': '21', 'S': '22', 'D': '23', 'F': '24', 'G': '25', 'H': '26', 'J': '27', 'K': '28', 'L': '29',
    'Z': '31', 'X': '32', 'C': '33', 'V': '34', 'B': '35', 'N': '36', 'M': '37',
}
CHESSBOARD_DECODE = {v: k for k, v in KEYBOARD_CHESSBOARD.items()}

# 手机键盘密码 (T9)
PHONE_KEYPAD = {
    'A': '21', 'B': '22', 'C': '23', 'D': '31', 'E': '32', 'F': '33',
    'G': '41', 'H': '42', 'I': '43', 'J': '51', 'K': '52', 'L': '53',
    'M': '61', 'N': '62', 'O': '63', 'P': '71', 'Q': '72', 'R': '73', 'S': '74',
    'T': '81', 'U': '82', 'V': '83', 'W': '91', 'X': '92', 'Y': '93', 'Z': '94',
}
PHONE_DECODE = {v: k for k, v in PHONE_KEYPAD.items()}

# 标准银河字母 (SGA) — Minecraft 附魔台
SGA_CHARS = {
    'A': 'ᔑ', 'B': 'ʖ', 'C': 'ᓵ', 'D': '↸', 'E': 'ᒷ',
    'F': '⎓', 'G': '⊣', 'H': '⍑', 'I': '╎', 'J': '⋮',
    'K': 'ꖌ', 'L': 'ꖎ', 'M': 'ᒲ', 'N': 'リ', 'O': '𝙹',
    'P': '!',  'Q': 'ᑑ', 'R': '∷', 'S': 'ᓭ', 'T': 'ℸ',
    'U': '⚍', 'V': '⍊', 'W': '∴', 'X': '/', 'Y': '‖',
    'Z': '⋃',
}
SGA_DECODE = {v: k for k, v in SGA_CHARS.items() if len(v) == 1}

# ADFGX 密码表 (5x5)
ADFGX_TABLE = {
    'A': 'AA', 'B': 'AF', 'C': 'AD', 'D': 'AD', 'E': 'FG',
    'F': 'AX', 'G': 'AG', 'H': 'FV', 'I': 'FX', 'J': 'FX',
    'K': 'GA', 'L': 'GD', 'M': 'GG', 'N': 'GX', 'O': 'GF',
    'P': 'GV', 'Q': 'XA', 'R': 'XD', 'S': 'XG', 'T': 'XF',
    'U': 'XV', 'V': 'VA', 'W': 'VG', 'X': 'VF', 'Y': 'VD',
    'Z': 'VX',
}

# 当铺密码 — 中文笔画数映射数字
PAWNSHOP_MAP = {
    '口': 0, '由': 1, '中': 2, '人': 3, '工': 4,
    '大': 5, '王': 6, '夫': 7, '井': 8, '羊': 9,
}
PAWNSHOP_REV = {v: k for k, v in PAWNSHOP_MAP.items()}

# 托马斯·杰斐逊转轮密码（默认轮子）
JEFFERSON_ROTORS = [
    "ZWAXJGDLUBVIQHKYPNTCRMOSFE", "KPBELNACZDTRXMJQOYHGVSFUWI",
    "BDMAIZVRNSJUWFHTEQGYXPLOCK", "RPLNDVHGFCUKTEBSXQYIZMJWAO",
    "IHFRLABEUOTSGJVDKCPMNZQWXY", "AMKGHIWPNYCJBFZDRUSLOQXVET",
    "GWTHSPYBXIZULVKMRAFDCEONJQ", "NOZUTWDCVRJLXKISEFAPMYGHBQ",
    "QWATDSRFHENYVUBMCOIKZGJXPL", "WABMCXPLTDSRJQZGOIKFHENYVU",
    "XPLTDAOIKFZGHENYSRUBMCQWVJ", "TDSWAYXPLVUBOIKZGJRFHENMCQ",
    "BMCSRFHLTDENQWAOXPYVUIKZGJ", "XPHKZGJTDSENYVUBMLAOIRFCQW",
]


# ── Morse 摩斯密码 ─────────────────────────
MORSE_ENCODE_MAP = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.',
    'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---',
    'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---',
    'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-',
    'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--',
    'Z': '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    '.': '.-.-.-', ',': '--..--', '?': '..--..', '/': '-..-.',
    '@': '.--.-.', '(': '-.--.', ')': '-.--.-', '&': '.-...',
    ':': '---...', '=': '-...-', '-': '-....-', '+': '.-.-.',
    '"': '.-..-.', '\'': '.----.', '_': '..--.-', '!': '-.-.--',
}
MORSE_DECODE_MAP = {v: k for k, v in MORSE_ENCODE_MAP.items()}


# ── Base58 ────────────────────────────────
_B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


# ── Keyboard Coordinate 键盘坐标 ────────────
KEYBOARD_COORD_MAP = {
    'Q': '11', 'W': '12', 'E': '13', 'R': '14', 'T': '15',
    'Y': '16', 'U': '17', 'I': '18', 'O': '19', 'P': '10',
    'A': '21', 'S': '22', 'D': '23', 'F': '24', 'G': '25',
    'H': '26', 'J': '27', 'K': '28', 'L': '29',
    'Z': '31', 'X': '32', 'C': '33', 'V': '34', 'B': '35',
    'N': '36', 'M': '37',
}
KEYBOARD_COORD_REV = {v: k for k, v in KEYBOARD_COORD_MAP.items()}


# ── Number Coordinate 数字坐标 ──────────────
NUMBER_COORD_MAP = {c: f"{i}" for i, c in enumerate('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}
NUMBER_COORD_REV = {v: k for k, v in NUMBER_COORD_MAP.items()}
