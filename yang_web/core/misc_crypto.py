"""Misc Crypto 知识库 — 常见密码类型编码/解码 + 参考图表.

覆盖 CTF Misc 方向 20+ 种常见密码类型，提供编码/解码算法和视觉参考。
"""
import os
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "wordlists" / "data" / "misc_crypto"

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

# 社会主义核心价值观编码
CORE_VALUES = [
    "富强", "民主", "文明", "和谐",
    "自由", "平等", "公正", "法治",
    "爱国", "敬业", "诚信", "友善",
]
CORE_ENCODE = {chr(ord('A') + i): CORE_VALUES[i] for i in range(12)}
CORE_DECODE = {v: k for k, v in CORE_ENCODE.items()}

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

# ═══════════════════════════════════════════
# 密码类型元数据
# ═══════════════════════════════════════════

CIPHER_TYPES = {
    "pigpen": {
        "name": "猪圈密码",
        "aliases": ["pigpen", "猪圈", "masonic", "pigpen_cipher"],
        "category": "图形替换",
        "encode": True, "decode": True,
        "image": "猪圈密码.png",
        "description": "共济会密码变体，用井字格+点标符号表示字母",
        "features": ["井字格图案", "带点/不带点", "4宫格变体"],
    },
    "bacon": {
        "name": "培根密码",
        "aliases": ["bacon", "培根", "baconian"],
        "category": "二进制替换",
        "encode": True, "decode": True,
        "image": "培根密码.jpg",
        "description": "用 A/B 5 位序列表示字母，可隐藏在大小写中",
        "features": ["AAAAA-ZZZZZ", "可隐藏在大小写/粗体中", "24/26字母版本"],
    },
    "polybius": {
        "name": "波利比奥斯棋盘",
        "aliases": ["polybius", "波利比奥斯", "polybius_square"],
        "category": "坐标替换",
        "encode": True, "decode": True,
        "image": "波利比奥斯棋盘.png",
        "description": "5×5 方阵行列坐标表示字母（I=J）",
        "features": ["11-55行列坐标", "I/J合并", "可扩展6x6含数字"],
    },
    "vigenere": {
        "name": "维吉尼亚密码",
        "aliases": ["vigenere", "维吉尼亚", "vig"],
        "category": "多表替换",
        "encode": True, "decode": True,
        "image": "维吉尼亚密码.png",
        "description": "使用密钥词的凯撒密码变体，多表替换",
        "features": ["密钥循环", "维吉尼亚方阵", "26×26表格"],
    },
    "caesar": {
        "name": "凯撒密码",
        "aliases": ["caesar", "凯撒", "caesar_shift"],
        "category": "单表替换",
        "encode": True, "decode": True,
        "image": "凯撒密码加密.jpg",
        "description": "固定偏移字母表，最古老的加密方式",
        "features": ["ROT13是其特例", "偏移量1-25", "可暴力枚举"],
    },
    "adfgx": {
        "name": "ADFGX 加密法",
        "aliases": ["adfgx", "adfgvx"],
        "category": "WWI 军事密码",
        "encode": True, "decode": True,
        "image": "ADFGX加密法.png",
        "description": "一战德军使用的双步加密：Polybius + 列置换",
        "features": ["仅用ADFGX字母", "5×5 Polybius", "需要密钥词"],
    },
    "qwe_keyboard": {
        "name": "QWE 键盘加密法",
        "aliases": ["qwe", "键盘QWE"],
        "category": "键盘映射",
        "encode": True, "decode": True,
        "image": "电脑键盘QWE加密法.jpg",
        "description": "QWERTY键盘顺序映射ABCD...",
        "features": ["Q=A, W=B, E=C...", "键盘布局", "简单替换"],
    },
    "keyboard_chessboard": {
        "name": "电脑键盘棋盘密码",
        "aliases": ["键盘棋盘", "keyboard_chess"],
        "category": "键盘映射",
        "encode": True, "decode": True,
        "image": "电脑键盘棋盘加密.jpg",
        "description": "键盘3行布局，行号+列号表示每个键",
        "features": ["Q=11, W=12...", "数字坐标", "3行键盘映射"],
    },
    "keyboard_coordinate": {
        "name": "电脑键盘坐标加密",
        "aliases": ["键盘坐标", "keyboard_coord"],
        "category": "键盘映射",
        "encode": True, "decode": False,
        "image": "电脑键盘坐标加密.jpg",
        "description": "用键盘矩阵行列坐标表示字母",
        "features": ["行号+列号", "双数字坐标", "参考图"],
    },
    "phone_keypad": {
        "name": "手机键盘密码",
        "aliases": ["phone", "手机键盘", "T9", "nokia"],
        "category": "数字映射",
        "encode": True, "decode": True,
        "image": "手机键盘加密解密.jpg",
        "description": "传统手机九宫格键盘，数字键+按键次数",
        "features": ["A=21, B=22...", "九宫格数字", "双位数字"],
    },
    "atbash": {
        "name": "埃特巴什码",
        "aliases": ["atbash", "埃特巴什"],
        "category": "单表替换",
        "encode": True, "decode": True,
        "image": None,
        "description": "字母表反转（A↔Z, B↔Y...），自反密码",
        "features": ["自反性", "A=Z, B=Y...", "最简单替换"],
    },
    "rail_fence": {
        "name": "栅栏密码",
        "aliases": ["rail_fence", "栅栏", "railfence"],
        "category": "置换",
        "encode": True, "decode": True,
        "image": None,
        "description": "之字形排列后按行读取",
        "features": ["之字形", "多层栅栏", "W型变体"],
    },
    "rot13": {
        "name": "ROT13",
        "aliases": ["rot13", "rot"],
        "category": "单表替换",
        "encode": True, "decode": True,
        "image": None,
        "description": "凯撒密码偏移13位特例，加密=解密",
        "features": ["自反性", "ROT5(数字)", "ROT47(ASCII)"],
    },
    "morse": {
        "name": "摩尔密码",
        "aliases": ["morse", "摩尔", "摩尔斯"],
        "category": "信号编码",
        "encode": True, "decode": True,
        "image": "摩尔密码加密与解密.jpg",
        "description": "点划信号编码，可表现为音频/灯光/文字",
        "features": [".- 长短信号", "可隐藏为音频", "空格/斜杠分隔"],
    },
    "core_values": {
        "name": "核心价值观编码",
        "aliases": ["核心价值观", "24字", "core_values"],
        "category": "中文编码",
        "encode": True, "decode": True,
        "image": None,
        "description": "用12组社会主义核心价值观词组表示A-L共12个字母",
        "features": ["富强=字母", "仅支持A-L", "CTF常见中文编码"],
    },
    "pawnshat": {
        "name": "当铺密码",
        "aliases": ["当铺", "pawnshop", "pawn"],
        "category": "中文编码",
        "encode": True, "decode": True,
        "image": "当铺密码.jpg",
        "description": "汉字出头顶部笔画数映射数字0-9",
        "features": ["笔画头数", "口=0 由=1", "单数字编码"],
    },
    "number_coordinate": {
        "name": "数字坐标加密字母",
        "aliases": ["数字坐标", "number_coord"],
        "category": "坐标替换",
        "encode": True, "decode": False,
        "image": "数字坐标加密字母.png",
        "description": "字母网格坐标表示法，行号+列号",
        "features": ["XY坐标", "数字对", "参考图"],
    },
    "alphabet_order": {
        "name": "字母表顺序加密",
        "aliases": ["字母顺序", "alphabet_order"],
        "category": "数字映射",
        "encode": True, "decode": True,
        "image": "字母表顺序加密法和反字母表加密法和小键盘加密法.jpg",
        "description": "A=1, B=2...的简单数字对应",
        "features": ["A=1 B=2...", "反字母A=26", "小键盘映射"],
    },
    "standard_galactic": {
        "name": "标准银河字母",
        "aliases": ["SGA", "标准银河", "galactic", "enchanting_table"],
        "category": "符号替换",
        "encode": True, "decode": True,
        "image": "标准银河字母.png",
        "description": "Minecraft 附魔台文字，风格化字母替换",
        "features": ["Minecraft风格", "特殊符号字符", "Unicode"],
    },
    "binary": {
        "name": "二进制加密",
        "aliases": ["binary", "二进制", "2进制"],
        "category": "进制编码",
        "encode": True, "decode": True,
        "image": None,
        "description": "ASCII/Unicode 字符的二进制表示",
        "features": ["7位/8位", "空格分隔", "可配合其他编码"],
    },
    "reverse": {
        "name": "倒序加密",
        "aliases": ["reverse", "倒序", "倒叙", "反转"],
        "category": "置换",
        "encode": True, "decode": True,
        "image": None,
        "description": "字符串直接反转，最简单的置换操作",
        "features": ["ABC→CBA", "可单词/句子", "非全反转注意"],
    },
    "jefferson_wheel": {
        "name": "托马斯·杰斐逊转轮密码",
        "aliases": ["jefferson", "转轮", "rotor", "轮转"],
        "category": "多表替换",
        "encode": True, "decode": True,
        "image": None,
        "description": "多轮盘密码机，密钥是轮盘使用顺序",
        "features": ["14个轮盘", "密钥控制顺序", "破解需遍历"],
    },
    "fes_hieroglyph": {
        "name": "菲斯象形文字",
        "aliases": ["菲斯", "fes", "hieroglyph"],
        "category": "符号替换",
        "encode": False, "decode": False,
        "image": "非斯的象形文字翻译图.png",
        "description": "图形符号对应字母的替换密码（仅参考图）",
        "features": ["象形图→字母", "视觉参考", "需手动对照"],
    },
    "blue_punch_card": {
        "name": "蓝色打孔卡",
        "aliases": ["punchcard", "打孔卡", "blue_punch"],
        "category": "编码参考",
        "encode": False, "decode": False,
        "image": "Blue-punch-card-front-horiz.png",
        "description": "IBM 打孔卡编码参考图，二进制存储的早期形式",
        "features": ["IBM格式", "80列", "矩形孔"],
    },
}

# ═══════════════════════════════════════════
# 编码/解码函数
# ═══════════════════════════════════════════

def _clean_text(text: str) -> str:
    return text.upper().replace(' ', '').replace('\n', '').replace('\r', '')


# ── 猪圈密码 ──────────────────────────────
def pigpen_encode(text: str) -> str:
    """将字母编码为猪圈密码符号（用 ASCII 近似表示）。"""
    result = []
    for c in _clean_text(text):
        if c in PIGPEN_ENCODE:
            result.append(PIGPEN_ENCODE[c])
        else:
            result.append(c)
    return ' '.join(result)


def pigpen_decode(symbols: str) -> str:
    """猪圈密码符号 → 字母（仅支持预定义字符）。"""
    rev = {v: k for k, v in PIGPEN_ENCODE.items()}
    # Try splitting by common separators
    for sep in [' ', '|', '/']:
        if sep in symbols:
            parts = symbols.split(sep)
            return ''.join(rev.get(p.strip(), p.strip()) for p in parts if p.strip())
    return symbols  # can't auto-parse


# ── 培根密码 ──────────────────────────────
def bacon_encode(text: str) -> str:
    return ' '.join(BACON_24.get(c, c) for c in _clean_text(text))


def bacon_decode(cipher_text: str) -> str:
    rev = {v: k for k, v in BACON_24.items()}
    result = []
    parts = cipher_text.replace(' ', '').lower()
    for i in range(0, len(parts) - 4, 5):
        chunk = parts[i:i+5].upper()
        result.append(rev.get(chunk, '?'))
    return ''.join(result)


# ── Polybius 棋盘 ─────────────────────────
def polybius_encode(text: str) -> str:
    result = []
    for c in _clean_text(text):
        if c == 'J': c = 'I'
        for row in range(5):
            for col in range(5):
                if POLYBIUS_GRID[row][col] == c:
                    result.append(f"{row+1}{col+1}")
                    break
    return ' '.join(result)


def polybius_decode(cipher_text: str) -> str:
    result = []
    nums = [n for n in cipher_text.replace(' ', '') if n.isdigit()]
    for i in range(0, len(nums) - 1, 2):
        row = int(nums[i]) - 1
        col = int(nums[i+1]) - 1
        if 0 <= row < 5 and 0 <= col < 5:
            result.append(POLYBIUS_GRID[row][col])
    return ''.join(result)


# ── 维吉尼亚密码 ─────────────────────────
def vigenere_encode(text: str, key: str) -> str:
    text, key = text.upper(), key.upper()
    result = []
    ki = 0
    for c in text:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - 65
            result.append(chr((ord(c) - 65 + shift) % 26 + 65))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)


def vigenere_decode(cipher_text: str, key: str) -> str:
    text, key = cipher_text.upper(), key.upper()
    result = []
    ki = 0
    for c in text:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - 65
            result.append(chr((ord(c) - 65 - shift) % 26 + 65))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)


# ── QWE 键盘 ──────────────────────────────
def qwe_encode(text: str) -> str:
    return ''.join(QWE_ENCODE.get(c, c) for c in _clean_text(text))


def qwe_decode(cipher_text: str) -> str:
    return ''.join(QWE_DECODE.get(c, c) for c in _clean_text(cipher_text))


# ── 键盘棋盘 ──────────────────────────────
def keyboard_chess_encode(text: str) -> str:
    return ' '.join(KEYBOARD_CHESSBOARD.get(c, '??') for c in _clean_text(text))


def keyboard_chess_decode(cipher_text: str) -> str:
    parts = cipher_text.split()
    return ''.join(CHESSBOARD_DECODE.get(p, '?') for p in parts)


# ── 手机键盘 ──────────────────────────────
def phone_encode(text: str) -> str:
    return ' '.join(PHONE_KEYPAD.get(c, '??') for c in _clean_text(text))


def phone_decode(cipher_text: str) -> str:
    parts = cipher_text.split()
    return ''.join(PHONE_DECODE.get(p, '?') for p in parts)


# ── 核心价值观 ────────────────────────────
def core_values_encode(text: str) -> str:
    return ' '.join(CORE_ENCODE.get(c, c) for c in _clean_text(text))


def core_values_decode(cipher_text: str) -> str:
    parts = cipher_text.split()
    return ''.join(CORE_DECODE.get(p, '?') for p in parts)


# ── 当铺密码 ─────────────────────────────
def pawnshat_encode(text: str) -> str:
    result = []
    for c in text:
        if c.isdigit() and int(c) in PAWNSHOP_REV:
            result.append(PAWNSHOP_REV[int(c)])
        else:
            result.append(c)
    return ' '.join(result)


def pawnshat_decode(cipher_text: str) -> str:
    result = []
    for c in cipher_text.replace(' ', ''):
        result.append(str(PAWNSHOP_MAP.get(c, c)))
    return ''.join(result)


# ── 字母表顺序 ────────────────────────────
def alphabet_order_encode(text: str) -> str:
    return ' '.join(str(ord(c) - 64) for c in _clean_text(text) if c.isalpha())


def alphabet_order_decode(cipher_text: str) -> str:
    result = []
    for n in cipher_text.split():
        try:
            result.append(chr(int(n) + 64))
        except ValueError:
            result.append('?')
    return ''.join(result)


# ── 标准银河字母 ─────────────────────────
def sga_encode(text: str) -> str:
    return ''.join(SGA_CHARS.get(c, c) for c in _clean_text(text))


def sga_decode(cipher_text: str) -> str:
    return ''.join(SGA_DECODE.get(c, c) for c in cipher_text)


# ── 二进制 ────────────────────────────────
def binary_encode(text: str) -> str:
    return ' '.join(f"{ord(c):08b}" for c in text)


def binary_decode(cipher_text: str) -> str:
    clean = cipher_text.replace(' ', '').replace('\n', '').replace('\r', '').strip()
    if not clean:
        return ''
    result = []
    # Try space-separated first
    parts = cipher_text.strip().split()
    if len(parts) > 1:
        for b in parts:
            try:
                val = int(b, 2)
                if 0 <= val <= 0x10FFFF:
                    result.append(chr(val))
            except (ValueError, OverflowError):
                pass
        if result:
            return ''.join(result)
    # Try 8-bit or 7-bit chunks
    for width in [8, 7]:
        result = []
        for i in range(0, len(clean), width):
            chunk = clean[i:i+width]
            if len(chunk) < width:
                continue
            try:
                val = int(chunk, 2)
                if 0 <= val <= 0x10FFFF:
                    result.append(chr(val))
            except (ValueError, OverflowError):
                pass
        if result:
            return ''.join(result)
    return cipher_text


# ── 倒序 ──────────────────────────────────
def reverse_encode(text: str) -> str:
    return text[::-1]


def reverse_decode(cipher_text: str) -> str:
    return cipher_text[::-1]  # self-inverse


# ── ADFGX ─────────────────────────────────
def _adfgx_polybius(text: str, keyword: str = "") -> str:
    """ADFGX Polybius substitution phase."""
    letters = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'  # J → I
    result = []
    for c in text.upper().replace('J', 'I'):
        if c in letters:
            idx = letters.index(c)
            row, col = idx // 5, idx % 5
            result.append("ADFGX"[row] + "ADFGX"[col])
        elif c.isdigit():
            result.append(c)
    return ''.join(result)


def adfgx_encode(text: str, keyword: str) -> str:
    sub = _adfgx_polybius(text)
    if not keyword:
        return ' '.join(sub[i:i+2] for i in range(0, len(sub), 2))
    # Columnar transposition
    kw = keyword.upper()
    cols = {c: [] for c in kw}
    for i, ch in enumerate(sub):
        cols[kw[i % len(kw)]].append(ch)
    sorted_cols = sorted(cols.keys())
    return ''.join(''.join(cols[k]) for k in sorted_cols)


def adfgx_decode(cipher_text: str, keyword: str) -> str:
    if not keyword:
        letters = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
        result = []
        for i in range(0, len(cipher_text) - 1, 2):
            r, c = cipher_text[i], cipher_text[i+1]
            if r in 'ADFGX' and c in 'ADFGX':
                idx = 'ADFGX'.index(r) * 5 + 'ADFGX'.index(c)
                result.append(letters[idx])
        return ''.join(result)
    # With keyword: reverse columnar transposition
    kw = keyword.upper()
    kw_sorted = sorted(kw)
    col_len = len(cipher_text) // len(kw)
    remainder = len(cipher_text) % len(kw)
    col_lengths = {k: col_len + (1 if i < remainder else 0) for i, k in enumerate(kw_sorted)}
    pos = 0
    cols = {}
    for k in kw_sorted:
        cols[k] = cipher_text[pos:pos + col_lengths[k]]
        pos += col_lengths[k]
    # Reconstruct pre-transposition text
    result = []
    for i in range(col_len + 1):
        for k in kw:
            if i < col_lengths.get(k, 0):
                result.append(cols[k][i])
    sub = ''.join(result)
    letters = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    plain = []
    for i in range(0, len(sub) - 1, 2):
        r, c = sub[i], sub[i+1]
        if r in 'ADFGX' and c in 'ADFGX':
            idx = 'ADFGX'.index(r) * 5 + 'ADFGX'.index(c)
            plain.append(letters[idx])
    return ''.join(plain)


# ── 杰斐逊转轮 ───────────────────────────
def jefferson_decode(cipher_text: str, key: list, rotors: list = None) -> list:
    """托马斯·杰斐逊转轮密码解码，返回所有可能的明文。"""
    if rotors is None:
        rotors = JEFFERSON_ROTORS
    tmp_list = []
    for i in range(len(rotors)):
        k = key[i] - 1
        rotor = rotors[k]
        target = cipher_text[i] if i < len(cipher_text) else cipher_text[-1]
        for j in range(len(rotor)):
            if target.upper() == rotor[j]:
                tmp = rotor[j:] + rotor[:j] if j > 0 else rotor
                tmp_list.append(tmp)
                break
    # Build column strings
    messages = []
    col_len = min(len(t) for t in tmp_list)
    for i in range(col_len):
        col = ''.join(t[i] for t in tmp_list)
        messages.append(col)
    return messages


# ═══════════════════════════════════════════
# 查询 & 工具函数
# ═══════════════════════════════════════════

def list_ciphers(category: str = None) -> list:
    """列出所有已注册的密码类型。"""
    result = []
    for cid, info in CIPHER_TYPES.items():
        if category and info.get("category") != category:
            continue
        result.append({
            "id": cid,
            **info,
        })
    return result


def get_cipher(cipher_id: str) -> dict:
    """返回指定密码类型的完整信息。"""
    return CIPHER_TYPES.get(cipher_id.lower())


def search_ciphers(query: str) -> list:
    """按名称/别名搜索密码类型。"""
    q = query.lower()
    results = []
    for cid, info in CIPHER_TYPES.items():
        text = cid + " " + info["name"] + " " + " ".join(info.get("aliases", [])) + " " + info["category"]
        if q in text.lower():
            results.append({"id": cid, **info})
    return results


def get_image_path(cipher_id: str) -> str:
    """返回密码类型对应的参考图路径。"""
    info = CIPHER_TYPES.get(cipher_id.lower())
    if info and info.get("image"):
        img_path = DATA_DIR / info["image"]
        if img_path.exists():
            return str(img_path)
    return ""


def get_categories() -> list:
    """返回所有类别。"""
    cats = set()
    for info in CIPHER_TYPES.values():
        cats.add(info["category"])
    return sorted(cats)


def encode(cipher_id: str, text: str, **kwargs) -> str:
    """通用编码入口。"""
    cid = cipher_id.lower().replace('-', '_').replace(' ', '_')
    funcs = {
        "pigpen": pigpen_encode,
        "bacon": bacon_encode, "baconian": bacon_encode,
        "polybius": polybius_encode, "polybius_square": polybius_encode,
        "vigenere": lambda t: vigenere_encode(t, kwargs.get("key", "A")),
        "qwe": qwe_encode, "qwe_keyboard": qwe_encode,
        "keyboard_chessboard": keyboard_chess_encode,
        "phone": phone_encode, "phone_keypad": phone_encode,
        "core_values": core_values_encode,
        "alphabet_order": alphabet_order_encode,
        "sga": sga_encode, "standard_galactic": sga_encode,
        "binary": binary_encode,
        "reverse": reverse_encode,
        "pawnshat": pawnshat_encode,
        "adfgx": lambda t: adfgx_encode(t, kwargs.get("key", "")),
        "jefferson_wheel": lambda t: jefferson_decode(t, kwargs.get("key", []), kwargs.get("rotors")),
    }
    if cid in funcs:
        return funcs[cid](text)
    return f"[!] 不支持编码: {cipher_id}"


def decode(cipher_id: str, cipher_text: str, **kwargs) -> str:
    """通用解码入口。"""
    cid = cipher_id.lower().replace('-', '_').replace(' ', '_')
    funcs = {
        "pigpen": pigpen_decode,
        "bacon": bacon_decode, "baconian": bacon_decode,
        "polybius": polybius_decode, "polybius_square": polybius_decode,
        "vigenere": lambda t: vigenere_decode(t, kwargs.get("key", "A")),
        "qwe": qwe_decode, "qwe_keyboard": qwe_decode,
        "keyboard_chessboard": keyboard_chess_decode,
        "phone": phone_decode, "phone_keypad": phone_decode,
        "core_values": core_values_decode,
        "alphabet_order": alphabet_order_decode,
        "sga": sga_decode, "standard_galactic": sga_decode,
        "binary": binary_decode,
        "reverse": reverse_decode,
        "pawnshat": pawnshat_decode,
        "adfgx": lambda t: adfgx_decode(t, kwargs.get("key", "")),
        "jefferson_wheel": lambda t: jefferson_decode(t, kwargs.get("key", []), kwargs.get("rotors")),
    }
    if cid in funcs:
        return funcs[cid](cipher_text)
    return f"[!] 不支持解码: {cipher_id}"
