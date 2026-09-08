# -*- coding: utf-8 -*-
"""cipher_classic.py — 经典编码/替换类密码（无 key 或固定 key）

覆盖 CTF 高频经典编码，纯 Python 标准库零依赖实现。
API 风格与 misc_crypto.py 一致：
  - <name>_encode(text) / <name>_decode(text)
  - CIPHERS 注册表
  - encode() / decode() 统一分发入口
  - list_ciphers() / get_cipher() / search_ciphers()
"""
import base64
import re

# ═══════════════════════════════════════════════════════════
# 常量表
# ═══════════════════════════════════════════════════════════

# DNA 编码：每 2 bit -> 1 碱基（A=00 C=01 G=10 T=11）
DNA_MAP = {'A': '00', 'C': '01', 'G': '10', 'T': '11'}
DNA_REV = {v: k for k, v in DNA_MAP.items()}

# Baudot ITA2 字母表（5-bit，big-endian bit order）
BAUDOT = {
    'A': '00011', 'B': '11001', 'C': '01110', 'D': '01001', 'E': '00001',
    'F': '01101', 'G': '11010', 'H': '10100', 'I': '00110', 'J': '01011',
    'K': '01111', 'L': '10010', 'M': '11100', 'N': '01100', 'O': '11000',
    'P': '10110', 'Q': '10111', 'R': '01010', 'S': '00101', 'T': '10000',
    'U': '00111', 'V': '11110', 'W': '10011', 'X': '11101', 'Y': '10101',
    'Z': '10001',
}
BAUDOT_REV = {v: k for k, v in BAUDOT.items()}

# Cisco Type7 固定密钥
TYPE7_KEY = "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"

# 云影密码（01248）：十进制数字 -> 0/1/2/4/8 组合
YUNYING_DIGIT = {
    '0': '0', '1': '1', '2': '2', '3': '12', '4': '4',
    '5': '14', '6': '24', '7': '124', '8': '8', '9': '18',
}
YUNYING_REV = {v: k for k, v in YUNYING_DIGIT.items()}

# 敲击码 tap code：5x5 Polybius（I/J 合并，去 K）
TAP_ALPHABET = "ABCDEFGHIJLMNOPQRSTUVWXYZ"  # 无 K（I/J 合并，25 字母）

# NATO 音标
NATO = {
    'A': 'Alpha', 'B': 'Bravo', 'C': 'Charlie', 'D': 'Delta', 'E': 'Echo',
    'F': 'Foxtrot', 'G': 'Golf', 'H': 'Hotel', 'I': 'India', 'J': 'Juliett',
    'K': 'Kilo', 'L': 'Lima', 'M': 'Mike', 'N': 'November', 'O': 'Oscar',
    'P': 'Papa', 'Q': 'Quebec', 'R': 'Romeo', 'S': 'Sierra', 'T': 'Tango',
    'U': 'Uniform', 'V': 'Victor', 'W': 'Whiskey', 'X': 'X-ray', 'Y': 'Yankee',
    'Z': 'Zulu',
}
NATO_REV = {v.lower(): k for k, v in NATO.items()}

# 盲文 Braille（Unicode U+2800 起）
BRAILLE = {
    'A': '\u2801', 'B': '\u2803', 'C': '\u2809', 'D': '\u2819', 'E': '\u2811',
    'F': '\u280b', 'G': '\u281b', 'H': '\u2813', 'I': '\u280a', 'J': '\u281a',
    'K': '\u2805', 'L': '\u2807', 'M': '\u280d', 'N': '\u281d', 'O': '\u2815',
    'P': '\u280f', 'Q': '\u281f', 'R': '\u2817', 'S': '\u280e', 'T': '\u281e',
    'U': '\u2825', 'V': '\u2827', 'W': '\u283a', 'X': '\u282d', 'Y': '\u283d',
    'Z': '\u2835',
}
BRAILLE_REV = {v: k for k, v in BRAILLE.items()}

# 九宫格 handycode（手机 T9 多击）
HANDY = {
    'A': '2', 'B': '22', 'C': '222', 'D': '3', 'E': '33', 'F': '333',
    'G': '4', 'H': '44', 'I': '444', 'J': '5', 'K': '55', 'L': '555',
    'M': '6', 'N': '66', 'O': '666', 'P': '7', 'Q': '77', 'R': '777',
    'S': '7777', 'T': '8', 'U': '88', 'V': '888', 'W': '9', 'X': '99',
    'Y': '999', 'Z': '9999',
}
HANDY_REV = {v: k for k, v in HANDY.items()}

# QWERTY <-> Dvorak 键位映射
_QWERTY_KEYS = "`1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./"
_DVORAK_KEYS = "`1234567890[]',.pyfgcrl/=\\aoeuidhtns-;qjkxbmwvz"

# 键盘上档键（shift+数字 -> 符号）
SHIFT_SYMBOL = {'1': '!', '2': '@', '3': '#', '4': '$', '5': '%',
                '6': '^', '7': '&', '8': '*', '9': '(', '0': ')'}
SHIFT_SYMBOL_REV = {v: k for k, v in SHIFT_SYMBOL.items()}

# 音符密码 Solresol（7 音节循环 A=do B=re C=mi D=fa E=sol F=la G=si）
SOLRESOL = ['do', 're', 'mi', 'fa', 'sol', 'la', 'si']
SOLRESOL_REV = {v: i for i, v in enumerate(SOLRESOL)}

# Bubble Babble（18 个辅音字母）
_BB_VOWELS = "aeiouy"
_BB_CONSONANTS = "bcdfghklmnprstvzx"  # 17 个


# ═══════════════════════════════════════════════════════════
# 算法实现
# ═══════════════════════════════════════════════════════════

# ---------- DNA ----------
def dna_encode(text: str) -> str:
    data = text.encode('utf-8')
    bits = ''.join(f'{b:08b}' for b in data)
    return ''.join(DNA_REV.get(bits[i:i + 2], '') for i in range(0, len(bits), 2))

def dna_decode(cipher: str) -> str:
    s = ''.join(c for c in cipher.upper() if c in 'ACGT')
    bits = ''.join(DNA_MAP[c] for c in s)
    # 补到 8 的倍数
    bits = bits[:len(bits) - len(bits) % 8]
    out = bytearray()
    for i in range(0, len(bits), 8):
        out.append(int(bits[i:i + 8], 2))
    return out.decode('utf-8', errors='replace')

# ---------- A1Z26 ----------
def a1z26_encode(text: str) -> str:
    out = []
    for c in text.upper():
        if 'A' <= c <= 'Z':
            out.append(str(ord(c) - 64))
        else:
            out.append(c)
    return ' '.join(out)

def a1z26_decode(cipher: str) -> str:
    out = []
    for tok in re.split(r'[\s,;]+', cipher.strip()):
        if tok.isdigit() and 1 <= int(tok) <= 26:
            out.append(chr(int(tok) + 64))
        elif tok:
            out.append(tok)
    return ''.join(out)

# ---------- Baudot ----------
def baudot_encode(text: str) -> str:
    return ' '.join(BAUDOT[c] for c in text.upper() if c in BAUDOT)

def baudot_decode(cipher: str) -> str:
    toks = re.findall(r'[01]{5}', cipher.replace(' ', ''))
    return ''.join(BAUDOT_REV.get(t, '?') for t in toks)

# ---------- Cisco Type7 ----------
def type7_encode(text: str) -> str:
    out = []
    for i, c in enumerate(text):
        x = ord(c) ^ ord(TYPE7_KEY[i % len(TYPE7_KEY)])
        out.append(f'{x:02X}')
    return ''.join(out)

def type7_decode(cipher: str) -> str:
    s = re.sub(r'[^0-9a-fA-F]', '', cipher)
    out = []
    for i in range(0, len(s) - 1, 2):
        x = int(s[i:i + 2], 16)
        out.append(chr(x ^ ord(TYPE7_KEY[(i // 2) % len(TYPE7_KEY)])))
    return ''.join(out)

# ---------- 云影密码 01248 ----------
# 每个十进制位用 0/1/2/4/8 组合表示；位之间空格分隔，字符之间 | 分隔
def yunying_encode(text: str) -> str:
    out = []
    for c in text:
        dec = str(ord(c))
        out.append(' '.join(YUNYING_DIGIT[d] for d in dec))
    return ' | '.join(out)

def yunying_decode(cipher: str) -> str:
    out = []
    for chunk in cipher.split('|'):
        chunk = chunk.strip()
        if not chunk:
            continue
        digits = []
        for g in chunk.split():
            digits.append(str(sum(int(x) for x in g if x in '01248')))
        try:
            out.append(chr(int(''.join(digits))))
        except (ValueError, OverflowError):
            out.append('?')
    return ''.join(out)

# ---------- 敲击码 tap code ----------
def tap_code_encode(text: str) -> str:
    out = []
    for c in text.upper():
        if c == 'K':
            c = 'C'  # I/J 合并，K 归 C
        if c in TAP_ALPHABET:
            idx = TAP_ALPHABET.index(c)
            row, col = idx // 5 + 1, idx % 5 + 1
            out.append(f'{row},{col}')
    return ' '.join(out)

def tap_code_decode(cipher: str) -> str:
    out = []
    for m in re.finditer(r'(\d)\s*[,.\s]\s*(\d)', cipher):
        row, col = int(m.group(1)), int(m.group(2))
        if 1 <= row <= 5 and 1 <= col <= 5:
            out.append(TAP_ALPHABET[(row - 1) * 5 + (col - 1)])
    return ''.join(out)

# ---------- NATO ----------
def nato_encode(text: str) -> str:
    return ' '.join(NATO.get(c, c) for c in text.upper())

def nato_decode(cipher: str) -> str:
    out = []
    for w in re.findall(r'[A-Za-z]+', cipher):
        out.append(NATO_REV.get(w.lower(), w[0].upper() if w else ''))
    return ''.join(out)

# ---------- 盲文 ----------
def braille_encode(text: str) -> str:
    return ''.join(BRAILLE.get(c, c) for c in text.upper())

def braille_decode(cipher: str) -> str:
    return ''.join(BRAILLE_REV.get(c, c) for c in cipher)

# ---------- Burrows-Wheeler Transform ----------
def bwt_encode(text: str) -> str:
    s = text + '\x00'  # 用 \x00 作结束标记，简化逆变换
    n = len(s)
    rotations = sorted(s[i:] + s[:i] for i in range(n))
    return ''.join(r[-1] for r in rotations)

def bwt_decode(cipher: str) -> str:
    n = len(cipher)
    table = [''] * n
    for _ in range(n):
        table = sorted(c + t for c, t in zip(cipher, table))
    for row in table:
        if row.endswith('\x00'):
            return row[:-1]
    return ''.join(table[0][:-1]) if table else ''

# ---------- Manchester ----------
def manchester_encode(text: str) -> str:
    data = text.encode('utf-8')
    bits = ''.join(f'{b:08b}' for b in data)
    return ''.join('01' if b == '0' else '10' for b in bits)

def manchester_decode(cipher: str) -> str:
    s = ''.join(c for c in cipher if c in '01')
    s = s[:len(s) - len(s) % 2]
    bits = ''.join('0' if s[i:i + 2] == '01' else '1' if s[i:i + 2] == '10' else '' for i in range(0, len(s), 2))
    bits = bits[:len(bits) - len(bits) % 8]
    out = bytearray()
    for i in range(0, len(bits), 8):
        out.append(int(bits[i:i + 8], 2))
    return out.decode('utf-8', errors='replace')

# ---------- 键盘键码 keyCode ----------
def keyboard_keycode_encode(text: str) -> str:
    return ' '.join(str(ord(c)) for c in text)

def keyboard_keycode_decode(cipher: str) -> str:
    out = []
    for tok in re.findall(r'\d+', cipher):
        n = int(tok)
        if 0 <= n <= 0x10FFFF:
            out.append(chr(n))
    return ''.join(out)

# ---------- 键盘上档键转数字 ----------
def keyboard_shift_encode(text: str) -> str:
    return ''.join(SHIFT_SYMBOL.get(c, c) for c in text)

def keyboard_shift_decode(cipher: str) -> str:
    return ''.join(SHIFT_SYMBOL_REV.get(c, c) for c in cipher)

# ---------- 九宫格 handycode ----------
def handycode_encode(text: str) -> str:
    return ' '.join(HANDY.get(c, c) for c in text.upper())

def handycode_decode(cipher: str) -> str:
    out = []
    for tok in re.split(r'[\s,;]+', cipher.strip()):
        if tok and tok.isdigit():
            out.append(HANDY_REV.get(tok, '?'))
    return ''.join(out)

# ---------- Dvorak ----------
def dvorak_encode(text: str) -> str:
    return ''.join(_DVORAK_KEYS[_QWERTY_KEYS.index(c)] if c in _QWERTY_KEYS else c for c in text)

def dvorak_decode(cipher: str) -> str:
    return ''.join(_QWERTY_KEYS[_DVORAK_KEYS.index(c)] if c in _DVORAK_KEYS else c for c in cipher)

# ---------- 反斜杠转义 ----------
def backslash_encode(text: str) -> str:
    return ''.join(f'\\x{b:02x}' for b in text.encode('utf-8'))

def backslash_decode(cipher: str) -> str:
    out = bytearray()
    for m in re.finditer(r'\\x([0-9a-fA-F]{2})', cipher):
        out.append(int(m.group(1), 16))
    return out.decode('utf-8', errors='replace')

# ---------- 斜杠管道 Slash/Pipe ----------
def slash_pipe_encode(text: str) -> str:
    data = text.encode('utf-8')
    bits = ''.join(f'{b:08b}' for b in data)
    return ''.join('/' if b == '0' else '|' for b in bits)

def slash_pipe_decode(cipher: str) -> str:
    s = ''.join(c for c in cipher if c in '/|')
    s = s[:len(s) - len(s) % 8]
    bits = ''.join('0' if c == '/' else '1' for c in s)
    out = bytearray()
    for i in range(0, len(bits), 8):
        out.append(int(bits[i:i + 8], 2))
    return out.decode('utf-8', errors='replace')

# ---------- Albam（分半互换，对合）----------
def albam_encode(text: str) -> str:
    return albam_decode(text)

def albam_decode(cipher: str) -> str:
    out = []
    for c in cipher:
        if 'A' <= c <= 'Z':
            out.append(chr((ord(c) - 65 + 13) % 26 + 65))
        elif 'a' <= c <= 'z':
            out.append(chr((ord(c) - 97 + 13) % 26 + 97))
        else:
            out.append(c)
    return ''.join(out)

# ---------- 音符密码 Solresol（双音节，7x7 单射）----------
def solresol_encode(text: str) -> str:
    out = []
    for c in text.upper():
        if 'A' <= c <= 'Z':
            idx = ord(c) - 65
            out.append(f'{SOLRESOL[idx // 7]} {SOLRESOL[idx % 7]}')
        else:
            out.append(c)
    return ' '.join(out)

def solresol_decode(cipher: str) -> str:
    out = []
    words = re.findall(r'[A-Za-z]+', cipher)
    i = 0
    while i < len(words):
        w = words[i].lower()
        if w in SOLRESOL_REV:
            if i + 1 < len(words) and words[i + 1].lower() in SOLRESOL_REV:
                idx = SOLRESOL_REV[w] * 7 + SOLRESOL_REV[words[i + 1].lower()]
                if idx < 26:
                    out.append(chr(idx + 65))
                    i += 2
                    continue
            out.append(chr(SOLRESOL_REV[w] + 65))
            i += 1
        else:
            out.append(words[i])
            i += 1
    return ''.join(out)

# ---------- Bubble Babble ----------
def bubble_babble_encode(text: str) -> str:
    data = text.encode('utf-8')
    seed = 1
    result = ['x']
    rounds = len(data) // 2 + 1
    for i in range(rounds):
        if i + 1 < rounds or len(data) % 2 != 0:
            b1 = data[2 * i]
            result.append(_BB_VOWELS[(((b1 >> 6) & 0x3) + seed) % 6])
            result.append(_BB_CONSONANTS[seed % 17])
            if 2 * i + 1 < len(data):
                b2 = data[2 * i + 1]
                result.append(_BB_VOWELS[(((b2 >> 6) & 0x3) + seed) % 6])
                seed = (seed * 5 + b1 * 7 + b2) % 36
                result.append(_BB_CONSONANTS[seed % 17])
            else:
                result.append(_BB_VOWELS[(0 + seed) % 6])
                seed = (seed * 5 + b1 * 7) % 36
                result.append(_BB_CONSONANTS[seed % 17])
        else:
            result.append(_BB_VOWELS[seed % 6])
            result.append(_BB_CONSONANTS[16])
            result.append(_BB_VOWELS[seed // 6])
    result.append('x')
    return ''.join(result)

def bubble_babble_decode(cipher: str) -> str:
    s = cipher.strip().lower()
    if len(s) < 2 or s[0] != 'x' or s[-1] != 'x':
        return '[!] 非 Bubble Babble 格式'
    s = s[1:-1]

    def dfs(pos, seed, out):
        if pos == len(s):
            return bytes(out)
        if pos + 1 >= len(s):
            return None
        if s[pos] not in _BB_VOWELS or s[pos + 1] not in _BB_CONSONANTS:
            return None
        v1i = _BB_VOWELS.index(s[pos])
        c1i = _BB_CONSONANTS.index(s[pos + 1])
        if c1i != seed % 17:
            return None
        hb1 = (v1i - seed) % 6
        if hb1 > 3:
            return None
        if pos + 3 < len(s):
            if s[pos + 2] not in _BB_VOWELS or s[pos + 3] not in _BB_CONSONANTS:
                return None
            v2i = _BB_VOWELS.index(s[pos + 2])
            c2i = _BB_CONSONANTS.index(s[pos + 3])
            hb2 = (v2i - seed) % 6
            if hb2 > 3:
                return None
            for b1 in range(hb1 << 6, (hb1 << 6) + 64):
                for b2 in range(hb2 << 6, (hb2 << 6) + 64):
                    sn = (seed * 5 + b1 * 7 + b2) % 36
                    if sn % 17 == c2i:
                        res = dfs(pos + 4, sn, out + bytes([b1, b2]))
                        if res is not None:
                            return res
            return None
        else:
            if pos + 2 >= len(s):
                return None
            if s[pos + 2] not in _BB_VOWELS:
                return None
            v2i = _BB_VOWELS.index(s[pos + 2])
            if c1i != 16 or v2i != seed // 6:
                return None
            return bytes(out)

    result = dfs(0, 1, bytearray())
    if result is None:
        return '[!] 解码失败'
    # 奇数长度时末尾有 0x00 padding，去掉
    result = result.rstrip(b'\x00')
    return result.decode('utf-8', errors='replace')

# ---------- 汉码 / 区位码 ----------
def chinesecode_encode(text: str) -> str:
    out = []
    for c in text:
        try:
            b = c.encode('gb2312')
            if len(b) == 2:
                out.append(f'{b[0] - 0xA0:02d}{b[1] - 0xA0:02d}')
            else:
                out.append(str(ord(c)))
        except UnicodeEncodeError:
            out.append(str(ord(c)))
    return ' '.join(out)

def chinesecode_decode(cipher: str) -> str:
    out = []
    for tok in re.split(r'[\s,;]+', cipher.strip()):
        if re.fullmatch(r'\d{4}', tok):
            qu, wei = int(tok[:2]), int(tok[2:])
            try:
                out.append(bytes([qu + 0xA0, wei + 0xA0]).decode('gb2312'))
            except Exception:
                out.append('?')
        elif tok.isdigit():
            out.append(chr(int(tok)))
        elif tok:
            out.append(tok)
    return ''.join(out)

# ---------- 箭头密码（8 方向 -> 3bit）----------
_ARROWS = '↑↗→↘↓↙←↖'
_ARROW_REV = {a: i for i, a in enumerate(_ARROWS)}

def arrows_encode(text: str) -> str:
    data = text.encode('utf-8')
    bits = ''.join(f'{b:08b}' for b in data)
    bits += '0' * ((-len(bits)) % 3)
    return ''.join(_ARROWS[int(bits[i:i + 3], 2)] for i in range(0, len(bits), 3))

def arrows_decode(cipher: str) -> str:
    bits = ''.join(f'{_ARROW_REV[c]:03b}' for c in cipher if c in _ARROW_REV)
    bits = bits[:len(bits) - len(bits) % 8]
    out = bytearray()
    for i in range(0, len(bits), 8):
        out.append(int(bits[i:i + 8], 2))
    return out.decode('utf-8', errors='replace')


# ═══════════════════════════════════════════════════════════
# 注册表
# ═══════════════════════════════════════════════════════════

CIPHERS = {
    "dna": {"name": "DNA编码", "aliases": ["dna", "DNA"], "category": "经典编码"},
    "a1z26": {"name": "A1Z26", "aliases": ["a1z26", "letter_number", "字母数字"], "category": "经典编码"},
    "baudot": {"name": "博多码Baudot", "aliases": ["baudot", "博多", "ITA2"], "category": "经典编码"},
    "type7": {"name": "Cisco Type7", "aliases": ["type7", "cisco", "type-7"], "category": "经典编码"},
    "yunying": {"name": "云影密码01248", "aliases": ["yunying", "云影", "01248"], "category": "经典编码"},
    "tap_code": {"name": "敲击码", "aliases": ["tap_code", "敲击码", "tapcode", "knock"], "category": "经典编码"},
    "nato": {"name": "北约音标NATO", "aliases": ["nato", "北约", "音标"], "category": "经典编码"},
    "braille": {"name": "盲文", "aliases": ["braille", "盲文"], "category": "经典编码"},
    "bwt": {"name": "块排序BWT", "aliases": ["bwt", "burrows_wheeler", "块排序"], "category": "经典编码"},
    "manchester": {"name": "曼彻斯特编码", "aliases": ["manchester", "曼彻斯特", "Manchester"], "category": "经典编码"},
    "keyboard_keycode": {"name": "键盘键码keyCode", "aliases": ["keycode", "键盘键码", "key_code"], "category": "键盘编码"},
    "keyboard_shift": {"name": "键盘上档键转数字", "aliases": ["键盘上档", "shift"], "category": "键盘编码"},
    "handycode": {"name": "九宫格handycode", "aliases": ["handycode", "九宫格", "handy"], "category": "键盘编码"},
    "dvorak": {"name": "德沃夏克键盘Dvorak", "aliases": ["dvorak", "德沃夏克"], "category": "键盘编码"},
    "backslash": {"name": "反斜杠Backslash", "aliases": ["backslash", "反斜杠"], "category": "经典编码"},
    "slash_pipe": {"name": "斜杠管道Slash/Pipe", "aliases": ["slash_pipe", "斜杠管道"], "category": "经典编码"},
    "albam": {"name": "Albam", "aliases": ["albam"], "category": "经典编码"},
    "solresol": {"name": "音符密码", "aliases": ["solresol", "音符", "music_note"], "category": "经典编码"},
    "chinesecode": {"name": "汉码/区位码", "aliases": ["chinesecode", "区位码", "汉码"], "category": "经典编码"},
    "arrows": {"name": "箭头密码", "aliases": ["arrows", "箭头"], "category": "经典编码"},
}

_FUNCS = {
    "dna": (dna_encode, dna_decode),
    "a1z26": (a1z26_encode, a1z26_decode),
    "baudot": (baudot_encode, baudot_decode),
    "type7": (type7_encode, type7_decode),
    "yunying": (yunying_encode, yunying_decode),
    "tap_code": (tap_code_encode, tap_code_decode),
    "nato": (nato_encode, nato_decode),
    "braille": (braille_encode, braille_decode),
    "bwt": (bwt_encode, bwt_decode),
    "manchester": (manchester_encode, manchester_decode),
    "keyboard_keycode": (keyboard_keycode_encode, keyboard_keycode_decode),
    "keyboard_shift": (keyboard_shift_encode, keyboard_shift_decode),
    "handycode": (handycode_encode, handycode_decode),
    "dvorak": (dvorak_encode, dvorak_decode),
    "backslash": (backslash_encode, backslash_decode),
    "slash_pipe": (slash_pipe_encode, slash_pipe_decode),
    "albam": (albam_encode, albam_decode),
    "solresol": (solresol_encode, solresol_decode),
    "chinesecode": (chinesecode_encode, chinesecode_decode),
    "arrows": (arrows_encode, arrows_decode),
}


def _norm(cipher_id: str) -> str:
    cid = cipher_id.lower().replace('-', '_').replace(' ', '_')
    # 别名映射
    alias_map = {}
    for cid_key, info in CIPHERS.items():
        for a in info.get("aliases", []):
            alias_map[a.lower().replace('-', '_').replace(' ', '_')] = cid_key
    return alias_map.get(cid, cid)


def encode(cipher_id: str, text: str, **kwargs) -> str:
    cid = _norm(cipher_id)
    if cid in _FUNCS:
        return _FUNCS[cid][0](text)
    return f"[!] 不支持编码: {cipher_id}"


def decode(cipher_id: str, cipher_text: str, **kwargs) -> str:
    cid = _norm(cipher_id)
    if cid in _FUNCS:
        return _FUNCS[cid][1](cipher_text)
    return f"[!] 不支持解码: {cipher_id}"


def list_ciphers(category: str = None) -> list:
    result = []
    for cid, info in CIPHERS.items():
        if category and info.get("category") != category:
            continue
        result.append({"id": cid, **info})
    return result


def get_cipher(cipher_id: str) -> dict:
    return CIPHERS.get(_norm(cipher_id))


def search_ciphers(query: str) -> list:
    q = query.lower()
    out = []
    for cid, info in CIPHERS.items():
        text = cid + " " + info["name"] + " " + " ".join(info.get("aliases", [])) + " " + info["category"]
        if q in text.lower():
            out.append({"id": cid, **info})
    return out


def get_categories() -> list:
    return sorted({info["category"] for info in CIPHERS.values()})
