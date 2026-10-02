"""yang_web.core.cipher_keyed 子模块 _fractionated（自 cipher_keyed.py 拆分，请勿手工重排）。"""

import base64
import hashlib
import hmac as hmac_mod
import re
from math import gcd
try:
    from .. import crypto_engine
except Exception:
    import crypto_engine

from ._common import (_keyword_alphabet, _only_letters, _polybius_keyed)
from ._transposition import (_transposition_key_order)


# ---------- Fractionated Morse ----------
_MORSE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..',
}

def fractionated_morse_encode(text, key=""):
    alpha = _keyword_alphabet(key)
    morse = 'x'.join(_MORSE[c] for c in _only_letters(text))
    morse = morse.replace('.', '0').replace('-', '1').replace('x', '2')
    # 每 3 个 morse 符号 -> 一个字母（0-25）
    while len(morse) % 3:
        morse += '2'  # 用分隔符补位
    out = []
    for i in range(0, len(morse), 3):
        idx = int(morse[i:i + 3], 3)
        if idx < 26:
            out.append(alpha[idx])
        else:
            out.append('?')
    return ''.join(out)

def fractionated_morse_decode(cipher, key=""):
    alpha = _keyword_alphabet(key)
    rev = {c: i for i, c in enumerate(alpha)}
    morse = ''
    for c in _only_letters(cipher):
        v = rev.get(c, 0)
        morse += f'{v:03b}'  # 3 位二进制 -> 但应该是 3 进制
    # 实际上 encode 用 3 进制（0/1/2），这里对应 base3
    # 重新处理
    morse = ''
    for c in _only_letters(cipher):
        v = rev.get(c)
        if v is None:
            continue
        t = ''
        for _ in range(3):
            t = str(v % 3) + t
            v //= 3
        morse += t
    morse = morse.replace('0', '.').replace('1', '-').replace('2', 'x')
    out = []
    for word in morse.split('x'):
        for letter, code in _MORSE.items():
            if code == word:
                out.append(letter)
                break
    return ''.join(out)

# ---------- Bifid 双密码 ----------
def bifid_encode(text, key=""):
    grid = _polybius_keyed(key)
    plain = _only_letters(text).replace('J', 'I')
    coords = []
    for c in plain:
        idx = grid.index(c)
        coords.append((idx // 5, idx % 5))
    rows = [r for r, _ in coords]
    cols = [c for _, c in coords]
    merged = rows + cols
    out = []
    for i in range(0, len(merged), 2):
        r, c = merged[i], merged[i + 1]
        out.append(grid[r * 5 + c])
    return ''.join(out)

def bifid_decode(cipher, key=""):
    grid = _polybius_keyed(key)
    cipher = _only_letters(cipher).replace('J', 'I')
    n = len(cipher)
    merged = []
    for c in cipher:
        idx = grid.index(c)
        merged.extend([idx // 5, idx % 5])
    rows = merged[:n]
    cols = merged[n:]
    out = []
    for i in range(n):
        out.append(grid[rows[i] * 5 + cols[i]])
    return ''.join(out)

# ---------- 四方 Foursquare ----------
def foursquare_encode(text, key1="", key2=""):
    g1 = _polybius_keyed(key1)
    g2 = _polybius_keyed(key2)
    std = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'  # 标准 Polybius
    plain = _only_letters(text).replace('J', 'I')
    if len(plain) % 2:
        plain += 'X'
    out = []
    for i in range(0, len(plain), 2):
        a, b = plain[i], plain[i + 1]
        ra, ca = divmod(std.index(a), 5)
        rb, cb = divmod(std.index(b), 5)
        out.append(g1[ra * 5 + cb])
        out.append(g2[rb * 5 + ca])
    return ''.join(out)

def foursquare_decode(cipher, key1="", key2=""):
    g1 = _polybius_keyed(key1)
    g2 = _polybius_keyed(key2)
    std = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
    cipher = _only_letters(cipher).replace('J', 'I')
    if len(cipher) % 2:
        cipher += 'X'
    out = []
    for i in range(0, len(cipher), 2):
        a, b = cipher[i], cipher[i + 1]
        ra, cb = divmod(g1.index(a), 5)
        rb, ca = divmod(g2.index(b), 5)
        out.append(std[ra * 5 + ca])
        out.append(std[rb * 5 + cb])
    return ''.join(out)

# ---------- Nihilist ----------
def nihilist_encode(text, key=""):
    grid = _polybius_keyed(key)
    plain = _only_letters(text).replace('J', 'I')
    k = _only_letters(key).replace('J', 'I')
    out = []
    for i, c in enumerate(plain):
        p_idx = grid.index(c)
        pr, pc = p_idx // 5 + 1, p_idx % 5 + 1
        kc = k[i % len(k)] if k else 'A'
        k_idx = grid.index(kc)
        kr, kc2 = k_idx // 5 + 1, k_idx % 5 + 1
        out.append(str(pr * 10 + pc + kr * 10 + kc2))
    return ' '.join(out)

def nihilist_decode(cipher, key=""):
    grid = _polybius_keyed(key)
    k = _only_letters(key).replace('J', 'I')
    out = []
    for tok in re.findall(r'\d+', cipher):
        v = int(tok)
        kc = k[(len(out)) % len(k)] if k else 'A'
        k_idx = grid.index(kc)
        kv = (k_idx // 5 + 1) * 10 + (k_idx % 5 + 1)
        pv = v - kv
        pr, pc = pv // 10 - 1, pv % 10 - 1
        if 0 <= pr < 5 and 0 <= pc < 5:
            out.append(grid[pr * 5 + pc])
    return ''.join(out)

# ---------- kamasutra 爱经（固定配对，对合）----------
_KAMASUTRA_PAIRS = {
    'A': 'F', 'B': 'Q', 'C': 'W', 'D': 'Z', 'E': 'G', 'G': 'E',
    'H': 'M', 'I': 'R', 'J': 'U', 'K': 'P', 'L': 'S', 'M': 'H',
    'N': 'X', 'O': 'V', 'P': 'K', 'Q': 'B', 'R': 'I', 'S': 'L',
    'T': 'Y', 'U': 'J', 'V': 'O', 'W': 'C', 'X': 'N', 'Y': 'T',
    'Z': 'D', 'F': 'A',
}

def kamasutra_encode(text, key=""):
    return ''.join(_KAMASUTRA_PAIRS.get(c, c) for c in _only_letters(text))

def kamasutra_decode(cipher, key=""):
    return kamasutra_encode(cipher, key)

# ---------- 费娜姆 Fenham（二进制 XOR）----------
def fenham_encode(text, key=""):
    k = _only_letters(key) or "A"
    out = []
    for i, c in enumerate(_only_letters(text)):
        x = ord(c) - 65
        ki = ord(k[i % len(k)]) - 65
        xor = x ^ ki
        out.append(chr(xor + 65) if xor < 26 else f'[{xor}]')
    return ''.join(out)

def fenham_decode(cipher, key=""):
    return fenham_encode(cipher, key)  # XOR 对合

# ---------- ADFGVX ----------
def adfgvx_encode(text, key=""):
    # 6x6 网格（A-Z + 0-9）
    grid = _only_letters(key) + '0123456789'
    seen = set()
    g = []
    for c in grid + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789':
        if c not in seen:
            seen.add(c)
            g.append(c)
    g = ''.join(g[:36])
    letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    # 第一阶段：字符 -> 坐标
    plain = text.upper()
    coords = []
    for c in plain:
        if c in g:
            idx = g.index(c)
            coords.append('ADFGVX'[idx // 6] + 'ADFGVX'[idx % 6])
    mid = ''.join(coords)
    # 第二阶段：列置换（用 key 排序）
    order = _transposition_key_order(key or "KEY")
    cols = len(order)
    rows = (len(mid) + cols - 1) // cols
    grid2 = [[''] * cols for _ in range(rows)]
    idx = 0
    for r in range(rows):
        for c in range(cols):
            if idx < len(mid):
                grid2[r][c] = mid[idx]
                idx += 1
    out = []
    for c in order:
        for r in range(rows):
            if grid2[r][c]:
                out.append(grid2[r][c])
    return ''.join(out)

def adfgvx_decode(cipher, key=""):
    letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    grid = _only_letters(key) + '0123456789'
    seen = set()
    g = []
    for c in grid + letters:
        if c not in seen:
            seen.add(c)
            g.append(c)
    g = ''.join(g[:36])
    order = _transposition_key_order(key or "KEY")
    cols = len(order)
    n = len(cipher)
    rows = (n + cols - 1) // cols
    full_cols = n % cols if n % cols else cols
    chunks = {}
    idx = 0
    for c in order:
        cl = rows if c < full_cols else rows - 1
        chunks[c] = cipher[idx:idx + cl]
        idx += cl
    grid2 = [[''] * cols for _ in range(rows)]
    for c in order:
        for r in range(len(chunks[c])):
            grid2[r][c] = chunks[c][r]
    mid = ''.join(''.join(row) for row in grid2)
    # 坐标 -> 字符
    out = []
    for i in range(0, len(mid), 2):
        r = 'ADFGVX'.index(mid[i])
        c = 'ADFGVX'.index(mid[i + 1])
        out.append(g[r * 6 + c])
    return ''.join(out)
