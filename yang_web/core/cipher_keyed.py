# -*- coding: utf-8 -*-
"""cipher_keyed.py — 带 key / 多 key 古典密码

覆盖 CTF 高频带密钥密码，纯 Python 标准库零依赖实现。
API 风格与 misc_crypto.py 一致：
  - <name>_encode(text, key) / <name>_decode(cipher, key)
  - CIPHERS 注册表（每项标注 needs_key）
  - encode() / decode() 统一分发入口（key 通过 kwargs 传入）
"""
import base64
import hashlib
import hmac as hmac_mod
import re
from math import gcd

try:
    from . import crypto_engine
except Exception:
    import crypto_engine


# ═══════════════════════════════════════════════════════════
# 工具函数
# ═══════════════════════════════════════════════════════════

def _modinv(a, m=26):
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def _only_letters(text):
    return ''.join(c for c in text.upper() if 'A' <= c <= 'Z')


def _polybius_keyed(key=""):
    """生成 5x5 Polybius 字母表（默认无 key，I/J 合并）。"""
    base = _only_letters(key).replace('J', 'I')
    seen = set()
    grid = []
    for c in base + 'ABCDEFGHIKLMNOPQRSTUVWXYZ':  # 无 J
        if c not in seen:
            seen.add(c)
            grid.append(c)
    return ''.join(grid[:25])


# ═══════════════════════════════════════════════════════════
# 算法实现
# ═══════════════════════════════════════════════════════════

# ---------- 仿射 affine ----------
def affine_encode(text, key="5,8"):
    try:
        a, b = (int(x.strip()) for x in str(key).split(','))
    except Exception:
        return "[!] key 格式应为 a,b"
    if gcd(a, 26) != 1:
        return "[!] a 必须与 26 互质"
    out = []
    for c in _only_letters(text):
        x = ord(c) - 65
        out.append(chr((a * x + b) % 26 + 65))
    return ''.join(out)

def affine_decode(cipher, key="5,8"):
    try:
        a, b = (int(x.strip()) for x in str(key).split(','))
    except Exception:
        return "[!] key 格式应为 a,b"
    a_inv = _modinv(a, 26)
    if a_inv is None:
        return "[!] a 必须与 26 互质"
    out = []
    for c in _only_letters(cipher):
        x = ord(c) - 65
        out.append(chr((a_inv * (x - b)) % 26 + 65))
    return ''.join(out)

# ---------- 乘法密码 multiplicative ----------
def multiplicative_encode(text, key="5"):
    try:
        a = int(str(key).strip())
    except Exception:
        return "[!] key 应为数字"
    if gcd(a, 26) != 1:
        return "[!] key 必须与 26 互质（可选 3/5/7/9/11/15/17/19/21/23/25）"
    return affine_encode(text, f"{a},0")

def multiplicative_decode(cipher, key="5"):
    try:
        a = int(str(key).strip())
    except Exception:
        return "[!] key 应为数字"
    return affine_decode(cipher, f"{a},0")

# ---------- 一次一密 OTP ----------
def otp_encode(text, key=""):
    if not key:
        return "[!] OTP 需要 key"
    data = text.encode('utf-8')
    kb = key.encode('utf-8')
    if len(kb) < len(data):
        kb = (kb * (len(data) // len(kb) + 1))[:len(data)]
    return base64.b64encode(bytes(a ^ b for a, b in zip(data, kb))).decode()

def otp_decode(cipher, key=""):
    if not key:
        return "[!] OTP 需要 key"
    try:
        data = base64.b64decode(cipher)
    except Exception:
        return "[!] 密文应为 Base64"
    kb = key.encode('utf-8')
    if len(kb) < len(data):
        kb = (kb * (len(data) // len(kb) + 1))[:len(data)]
    return bytes(a ^ b for a, b in zip(data, kb)).decode('utf-8', errors='replace')

# ---------- 希尔 Hill（2x2 / 3x3）----------
def _hill_matrix_from_key(key):
    key = str(key).strip().replace(' ', '')
    # 尝试解析为数字矩阵 "3,3,2,5" 或 "6,24,1,13,16,10,20,17,15"
    nums = re.findall(r'-?\d+', key)
    if len(nums) == 4:
        return [[int(nums[0]), int(nums[1])], [int(nums[2]), int(nums[3])]], 2
    if len(nums) == 9:
        m = [int(x) for x in nums]
        return [[m[0], m[1], m[2]], [m[3], m[4], m[5]], [m[6], m[7], m[8]]], 3
    # 否则用默认矩阵
    return [[3, 3], [2, 5]], 2

def _matrix_inv(matrix, n):
    if n == 2:
        a, b = matrix[0][0], matrix[0][1]
        c, d = matrix[1][0], matrix[1][1]
        det = (a * d - b * c) % 26
        inv = _modinv(det, 26)
        if inv is None:
            return None
        return [[(d * inv) % 26, (-b * inv) % 26], [(-c * inv) % 26, (a * inv) % 26]]
    # 3x3 逆矩阵
    m = matrix
    det = 0
    for i in range(3):
        det += m[0][i] * (m[1][(i + 1) % 3] * m[2][(i + 2) % 3] - m[1][(i + 2) % 3] * m[2][(i + 1) % 3])
    det %= 26
    inv = _modinv(det, 26)
    if inv is None:
        return None
    adj = [[0] * 3 for _ in range(3)]
    for i in range(3):
        for j in range(3):
            minor = [[m[r][c] for c in range(3) if c != j] for r in range(3) if r != i]
            cof = (minor[0][0] * minor[1][1] - minor[0][1] * minor[1][0])
            adj[j][i] = (cof * ((-1) ** (i + j))) % 26
    return [[(adj[i][j] * inv) % 26 for j in range(3)] for i in range(3)]

def hill_encode(text, key="3,3,2,5"):
    matrix, n = _hill_matrix_from_key(key)
    letters = _only_letters(text)
    while len(letters) % n != 0:
        letters += 'X'
    out = []
    for i in range(0, len(letters), n):
        block = [ord(c) - 65 for c in letters[i:i + n]]
        res = [sum(matrix[r][k] * block[k] for k in range(n)) % 26 for r in range(n)]
        out.extend(chr(x + 65) for x in res)
    return ''.join(out)

def hill_decode(cipher, key="3,3,2,5"):
    matrix, n = _hill_matrix_from_key(key)
    inv = _matrix_inv(matrix, n)
    if inv is None:
        return "[!] 矩阵不可逆（det 与 26 不互质）"
    letters = _only_letters(cipher)
    out = []
    for i in range(0, len(letters), n):
        block = [ord(c) - 65 for c in letters[i:i + n]]
        res = [sum(inv[r][k] * block[k] for k in range(n)) % 26 for r in range(n)]
        out.extend(chr(x + 65) for x in res)
    return ''.join(out)

# ---------- Gronsfeld ----------
def gronsfeld_encode(text, key="1234"):
    digits = [int(d) for d in str(key) if d.isdigit()]
    if not digits:
        return "[!] key 应为数字串"
    out = []
    for i, c in enumerate(_only_letters(text)):
        x = ord(c) - 65
        out.append(chr((x + digits[i % len(digits)]) % 26 + 65))
    return ''.join(out)

def gronsfeld_decode(cipher, key="1234"):
    digits = [int(d) for d in str(key) if d.isdigit()]
    if not digits:
        return "[!] key 应为数字串"
    out = []
    for i, c in enumerate(_only_letters(cipher)):
        x = ord(c) - 65
        out.append(chr((x - digits[i % len(digits)]) % 26 + 65))
    return ''.join(out)

# ---------- Beaufort ----------
def beaufort_encode(text, key=""):
    return beaufort_decode(text, key)  # Beaufort 对合

def beaufort_decode(cipher, key=""):
    k = _only_letters(key) or "A"
    out = []
    for i, c in enumerate(_only_letters(cipher)):
        ki = ord(k[i % len(k)]) - 65
        x = ord(c) - 65
        out.append(chr((ki - x) % 26 + 65))
    return ''.join(out)

# ---------- Autokey ----------
def autokey_encode(text, key=""):
    k = _only_letters(key) or "A"
    plain = _only_letters(text)
    keystream = k + plain
    out = []
    for i, c in enumerate(plain):
        out.append(chr((ord(c) - 65 + ord(keystream[i]) - 65) % 26 + 65))
    return ''.join(out)

def autokey_decode(cipher, key=""):
    k = _only_letters(key) or "A"
    cipher = _only_letters(cipher)
    keystream = list(k)
    out = []
    for i, c in enumerate(cipher):
        x = (ord(c) - 65 - (ord(keystream[i]) - 65)) % 26
        p = chr(x + 65)
        out.append(p)
        keystream.append(p)
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

# ---------- 斯巴达 Scytale ----------
def scytale_encode(text, key="3"):
    try:
        cols = int(str(key).strip())
    except Exception:
        return "[!] key 应为数字"
    if cols < 2:
        return text
    out = [''] * cols
    for i, c in enumerate(text):
        out[i % cols] += c
    return ''.join(out)

def scytale_decode(cipher, key="3"):
    try:
        cols = int(str(key).strip())
    except Exception:
        return "[!] key 应为数字"
    if cols < 2:
        return cipher
    n = len(cipher)
    rows = (n + cols - 1) // cols
    full_cols = n % cols if n % cols else cols
    col_lens = [rows if i < full_cols else rows - 1 for i in range(cols)]
    chunks = []
    idx = 0
    for cl in col_lens:
        chunks.append(cipher[idx:idx + cl])
        idx += cl
    out = []
    for r in range(rows):
        for c in range(cols):
            if r < len(chunks[c]):
                out.append(chunks[c][r])
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

# ---------- 关键字 KeywordCipher ----------
def _keyword_alphabet(key):
    base = _only_letters(key)
    seen = set()
    alpha = []
    for c in base:
        if c not in seen:
            seen.add(c)
            alpha.append(c)
    for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        if c not in seen:
            seen.add(c)
            alpha.append(c)
    return ''.join(alpha)

def keyword_encode(text, key=""):
    alpha = _keyword_alphabet(key)
    out = []
    for c in _only_letters(text):
        out.append(alpha[ord(c) - 65])
    return ''.join(out)

def keyword_decode(cipher, key=""):
    alpha = _keyword_alphabet(key)
    rev = {c: chr(i + 65) for i, c in enumerate(alpha)}
    return ''.join(rev.get(c, c) for c in _only_letters(cipher))

# ---------- 单表置换 / 简单替换 SimpleSubstitution ----------
def simple_substitution_encode(text, key=""):
    # key 是 26 字母替换表（如 "ZYXWVUTSRQPONMLKJIHGFEDCBA"）
    if key and len(_only_letters(key)) == 26:
        alpha = _only_letters(key)
    else:
        alpha = _keyword_alphabet(key) if key else 'ZYXWVUTSRQPONMLKJIHGFEDCBA'
    out = []
    for c in _only_letters(text):
        out.append(alpha[ord(c) - 65])
    return ''.join(out)

def simple_substitution_decode(cipher, key=""):
    if key and len(_only_letters(key)) == 26:
        alpha = _only_letters(key)
    else:
        alpha = _keyword_alphabet(key) if key else 'ZYXWVUTSRQPONMLKJIHGFEDCBA'
    rev = {c: chr(i + 65) for i, c in enumerate(alpha)}
    return ''.join(rev.get(c, c) for c in _only_letters(cipher))

# ---------- 列移位 ColTrans / 列置换 / 行置换 ----------
def _transposition_key_order(key):
    """返回 key 的列排序顺序（字母序）。"""
    k = _only_letters(key) or "KEY"
    return sorted(range(len(k)), key=lambda i: k[i])

def coltrans_encode(text, key=""):
    order = _transposition_key_order(key)
    cols = len(order)
    n = len(text)
    rows = (n + cols - 1) // cols
    grid = [[''] * cols for _ in range(rows)]
    idx = 0
    for r in range(rows):
        for c in range(cols):
            if idx < n:
                grid[r][c] = text[idx]
                idx += 1
    out = []
    for c in order:
        for r in range(rows):
            if grid[r][c]:
                out.append(grid[r][c])
    return ''.join(out)

def coltrans_decode(cipher, key=""):
    order = _transposition_key_order(key)
    cols = len(order)
    n = len(cipher)
    rows = (n + cols - 1) // cols
    full_cols = n % cols if n % cols else cols
    # 密文按 order 顺序排列；每列长度由列号决定（前 full_cols 列 rows 行，其余 rows-1）
    chunks = {}
    idx = 0
    for c in order:
        cl = rows if c < full_cols else rows - 1
        chunks[c] = cipher[idx:idx + cl]
        idx += cl
    grid = [[''] * cols for _ in range(rows)]
    for c in order:
        for r in range(len(chunks[c])):
            grid[r][c] = chunks[c][r]
    return ''.join(''.join(row) for row in grid)

def column_permutation_encode(text, key=""):
    return coltrans_encode(text, key)

def column_permutation_decode(cipher, key=""):
    return coltrans_decode(cipher, key)

def rows_permutation_encode(text, key=""):
    order = _transposition_key_order(key)
    rows = len(order)
    n = len(text)
    cols = (n + rows - 1) // rows
    lens = [cols] * rows
    total = rows * cols
    for i in range(total - n):
        lens[rows - 1 - i] -= 1
    grid = []
    idx = 0
    for l in lens:
        grid.append(text[idx:idx + l])
        idx += l
    return ''.join(grid[r] for r in order)

def rows_permutation_decode(cipher, key=""):
    order = _transposition_key_order(key)
    rows = len(order)
    n = len(cipher)
    cols = (n + rows - 1) // rows
    lens = [cols] * rows
    total = rows * cols
    for i in range(total - n):
        lens[rows - 1 - i] -= 1
    chunks = {}
    idx = 0
    for r in order:
        chunks[r] = cipher[idx:idx + lens[r]]
        idx += lens[r]
    return ''.join(chunks[r] for r in range(rows))

# ---------- Porta ----------
_PORTA = [
    "NOPQRSTUVWXYZABCDEFGHIJKLM",
    "OPQRSTUVWXYZNMABCDEFGHIJKL",
    "PQRSTUVWXYZNOLMABCDEFGHIJK",
    "QRSTUVWXYZNOPKLMABCDEFGHIJ",
    "RSTUVWXYZNOPQJKLMABCDEFGHI",
    "STUVWXYZNOPQRIJKLMABCDEFGH",
    "TUVWXYZNOPQRSHIJKLMABCDEFG",
    "UVWXYZNOPQRSTGHIJKLMABCDEF",
    "VWXYZNOPQRSTUFGHIJKLMABCDE",
    "WXYZNOPQRSTUVEFGHIJKLMABCD",
    "XYZNOPQRSTUVWDEFGHIJKLMABC",
    "YZNOPQRSTUVWXCDEFGHIJKLMAB",
    "ZNOPQRSTUVWXYBCDEFGHIJKLMA",
]

def porta_encode(text, key=""):
    k = _only_letters(key) or "A"
    out = []
    for i, c in enumerate(_only_letters(text)):
        table_idx = (ord(k[i % len(k)]) - 65) // 2
        x = ord(c) - 65
        out.append(_PORTA[table_idx][x])
    return ''.join(out)

def porta_decode(cipher, key=""):
    return porta_encode(cipher, key)  # Porta 对合

# ---------- Bazeries ----------
def bazeries_encode(text, key="123"):
    nums = [int(d) for d in str(key) if d.isdigit()] or [1]
    plain = _only_letters(text)
    out = []
    i = 0
    while i < len(plain):
        for n in nums:
            seg = plain[i:i + n]
            out.append(''.join(chr((ord(c) - 65 + n) % 26 + 65) for c in seg))
            i += n
            if i >= len(plain):
                break
    return ''.join(out)

def bazeries_decode(cipher, key="123"):
    nums = [int(d) for d in str(key) if d.isdigit()] or [1]
    cipher = _only_letters(cipher)
    out = []
    i = 0
    while i < len(cipher):
        for n in nums:
            seg = cipher[i:i + n]
            out.append(''.join(chr((ord(c) - 65 - n) % 26 + 65) for c in seg))
            i += n
            if i >= len(cipher):
                break
    return ''.join(out)

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

# ---------- 滚动密钥 running key ----------
def running_key_encode(text, key=""):
    k = _only_letters(key)
    if not k:
        return "[!] 需要 key"
    plain = _only_letters(text)
    out = []
    for i, c in enumerate(plain):
        out.append(chr((ord(c) - 65 + ord(k[i % len(k)]) - 65) % 26 + 65))
    return ''.join(out)

def running_key_decode(cipher, key=""):
    k = _only_letters(key)
    if not k:
        return "[!] 需要 key"
    out = []
    for i, c in enumerate(_only_letters(cipher)):
        out.append(chr((ord(c) - 65 - (ord(k[i % len(k)]) - 65)) % 26 + 65))
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

# ---------- Fernet ----------
def fernet_encode(text, key=""):
    try:
        key_bytes = base64.urlsafe_b64decode(key + '=' * (-len(key) % 4))
    except Exception:
        return "[!] key 应为 urlsafe base64 的 32 字节"
    if len(key_bytes) != 32:
        return "[!] key 应为 32 字节（16 签名 + 16 加密）"
    sign_key, enc_key = key_bytes[:16], key_bytes[16:]
    iv = __import__('os').urandom(16)
    data = text.encode('utf-8')
    # PKCS7 填充 + AES-128-CBC
    pad = 16 - len(data) % 16
    padded = data + bytes([pad]) * pad
    ciphertext = crypto_engine.aes_encrypt(enc_key, padded, 'cbc', iv)
    payload = b'\x80' + int(__import__('time').time()).to_bytes(8, 'big') + iv + ciphertext
    sig = hmac_mod.new(sign_key, payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(payload + sig).decode().rstrip('=')

def fernet_decode(cipher, key=""):
    try:
        key_bytes = base64.urlsafe_b64decode(key + '=' * (-len(key) % 4))
    except Exception:
        return "[!] key 格式错误"
    if len(key_bytes) != 32:
        return "[!] key 应为 32 字节"
    sign_key, enc_key = key_bytes[:16], key_bytes[16:]
    try:
        raw = base64.urlsafe_b64decode(cipher + '=' * (-len(cipher) % 4))
    except Exception:
        return "[!] 密文格式错误"
    if len(raw) < 1 + 8 + 16 + 32:
        return "[!] 密文过短"
    payload, sig = raw[:-32], raw[-32:]
    if not hmac_mod.compare_digest(hmac_mod.new(sign_key, payload, hashlib.sha256).digest(), sig):
        return "[!] HMAC 校验失败（key 错误或密文被篡改）"
    iv = payload[9:25]
    ciphertext = payload[25:]
    plain = crypto_engine.aes_decrypt(enc_key, ciphertext, 'cbc', iv)
    if not plain:
        return "[!] 解密失败"
    pad = plain[-1]
    return plain[:-pad].decode('utf-8', errors='replace')

# ---------- Enigma M3 ----------
_ROTORS = {
    'I': ('EKMFLGDQVZNTOWYHXUSPAIBRCJ', 'Q'),
    'II': ('AJDKSIRUXBLHWTMCQGZNPYFVOE', 'E'),
    'III': ('BDFHJLCPRTXVZNYEIWGAKMUSQO', 'V'),
    'IV': ('ESOVPZJAYQUIRHXLNFTGKDCMWB', 'J'),
    'V': ('VZBRGITYUPSDNHLXAWMJQOFECK', 'Z'),
}
_REFLECTORS = {
    'B': 'YRUHQSLDPXNGOKMIEBFZCWVJAT',
    'C': 'FVPJIAOYEDRZXWGCTKUQSBNMHL',
}

def _enigma_parse_key(key):
    # key 格式："转子名,起始位置" 如 "I II III,AAA" 或 "I,II,III|AAA|B" 简化："AAA"
    s = str(key).strip()
    rotor_names = ['I', 'II', 'III']
    positions = 'AAA'
    reflector = 'B'
    plugboard = ''
    if ',' in s:
        left, right = s.split(',', 1)
        rn = [x.strip().upper() for x in left.split()]
        if all(r in _ROTORS for r in rn):
            rotor_names = rn
        pos_part = right.strip()
        if '|' in pos_part:
            parts = pos_part.split('|')
            positions = parts[0].upper()[:3]
            if len(parts) > 1:
                reflector = parts[1].upper()[:1]
            if len(parts) > 2:
                plugboard = parts[2].upper()
        else:
            positions = pos_part.upper()[:3]
    elif len(s) >= 3:
        positions = s.upper()[:3]
    return rotor_names, positions.ljust(3, 'A'), reflector, plugboard

def _enigma_advance(rotors, rotor_names):
    # 双步进机制
    notch_positions = [_ROTORS[rn][1] for rn in rotor_names]
    # 检查中间转子是否在 notch（触发左转子步进）
    middle_at_notch = chr(rotors[1] + 65) in notch_positions[1]
    right_at_notch = chr(rotors[2] + 65) in notch_positions[2]
    if middle_at_notch:
        rotors[1] = (rotors[1] + 1) % 26
        rotors[0] = (rotors[0] + 1) % 26
    if right_at_notch:
        rotors[1] = (rotors[1] + 1) % 26
    rotors[2] = (rotors[2] + 1) % 26

def _enigma_transform(c, rotors, rotor_names, reflector):
    x = ord(c) - 65
    # 正向：右 -> 中 -> 左
    for i in range(2, -1, -1):
        wiring = _ROTORS[rotor_names[i]][0]
        offset = rotors[i]
        x = (ord(wiring[(x + offset) % 26]) - 65 - offset) % 26
    # 反射器
    x = ord(_REFLECTORS[reflector][x]) - 65
    # 反向：左 -> 中 -> 右
    for i in range(3):
        wiring = _ROTORS[rotor_names[i]][0]
        offset = rotors[i]
        pos = (x + offset) % 26
        x = (wiring.index(chr(pos + 65)) - offset) % 26
    return chr(x + 65)

def enigma_encode(text, key=""):
    rotor_names, positions, reflector, plugboard = _enigma_parse_key(key)
    plug = {}
    if plugboard:
        pairs = re.findall(r'([A-Z]{2})', plugboard)
        for a, b in pairs:
            plug[a] = b
            plug[b] = a
    rotors = [ord(p) - 65 for p in positions]
    letters = _only_letters(text)
    out = []
    for c in letters:
        _enigma_advance(rotors, rotor_names)
        c2 = plug.get(c, c)
        c3 = _enigma_transform(c2, rotors, rotor_names, reflector)
        out.append(plug.get(c3, c3))
    return ''.join(out)

def enigma_decode(cipher, key=""):
    return enigma_encode(cipher, key)  # Enigma 对合

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


# ═══════════════════════════════════════════════════════════
# 注册表
# ═══════════════════════════════════════════════════════════

CIPHERS = {
    "affine": {"name": "仿射密码", "aliases": ["affine", "仿射"], "category": "带key密码", "key_hint": "a,b (a与26互质)"},
    "multiplicative": {"name": "乘法密码", "aliases": ["multiplicative", "乘法"], "category": "带key密码", "key_hint": "a (与26互质)"},
    "otp": {"name": "一次一密OTP", "aliases": ["otp", "one_time_pad", "一次一密"], "category": "带key密码", "key_hint": "密钥"},
    "hill": {"name": "希尔Hill", "aliases": ["hill", "希尔"], "category": "多key密码", "key_hint": "矩阵 (如 3,3,2,5)"},
    "gronsfeld": {"name": "Gronsfeld", "aliases": ["gronsfeld"], "category": "带key密码", "key_hint": "数字串"},
    "beaufort": {"name": "博福特Beaufort", "aliases": ["beaufort", "博福特"], "category": "带key密码", "key_hint": "密钥词"},
    "autokey": {"name": "自动密钥Autokey", "aliases": ["autokey", "自动密钥"], "category": "带key密码", "key_hint": "初始密钥"},
    "bifid": {"name": "双密码Bifid", "aliases": ["bifid", "双密码"], "category": "多key密码", "key_hint": "密钥词(可选)"},
    "foursquare": {"name": "四方密码", "aliases": ["foursquare", "四方"], "category": "多key密码", "key_hint": "key1,key2"},
    "scytale": {"name": "斯巴达Scytale", "aliases": ["scytale", "斯巴达", "caesar_box"], "category": "带key密码", "key_hint": "列数"},
    "nihilist": {"name": "Nihilist", "aliases": ["nihilist"], "category": "带key密码", "key_hint": "密钥词"},
    "keyword": {"name": "关键字KeywordCipher", "aliases": ["keyword", "关键字", "keyword_cipher"], "category": "带key密码", "key_hint": "关键字"},
    "simple_substitution": {"name": "简单替换", "aliases": ["simple_substitution", "简单替换", "monoalphabetic"], "category": "带key密码", "key_hint": "26字母替换表"},
    "coltrans": {"name": "列移位ColTrans", "aliases": ["coltrans", "列移位", "columnar_transposition"], "category": "带key密码", "key_hint": "密钥词"},
    "column_permutation": {"name": "列置换", "aliases": ["column_permutation", "列置换"], "category": "带key密码", "key_hint": "密钥词"},
    "rows_permutation": {"name": "行置换", "aliases": ["rows_permutation", "行置换"], "category": "带key密码", "key_hint": "密钥词"},
    "porta": {"name": "城门Porta", "aliases": ["porta", "城门"], "category": "带key密码", "key_hint": "密钥词"},
    "bazeries": {"name": "Bazeries", "aliases": ["bazeries"], "category": "带key密码", "key_hint": "数字串"},
    "fractionated_morse": {"name": "分组摩斯", "aliases": ["fractionated_morse", "分组摩斯"], "category": "带key密码", "key_hint": "密钥词"},
    "fenham": {"name": "费娜姆Fenham", "aliases": ["fenham", "费娜姆"], "category": "带key密码", "key_hint": "密钥词"},
    "running_key": {"name": "滚动密钥", "aliases": ["running_key", "滚动密钥", "running"], "category": "带key密码", "key_hint": "长密钥"},
    "kamasutra": {"name": "爱经Kamasutra", "aliases": ["kamasutra", "爱经"], "category": "带key密码", "key_hint": "无"},
    "fernet": {"name": "Fernet", "aliases": ["fernet"], "category": "带key密码", "key_hint": "32字节base64"},
    "enigma": {"name": "恩尼格玛Enigma M3", "aliases": ["enigma", "恩尼格玛", "enigma_m3"], "category": "多key密码", "key_hint": "如 I II III,AAA|B"},
    "adfgvx": {"name": "ADFGVX", "aliases": ["adfgvx"], "category": "多key密码", "key_hint": "密钥词"},
}

_FUNCS = {
    "affine": (affine_encode, affine_decode),
    "multiplicative": (multiplicative_encode, multiplicative_decode),
    "otp": (otp_encode, otp_decode),
    "hill": (hill_encode, hill_decode),
    "gronsfeld": (gronsfeld_encode, gronsfeld_decode),
    "beaufort": (beaufort_encode, beaufort_decode),
    "autokey": (autokey_encode, autokey_decode),
    "bifid": (bifid_encode, bifid_decode),
    "foursquare": (foursquare_encode, foursquare_decode),
    "scytale": (scytale_encode, scytale_decode),
    "nihilist": (nihilist_encode, nihilist_decode),
    "keyword": (keyword_encode, keyword_decode),
    "simple_substitution": (simple_substitution_encode, simple_substitution_decode),
    "coltrans": (coltrans_encode, coltrans_decode),
    "column_permutation": (column_permutation_encode, column_permutation_decode),
    "rows_permutation": (rows_permutation_encode, rows_permutation_decode),
    "porta": (porta_encode, porta_decode),
    "bazeries": (bazeries_encode, bazeries_decode),
    "fractionated_morse": (fractionated_morse_encode, fractionated_morse_decode),
    "fenham": (fenham_encode, fenham_decode),
    "running_key": (running_key_encode, running_key_decode),
    "kamasutra": (kamasutra_encode, kamasutra_decode),
    "fernet": (fernet_encode, fernet_decode),
    "enigma": (enigma_encode, enigma_decode),
    "adfgvx": (adfgvx_encode, adfgvx_decode),
}


def _norm(cipher_id):
    cid = cipher_id.lower().replace('-', '_').replace(' ', '_')
    alias_map = {}
    for cid_key, info in CIPHERS.items():
        for a in info.get("aliases", []):
            alias_map[a.lower().replace('-', '_').replace(' ', '_')] = cid_key
    return alias_map.get(cid, cid)


def encode(cipher_id, text, key="", **kwargs):
    cid = _norm(cipher_id)
    k = kwargs.get("key", key)
    if cid in _FUNCS:
        return _FUNCS[cid][0](text, k)
    return f"[!] 不支持编码: {cipher_id}"


def decode(cipher_id, cipher_text, key="", **kwargs):
    cid = _norm(cipher_id)
    k = kwargs.get("key", key)
    if cid in _FUNCS:
        return _FUNCS[cid][1](cipher_text, k)
    return f"[!] 不支持解码: {cipher_id}"


def list_ciphers(category=None):
    result = []
    for cid, info in CIPHERS.items():
        if category and info.get("category") != category:
            continue
        result.append({"id": cid, **info})
    return result


def get_cipher(cipher_id):
    return CIPHERS.get(_norm(cipher_id))


def search_ciphers(query):
    q = query.lower()
    out = []
    for cid, info in CIPHERS.items():
        text = cid + " " + info["name"] + " " + " ".join(info.get("aliases", [])) + " " + info["category"]
        if q in text.lower():
            out.append({"id": cid, **info})
    return out


def get_categories():
    return sorted({info["category"] for info in CIPHERS.values()})
