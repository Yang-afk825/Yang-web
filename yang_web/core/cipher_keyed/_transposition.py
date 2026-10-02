"""yang_web.core.cipher_keyed 子模块 _transposition（自 cipher_keyed.py 拆分，请勿手工重排）。"""

import base64
import hashlib
import hmac as hmac_mod
import re
from math import gcd
try:
    from .. import crypto_engine
except Exception:
    import crypto_engine

from ._common import (_only_letters)


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
