"""yang_web.core.misc_crypto 子模块 _coord（自 misc_crypto.py 拆分，请勿手工重排）。"""

import os
import re
import base64 as b64
import binascii
import html as html_mod
import codecs
import urllib.parse
from pathlib import Path

from ._data import (KEYBOARD_COORD_MAP, KEYBOARD_COORD_REV, NUMBER_COORD_MAP, NUMBER_COORD_REV)



def keyboard_coordinate_encode(text: str) -> str:
    result = []
    for c in text.upper():
        if c in KEYBOARD_COORD_MAP:
            result.append(KEYBOARD_COORD_MAP[c])
        else:
            result.append(c)
    return ' '.join(result)


def keyboard_coordinate_decode(cipher_text: str) -> str:
    result = []
    tokens = ''.join(cipher_text.split())
    for i in range(0, len(tokens) - 1, 2):
        pair = tokens[i:i+2]
        if pair in KEYBOARD_COORD_REV:
            result.append(KEYBOARD_COORD_REV[pair])
        else:
            result.append('?')
    return ''.join(result)


def number_coordinate_encode(text: str) -> str:
    result = []
    for c in text.upper():
        if c in NUMBER_COORD_MAP:
            result.append(NUMBER_COORD_MAP[c])
        else:
            result.append(c)
    return ' '.join(result)


def number_coordinate_decode(cipher_text: str) -> str:
    result = []
    tokens = cipher_text.split()
    for t in tokens:
        if t in NUMBER_COORD_REV:
            result.append(NUMBER_COORD_REV[t])
        else:
            result.append('?')
    return ''.join(result)


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
