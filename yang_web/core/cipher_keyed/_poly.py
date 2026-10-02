"""yang_web.core.cipher_keyed 子模块 _poly（自 cipher_keyed.py 拆分，请勿手工重排）。"""

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
