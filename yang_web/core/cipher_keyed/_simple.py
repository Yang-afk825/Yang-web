"""yang_web.core.cipher_keyed 子模块 _simple（自 cipher_keyed.py 拆分，请勿手工重排）。"""

import base64
import hashlib
import hmac as hmac_mod
import re
from math import gcd
try:
    from .. import crypto_engine
except Exception:
    import crypto_engine

from ._common import (_keyword_alphabet, _modinv, _only_letters)



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
