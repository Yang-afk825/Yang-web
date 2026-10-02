"""yang_web.core.misc_crypto 子模块 _encoding（自 misc_crypto.py 拆分，请勿手工重排）。"""

import os
import re
import base64 as b64
import binascii
import html as html_mod
import codecs
import urllib.parse
from pathlib import Path

from ._data import (_B58_ALPHABET)



# ═══════════════════════════════════════════
#  基础编码 encode/decode (Base64/32/16/58/85/URL/HTML/Unicode/Binary/Octal)
# ═══════════════════════════════════════════

# ── Base64 ────────────────────────────────
def base64_encode(text: str) -> str:
    return b64.b64encode(text.encode('utf-8')).decode('ascii')

def base64_decode(cipher_text: str) -> str:
    t = cipher_text.strip()
    missing = len(t) % 4
    if missing:
        t += '=' * (4 - missing)
    try:
        return b64.b64decode(t, validate=True).decode('utf-8', errors='replace')
    except Exception:
        return b64.b64decode(t).decode('utf-8', errors='replace')


# ── Base32 ────────────────────────────────
def base32_encode(text: str) -> str:
    return b64.b32encode(text.encode('utf-8')).decode('ascii')

def base32_decode(cipher_text: str) -> str:
    t = cipher_text.strip().rstrip('=').upper()
    missing = len(t) % 8
    if missing:
        t += '=' * (8 - missing)
    try:
        return b64.b32decode(t).decode('utf-8', errors='replace')
    except Exception:
        return ''


# ── Base16 / Hex ──────────────────────────
def base16_encode(text: str) -> str:
    return text.encode('utf-8').hex()

def base16_decode(cipher_text: str) -> str:
    t = cipher_text.strip().replace(' ', '').replace('\n', '')
    if t.lower().startswith('0x'):
        t = t[2:]
    try:
        return bytes.fromhex(t).decode('utf-8', errors='replace')
    except Exception:
        return ''

def base58_encode(text: str) -> str:
    data = text.encode('utf-8')
    n = int.from_bytes(data, 'big')
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(_B58_ALPHABET[r])
    # Add leading zeros
    for byte in data:
        if byte == 0:
            res.append(_B58_ALPHABET[0])
        else:
            break
    return ''.join(reversed(res))

def base58_decode(cipher_text: str) -> str:
    t = cipher_text.strip()
    n = 0
    for c in t:
        if c not in _B58_ALPHABET:
            continue
        n = n * 58 + _B58_ALPHABET.index(c)
    # Leading zeros from alphabet[0]
    leading_zeros = 0
    for c in t:
        if c == _B58_ALPHABET[0]:
            leading_zeros += 1
        else:
            break
    try:
        result = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        return (b'\x00' * leading_zeros + result).decode('utf-8', errors='replace')
    except Exception:
        return ''


# ── Base85 ────────────────────────────────
def base85_encode(text: str) -> str:
    try:
        return b64.a85encode(text.encode('utf-8')).decode('ascii')
    except Exception:
        return b64.b85encode(text.encode('utf-8')).decode('ascii')

def base85_decode(cipher_text: str) -> str:
    t = cipher_text.strip()
    try:
        return b64.a85decode(t.encode('ascii'), adobe=True).decode('utf-8', errors='replace')
    except Exception:
        try:
            return b64.a85decode(t.encode('ascii')).decode('utf-8', errors='replace')
        except Exception:
            try:
                return b64.b85decode(t.encode('ascii')).decode('utf-8', errors='replace')
            except Exception:
                return ''


# ── URL Encode ────────────────────────────
def url_encode(text: str) -> str:
    return urllib.parse.quote(text, safe='')

def url_decode(cipher_text: str) -> str:
    t = cipher_text.strip()
    # Handle + → space
    t = t.replace('+', '%20')
    try:
        return urllib.parse.unquote(t, encoding='utf-8')
    except Exception:
        return ''


# ── HTML Entity ───────────────────────────
def html_encode(text: str) -> str:
    return html_mod.escape(text)

def html_decode(cipher_text: str) -> str:
    try:
        return html_mod.unescape(cipher_text)
    except Exception:
        return cipher_text


# ── Unicode Escape ────────────────────────
def unicode_encode(text: str) -> str:
    result = []
    for c in text:
        cp = ord(c)
        if cp > 127:
            result.append(f'\\u{cp:04x}')
        else:
            result.append(c)
    return ''.join(result)

def unicode_decode(cipher_text: str) -> str:
    try:
        return codecs.decode(cipher_text, 'unicode_escape')
    except Exception:
        return cipher_text


# ── Binary String ─────────────────────────
def binary_str_encode(text: str) -> str:
    return ' '.join(format(ord(c), '08b') for c in text)

def binary_str_decode(cipher_text: str) -> str:
    cleaned = cipher_text.replace(' ', '').replace('\n', '')
    result = []
    for i in range(0, len(cleaned) - 7, 8):
        try:
            result.append(chr(int(cleaned[i:i+8], 2)))
        except ValueError:
            result.append('?')
    return ''.join(result)


# ── Octal String ──────────────────────────
def octal_str_encode(text: str) -> str:
    return ' '.join(f'\\{oct(ord(c))[2:].zfill(3)}' for c in text)

def octal_str_decode(cipher_text: str) -> str:
    parts = cipher_text.strip().split()
    result = []
    for p in parts:
        p = p.strip('\\')
        try:
            result.append(chr(int(p, 8)))
        except ValueError:
            result.append('?')
    return ''.join(result)


# ── Decimal ASCII ─────────────────────────
def decimal_str_encode(text: str) -> str:
    return ' '.join(str(ord(c)) for c in text)

def decimal_str_decode(cipher_text: str) -> str:
    parts = cipher_text.strip().split()
    result = []
    for p in parts:
        try:
            n = int(p)
            if 0 <= n <= 0x10FFFF:
                result.append(chr(n))
            else:
                result.append('?')
        except ValueError:
            result.append('?')
    return ''.join(result)
