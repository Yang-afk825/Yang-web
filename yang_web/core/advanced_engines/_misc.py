"""yang_web.core.advanced_engines 子模块 _misc（自 advanced_engines.py 拆分，请勿手工重排）。"""

import re
import base64
import codecs
import struct
from typing import Optional, Tuple




# ═══════════════════════════════════════════
# 6. UTF-7 编解码
# ═══════════════════════════════════════════

def utf7_encode(text: str) -> str:
    """Encode text to UTF-7 format."""
    return text.encode('utf-7').decode('ascii', errors='replace')


def utf7_decode(cipher: str) -> str:
    """Decode UTF-7 text."""
    return cipher.encode('ascii').decode('utf-7', errors='replace')


# ═══════════════════════════════════════════
# 7. Zero-Width 字符隐写
# ═══════════════════════════════════════════

# Zero-width mapping: binary -> zero-width chars
ZW_MAP = ['\u200b', '\u200c', '\u200d', '\ufeff']  # 00, 01, 10, 11
ZW_TO_BITS = {c: f"{i:02b}" for i, c in enumerate(ZW_MAP)}


def zerowidth_encode(text: str) -> str:
    """Encode text as zero-width characters."""
    binary = ''.join(f"{ord(c):016b}" for c in text)
    result = []
    for i in range(0, len(binary), 2):
        pair = binary[i:i+2]
        idx = int(pair, 2) if len(pair) == 2 else 0
        result.append(ZW_MAP[idx])
    return ''.join(result)


def zerowidth_decode(cipher: str) -> str:
    """Decode zero-width characters to text."""
    binary = []
    for c in cipher:
        if c in ZW_TO_BITS:
            binary.append(ZW_TO_BITS[c])
    bit_string = ''.join(binary)
    result = []
    for i in range(0, len(bit_string) - 15, 16):
        try:
            result.append(chr(int(bit_string[i:i+16], 2)))
        except (ValueError, OverflowError):
            pass
    return ''.join(result)


# ═══════════════════════════════════════════
# 13. Punycode / IDNA 编解码
# ═══════════════════════════════════════════

def punycode_encode(text: str) -> str:
    """Encode domain/string to Punycode."""
    result = []
    for part in text.split('.'):
        if all(ord(c) < 128 for c in part):
            result.append(part)
        else:
            result.append('xn--' + part.encode('punycode').decode('ascii'))
    return '.'.join(result)


def punycode_decode(cipher: str) -> str:
    """Decode Punycode to original text."""
    if cipher.startswith('xn--'):
        return cipher[4:].encode('ascii').decode('punycode')
    parts = []
    for part in cipher.split('.'):
        if part.startswith('xn--'):
            parts.append(part[4:].encode('ascii').decode('punycode'))
        else:
            parts.append(part)
    return '.'.join(parts)


# ═══════════════════════════════════════════
# 14. Shellcode 编码 (Hex \x 格式)
# ═══════════════════════════════════════════

def shellcode_encode(text: str) -> str:
    """Convert text to shellcode hex format."""
    return ''.join(f'\\x{ord(c):02x}' for c in text)


def shellcode_decode(cipher: str) -> str:
    """Decode \\x format shellcode to text."""
    import re as re_mod
    hex_pairs = re_mod.findall(r'\\x([0-9a-fA-F]{2})', cipher)
    if hex_pairs:
        return ''.join(chr(int(h, 16)) for h in hex_pairs)
    # Also try without \x prefix
    clean = cipher.replace('\\x', '').replace('0x', '').replace(' ', '')
    try:
        return bytes.fromhex(clean).decode('utf-8', errors='replace')
    except Exception:
        return '[!] 无法解析'


# ═══════════════════════════════════════════
# 16. 多重编码级联
# ═══════════════════════════════════════════

def _xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR bytes with key."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
