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
    """Encode text as zero-width characters（每个 UTF-16 码元占 16 bit）。

    旧实现用 ``ord(c):016b`` —— 宽度 16 只是**下限**，
    码点超过 U+FFFF（emoji 等）会输出 17 位，整个比特流从此错位。
    改用 UTF-16 码元，BMP 内外一律 16 位。
    """
    data = text.encode('utf-16-be')
    binary = ''.join(format(int.from_bytes(data[i:i + 2], 'big'), '016b')
                     for i in range(0, len(data), 2))
    result = []
    for i in range(0, len(binary), 2):
        pair = binary[i:i + 2]
        idx = int(pair, 2) if len(pair) == 2 else 0
        result.append(ZW_MAP[idx])
    return ''.join(result)


def zerowidth_decode(cipher: str) -> str:
    """Decode zero-width characters to text."""
    binary = ''.join(ZW_TO_BITS[c] for c in cipher if c in ZW_TO_BITS)
    out = bytearray()
    for i in range(0, len(binary) - 15, 16):
        out.extend(int(binary[i:i + 16], 2).to_bytes(2, 'big'))
    return bytes(out).decode('utf-16-be', errors='replace')


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
    """Convert text to shellcode hex format.

    按 UTF-8 **字节** 展开。旧实现用 ``f'\\\\x{ord(c):02x}'``——
    ``02x`` 只是最小宽度，中文会写成 ``\\x4e2d`` 这种 4 位「伪字节」，
    而解码端只认 2 位十六进制，必然错位。
    """
    return ''.join(f'\\x{b:02x}' for b in text.encode('utf-8'))


def shellcode_decode(cipher: str) -> str:
    """Decode \\x format shellcode to text."""
    import re as re_mod
    hex_pairs = re_mod.findall(r'\\x([0-9a-fA-F]{2})', cipher)
    if hex_pairs:
        return bytes(int(h, 16) for h in hex_pairs).decode('utf-8', errors='replace')
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
