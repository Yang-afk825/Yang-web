"""yang_web.core.advanced_engines 子模块 _mailbin（自 advanced_engines.py 拆分，请勿手工重排）。"""

import re
import base64
import codecs
import struct
from typing import Optional, Tuple




# ═══════════════════════════════════════════
# 3. Quoted-Printable
# ═══════════════════════════════════════════

def quoted_printable_encode(text: str) -> str:
    """Encode text to Quoted-Printable format (pure Python)."""
    data = text.encode('utf-8')
    result = []
    for byte in data:
        if byte == 32:
            result.append('_')
        elif (byte < 33 or byte > 126 or byte == 61):
            result.append(f'={byte:02X}')
        else:
            result.append(chr(byte))
    return ''.join(result)


def quoted_printable_decode(cipher: str) -> str:
    """Decode Quoted-Printable text (pure Python, no quopri)."""
    import re

    result = bytearray()
    i = 0
    s = cipher.strip()

    while i < len(s):
        c = s[i]
        if c == '=':
            if i + 2 < len(s):
                hex_pair = s[i+1:i+3]
                if hex_pair == '\r\n' or hex_pair == '\n':
                    # Soft line break, skip
                    i += 3
                    continue
                try:
                    result.append(int(hex_pair, 16))
                    i += 3
                    continue
                except ValueError:
                    pass
        result.append(ord(c))
        i += 1

    return bytes(result).decode('utf-8', errors='replace')


# ═══════════════════════════════════════════
# 4. UUEncode
# ═══════════════════════════════════════════

def uuencode(text: str) -> str:
    """Encode text to UUEncode format."""
    data = text.encode('utf-8')
    result = []
    for i in range(0, len(data), 45):
        chunk = data[i:i+45]
        length_byte = chr(32 + len(chunk))
        encoded = base64.b64encode(chunk).decode('ascii').replace('+', '+')  # standard
        result.append(length_byte + encoded)
    result.append('`')  # end marker
    return '\n'.join(result)


def uudecode(cipher: str) -> str:
    """Decode UUEncode text."""
    result = bytearray()
    for line in cipher.strip().split('\n'):
        line = line.strip()
        if not line or line == '`' or line.startswith('begin') or line.startswith('end'):
            continue
        length_byte = ord(line[0]) if line else 0
        if length_byte < 32 or length_byte > 96:
            continue
        count = length_byte - 32
        data_str = line[1:].strip()
        if count > 0:
            try:
                decoded = base64.b64decode(data_str + '==')
                result.extend(decoded[:count])
            except Exception:
                pass
    return bytes(result).decode('utf-8', errors='replace')


# ═══════════════════════════════════════════
# 5. XXEncode
# ═══════════════════════════════════════════

XXENCODE_ALPHABET = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def xxencode(text: str) -> str:
    """Encode text to XXEncode format."""
    data = text.encode('utf-8')
    result = []
    for i in range(0, len(data), 45):
        chunk = data[i:i+45]
        length_byte = chr(32 + len(chunk))
        # XXEncode uses its own alphabet
        # Convert each 3 bytes to 4 chars using the xx alphabet
        encoded_chars = []
        for j in range(0, len(chunk), 3):
            triple = chunk[j:j+3]
            if len(triple) < 3:
                triple = triple + b'\x00' * (3 - len(triple))
            vals = [triple[0] >> 2,
                    ((triple[0] & 0x03) << 4) | (triple[1] >> 4),
                    ((triple[1] & 0x0F) << 2) | (triple[2] >> 6),
                    triple[2] & 0x3F]
            encoded_chars.extend(XXENCODE_ALPHABET[v] for v in vals)
        # Trim padding
        encoded_chars = encoded_chars[:((len(chunk) + 2) // 3) * 4]
        result.append(length_byte + ''.join(encoded_chars))
    result.append('+')  # end marker
    return '\n'.join(result)


def xxdecode(cipher: str) -> str:
    """Decode XXEncode text."""
    result = bytearray()
    for line in cipher.strip().split('\n'):
        line = line.strip()
        if not line or line == '+' or line.startswith('begin'):
            continue
        length_byte = ord(line[0]) if line else 0
        if length_byte < 32 or length_byte > 96:
            continue
        count = length_byte - 32
        data_str = line[1:].strip()
        if count > 0:
            for j in range(0, len(data_str), 4):
                quad = data_str[j:j+4]
                if len(quad) < 4:
                    quad = quad + '0' * (4 - len(quad))
                try:
                    vals = [XXENCODE_ALPHABET.index(q) for q in quad]
                    b0 = (vals[0] << 2) | (vals[1] >> 4)
                    b1 = ((vals[1] & 0x0F) << 4) | (vals[2] >> 2)
                    b2 = ((vals[2] & 0x03) << 6) | vals[3]
                    result.extend([b0, b1, b2])
                except ValueError:
                    pass
    return bytes(result[:len(result) - (3 - (count % 3)) if count % 3 else len(result)]).decode('utf-8', errors='replace')
