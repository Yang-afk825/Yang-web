"""yang_web.core.advanced_engines 子模块 _rot（自 advanced_engines.py 拆分，请勿手工重排）。"""

import re
import base64
import codecs
import struct
from typing import Optional, Tuple




# ═══════════════════════════════════════════
# 15. ROT47, ROT5, ROT18 变体
# ═══════════════════════════════════════════

def rot47_encode(text: str) -> str:
    """ROT47 cipher (all printable ASCII)."""
    result = []
    for c in text:
        code = ord(c)
        if 33 <= code <= 126:
            result.append(chr(33 + ((code - 33 + 47) % 94)))
        else:
            result.append(c)
    return ''.join(result)


def rot47_decode(cipher: str) -> str:
    """ROT47 is self-inverse."""
    return rot47_encode(cipher)


def rot5_encode(text: str) -> str:
    """ROT5 (digits only)."""
    result = []
    for c in text:
        if '0' <= c <= '9':
            result.append(str((int(c) + 5) % 10))
        else:
            result.append(c)
    return ''.join(result)


def rot5_decode(cipher: str) -> str:
    """ROT5 decode."""
    result = []
    for c in cipher:
        if '0' <= c <= '9':
            result.append(str((int(c) + 5) % 10))
        else:
            result.append(c)
    return ''.join(result)


def rot18_encode(text: str) -> str:
    """ROT18 = ROT13（字母）+ ROT5（数字）。"""
    result = []
    for c in text:
        if 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
        elif 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
        elif '0' <= c <= '9':
            result.append(str((int(c) + 5) % 10))
        else:
            result.append(c)
    return ''.join(result)


def rot18_decode(cipher: str) -> str:
    """ROT18 is self-inverse (rot13 for letters, rot5 for digits)."""
    return rot18_encode(cipher)


def rot8000_encode(text: str) -> str:
    """ROT8000 - rotate through ~32k Unicode chars."""
    result = []
    for c in text:
        code = ord(c)
        if 33 <= code <= 126:
            # Rotate in Unicode BMP range
            new_code = code + 32768
            if new_code > 65535:
                new_code = new_code - 94
            result.append(chr(new_code))
        else:
            result.append(c)
    return ''.join(result)


def rot8000_decode(cipher: str) -> str:
    """ROT8000 decode."""
    result = []
    for c in cipher:
        code = ord(c)
        if code >= 32801:
            new_code = code - 32768
            if 33 <= new_code <= 126:
                result.append(chr(new_code))
                continue
        result.append(c)
    return ''.join(result)
