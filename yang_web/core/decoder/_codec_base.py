"""yang_web.core.decoder 子模块 _codec_base（自 decoder.py 拆分，请勿手工重排）。"""

import re
import base64
import binascii
import string
import html as html_mod
import codecs
from typing import Optional, List, Tuple, Callable
from ..utils import is_printable, text_quality
from ..advanced_engines import (
    brainfuck_decode, ook_decode,
    quoted_printable_decode, uudecode, xxdecode,
    utf7_decode, punycode_decode, shellcode_decode,
    base91_decode, base92_decode,
    rot47_decode, rot5_decode, rot18_decode,    rot47_decode, rot5_decode, rot18_decode,
)
from ..chinese_ciphers import (
    _decode_buddha, core_values_decode, beast_decode,
    bear_decode, surnames_decode, telegraph_decode,
)




# ═══════════════════════════════════════════════════════════
#  编码 / 解码函数
# ═══════════════════════════════════════════════════════════

def decode_base64(text: str) -> str:
    text = text.strip()
    missing = len(text) % 4
    if missing:
        text += "=" * (4 - missing)
    try:
        return base64.b64decode(text, validate=True).decode("utf-8", errors="replace")
    except Exception:
        return base64.b64decode(text, validate=False).decode("utf-8", errors="replace")

def decode_base64url(text: str) -> str:
    text = text.strip()
    missing = len(text) % 4
    if missing:
        text += "=" * (4 - missing)
    try:
        return base64.urlsafe_b64decode(text).decode("utf-8", errors="replace")
    except Exception:
        return ""

def decode_base32(text: str) -> str:
    text = text.strip().rstrip("=").upper()
    missing = len(text) % 8
    if missing:
        text += "=" * (8 - missing)
    try:
        return base64.b32decode(text).decode("utf-8", errors="replace")
    except Exception:
        return ""

def decode_base16(text: str) -> str:
    text = text.strip().replace(" ", "").replace("\n", "")
    if text.startswith("0x") or text.startswith("0X"):
        text = text[2:]
    try:
        return bytes.fromhex(text).decode("utf-8", errors="replace")
    except Exception:
        return ""

def decode_base58(text: str) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    base = len(alphabet)
    num = 0
    for char in text.strip():
        if char not in alphabet:
            return ""
        num = num * base + alphabet.index(char)
    result = []
    while num > 0:
        num, rem = divmod(num, 256)
        result.append(rem)
    for char in text:
        if char == "1":
            result.append(0)
        else:
            break
    return bytes(reversed(result)).decode("utf-8", errors="replace") if result else ""

def decode_base85(text: str) -> str:
    text = text.strip()
    if text.startswith("<~"):
        text = text[2:]
    if text.endswith("~>"):
        text = text[:-2]
    try:
        return base64.a85decode(text.encode(), adobe=True).decode("utf-8", errors="replace")
    except Exception:
        try:
            return base64.b85decode(text.encode()).decode("utf-8", errors="replace")
        except Exception:
            return ""
