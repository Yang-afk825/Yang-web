"""yang_web.core.decoder 子模块 _det_text（自 decoder.py 拆分，请勿手工重排）。"""

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
    rot47_decode, rot5_decode, rot18_decode,
)
from ..chinese_ciphers import (
    _decode_buddha, core_values_decode, beast_decode,
    bear_decode, surnames_decode, telegraph_decode,
)



def _is_url_encoded(text: str) -> int:
    text = text.strip()
    pct_count = text.count("%")
    if pct_count == 0:
        return 0
    matches = re.findall(r"%[0-9a-fA-F]{2}", text)
    if len(matches) == pct_count and pct_count >= 1:
        return 90
    if len(matches) >= pct_count * 0.8:
        return 70
    return 20

def _is_html_entity(text: str) -> int:
    named = len(re.findall(r"&[a-zA-Z]+;", text))
    numeric = len(re.findall(r"&#\d+;", text))
    hex_entity = len(re.findall(r"&#x[0-9a-fA-F]+;", text))
    total = named + numeric + hex_entity
    if total >= 2:
        return 85
    if total == 1 and len(text) < 20:
        return 60
    return 0

def _is_rot13(text: str) -> int:
    letters = sum(1 for c in text if c.isalpha())
    if letters == 0:
        return 0
    rot13_text = codecs.decode(text, "rot_13")
    common_words = ["the", "and", "is", "are", "this", "that", "flag", "ctf"]
    original_score = sum(1 for w in common_words if w in text.lower())
    decoded_score = sum(1 for w in common_words if w in rot13_text.lower())
    if decoded_score > original_score and decoded_score >= 1:
        return 80
    if letters / len(text) > 0.8:
        return 50
    return 10

def _is_rot47(text: str) -> int:
    """Detect if ROT47 is likely (printable ASCII with no obvious pattern)."""
    if len(text) < 4:
        return 0
    printable = sum(1 for c in text if 32 <= ord(c) <= 126)
    if printable / len(text) < 0.9:
        return 0
    # Try ROT47 and check for common words
    decoded = rot47_decode(text)
    common = ['the', 'and', 'is', 'are', 'this', 'flag', 'ctf', 'http', 'www']
    score = sum(1 for w in common if w in decoded.lower())
    orig_score = sum(1 for w in common if w in text.lower())
    if score > orig_score and score >= 1:
        return 75
    return 15

def _is_binary(text: str) -> int:
    cleaned = text.replace(" ", "").replace("\n", "")
    if cleaned and all(c in "01" for c in cleaned):
        if len(cleaned) % 8 == 0 and len(cleaned) >= 8:
            return 95
        return 80
    return 0

def _is_octal(text: str) -> int:
    cleaned = text.strip()
    parts = cleaned.split()
    if all(re.fullmatch(r"[0-7]{2,3}", p) for p in parts) and len(parts) >= 2:
        return 85
    return 0

def _is_decimal(text: str) -> int:
    parts = text.strip().split()
    if len(parts) < 2:
        return 0
    nums = []
    for p in parts:
        try:
            n = int(p)
            if 32 <= n <= 126:
                nums.append(n)
            else:
                return 0
        except ValueError:
            return 0
    if len(nums) >= 2:
        return 85
    return 0

def _is_unicode_escape(text: str) -> int:
    u4 = len(re.findall(r"\\u[0-9a-fA-F]{4}", text))
    u8 = len(re.findall(r"\\U[0-9a-fA-F]{8}", text))
    if u4 + u8 >= 2:
        return 90
    if u4 + u8 == 1:
        return 60
    return 0

def _is_morse(text: str) -> int:
    cleaned = text.strip()
    total = len(cleaned.replace(" ", "").replace("/", ""))
    if total == 0:
        return 0
    morse_chars = {".", "-"}
    morse_ratio = sum(1 for c in cleaned if c in morse_chars or c in " /") / len(cleaned)
    if morse_ratio > 0.9 and "." in cleaned and "-" in cleaned:
        return 90
    if morse_ratio > 0.8:
        return 60
    return 0
