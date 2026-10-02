"""yang_web.core.decoder 子模块 _codec_text（自 decoder.py 拆分，请勿手工重排）。"""

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



def decode_url(text: str) -> str:
    from urllib.parse import unquote
    try:
        return unquote(text.strip(), errors="replace")
    except Exception:
        return ""

def decode_html(text: str) -> str:
    return html_mod.unescape(text.strip())

def decode_rot13(text: str) -> str:
    return codecs.decode(text.strip(), "rot_13")

def decode_binary(text: str) -> str:
    cleaned = text.strip().replace(" ", "").replace("\n", "")
    if len(cleaned) % 8 != 0:
        return ""
    chars = []
    for i in range(0, len(cleaned), 8):
        byte = cleaned[i:i+8]
        try:
            chars.append(chr(int(byte, 2)))
        except ValueError:
            return ""
    return "".join(chars)

def decode_octal(text: str) -> str:
    parts = text.strip().split()
    chars = []
    for p in parts:
        try:
            chars.append(chr(int(p, 8)))
        except (ValueError, OverflowError):
            return ""
    return "".join(chars)

def decode_decimal(text: str) -> str:
    parts = text.strip().split()
    chars = []
    for p in parts:
        try:
            chars.append(chr(int(p)))
        except (ValueError, OverflowError):
            return ""
    return "".join(chars)

def decode_unicode_escape(text: str) -> str:
    try:
        return text.encode().decode("unicode_escape")
    except Exception:
        return ""

def decode_morse(text: str) -> str:
    MORSE = {
        ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
        "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
        "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
        ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
        "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
        "--..": "Z",
        ".----": "1", "..---": "2", "...--": "3", "....-": "4", ".....": "5",
        "-....": "6", "--...": "7", "---..": "8", "----.": "9", "-----": "0",
        "/": " ",
    }
    words = text.strip().split(" / ")
    result = []
    for word in words:
        chars = word.split()
        decoded = "".join(MORSE.get(c, "?") for c in chars)
        result.append(decoded)
    return " ".join(result)
