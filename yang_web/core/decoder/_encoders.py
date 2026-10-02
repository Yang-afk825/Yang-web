"""yang_web.core.decoder 子模块 _encoders（自 decoder.py 拆分，请勿手工重排）。"""

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
#  编码函数
# ═══════════════════════════════════════════════════════════

def _encode_base64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()

def _encode_base64url(text: str) -> str:
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")

def _encode_base32(text: str) -> str:
    return base64.b32encode(text.encode()).decode().rstrip("=")

def _encode_base16(text: str) -> str:
    return text.encode().hex()

def _encode_base58(text: str) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    data = text.encode()
    n = int.from_bytes(data, "big")
    if n == 0:
        return "1"
    result = []
    while n > 0:
        n, rem = divmod(n, 58)
        result.append(alphabet[rem])
    for byte in data:
        if byte == 0:
            result.append("1")
        else:
            break
    return "".join(reversed(result))

def _encode_base85(text: str) -> str:
    return base64.a85encode(text.encode(), adobe=True).decode()

def _encode_url(text: str) -> str:
    from urllib.parse import quote
    return quote(text, safe="")

def _encode_html(text: str) -> str:
    return html_mod.escape(text)

def _encode_binary(text: str) -> str:
    return " ".join(f"{ord(c):08b}" for c in text)

def _encode_octal(text: str) -> str:
    return " ".join(f"{oct(ord(c))[2:]:0>3}" for c in text)

def _encode_decimal(text: str) -> str:
    return " ".join(str(ord(c)) for c in text)

def _encode_unicode_escape(text: str) -> str:
    return text.encode("unicode_escape").decode()

def _encode_morse(text: str) -> str:
    MORSE_ENC = {
        "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
        "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
        "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
        "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
        "Y": "-.--", "Z": "--..",
        "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....",
        "6": "-....", "7": "--...", "8": "---..", "9": "----.", "0": "-----",
        " ": "/",
    }
    return " ".join(MORSE_ENC.get(c.upper(), "?") for c in text)
