# -*- coding: utf-8 -*-
"""智能解码引擎 — 自动检测编码类型并链式解码.

支持编码类型 (共 28+ 种):
    Base 系: base64/32/16/58/85/91/92, url, html, unicode
    进制: 二进制/八进制/十进制
    古典: ROT13/ROT47/ROT5/ROT18, 摩斯电码
    传输: Quoted-Printable, UUEncode, XXEncode, UTF-7, Punycode, Shellcode
    编程: Brainfuck, Ook!
"""
import re
import base64
import binascii
import string
import html as html_mod
import codecs
from typing import Optional, List, Tuple, Callable
from .utils import is_printable
from .advanced_engines import (
    brainfuck_decode, ook_decode,
    quoted_printable_decode, uudecode, xxdecode,
    utf7_decode, punycode_decode, shellcode_decode,
    base91_decode, base92_decode,
    rot47_decode, rot5_decode, rot18_decode,
)


# ═══════════════════════════════════════════════════════════
#  编码检测函数 — 返回置信度 0-100
# ═══════════════════════════════════════════════════════════

def _is_base64(text: str) -> int:
    text = text.strip().rstrip("=")
    if len(text) % 4 == 1:
        return 0
    charset = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    if not all(c in charset for c in text):
        return 0
    upper = sum(1 for c in text if c.isupper())
    lower = sum(1 for c in text if c.islower())
    digits = sum(1 for c in text if c.isdigit())
    if upper > 0 and (lower > 0 or digits > 0):
        return 85
    if upper > 0:
        return 70
    return 40

def _is_base64_urlsafe(text: str) -> int:
    text = text.strip().rstrip("=")
    charset = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")
    if not all(c in charset for c in text):
        return 0
    if "-" in text or "_" in text:
        return 85
    return 0

def _is_base32(text: str) -> int:
    text = text.strip().rstrip("=").upper()
    charset = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
    if not all(c in charset for c in text):
        return 0
    if len(text) % 8 == 0:
        return 90
    return 75

def _is_base16(text: str) -> int:
    text = text.strip().replace(" ", "").replace("\n", "")
    if re.fullmatch(r"[0-9a-fA-F]+", text):
        if len(text) % 2 == 0:
            alpha = sum(1 for c in text if c.isalpha())
            if alpha > len(text) * 0.3:
                return 90
            return 75
        return 50
    return 0

def _is_base58(text: str) -> int:
    charset = set("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
    if not all(c in charset for c in text):
        return 0
    return 85

def _is_base85(text: str) -> int:
    charset = set(string.printable) - set("\t\n\r\x0b\x0c'\"\\")
    if not all(c in charset for c in text):
        return 0
    special = sum(1 for c in text if c in "~!@#$%^&*()_+-=[]|:;<>,.?/")
    if special > len(text) * 0.1:
        return 70
    return 30

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


def _is_quoted_printable(text: str) -> int:
    """Detect Quoted-Printable (=XX format)."""
    text = text.strip()
    # Count =XX hex patterns
    matches = re.findall(r'=[0-9A-Fa-f]{2}', text)
    if len(matches) < 2:
        return 0
    # Check ratio of encoded content
    encoded_len = len(''.join(matches))
    ratio = encoded_len / max(len(text), 1)
    # QP signature: 3 chars per byte (=XX), so high density
    if ratio > 0.55:  # >= 3 out of every ~5 chars are =XX
        return 95
    if ratio > 0.30:
        # Make sure it's not just base64 with random = signs
        if text.count('=') >= 3 and all(c in '0123456789ABCDEFabcdef=' for c in text):
            return 90
        return 80
    return 0

def _is_uuencode(text: str) -> int:
    """Detect UUEncode format."""
    lines = text.strip().split('\n')
    if len(lines) < 2:
        return 0
    has_begin = any('begin' in l.lower() for l in lines[:2])
    has_end = any('end' in l.lower() for l in lines[-2:])
    has_len_byte = False
    for l in lines:
        l = l.strip()
        if l and 32 <= ord(l[0]) <= 96 and l[0] not in 'M':
            has_len_byte = True
            break
    if has_begin and has_end:
        return 90
    if has_len_byte and has_begin:
        return 75
    return 0

def _is_xxencode(text: str) -> int:
    """Detect XXEncode format."""
    lines = text.strip().split('\n')
    if len(lines) < 2:
        return 0
    has_begin = any('begin' in l.lower() for l in lines[:2])
    has_len_byte = False
    xx_chars = set('+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
    for l in lines:
        l = l.strip()
        if l and 32 <= ord(l[0]) <= 96:
            # Check if line body uses XXEncode alphabet
            body = l[1:]
            if body and all(c in xx_chars for c in body[:min(20, len(body))]):
                has_len_byte = True
                break
    if has_begin and has_len_byte:
        return 85
    if has_len_byte and text.strip().endswith('+'):
        return 70
    return 0

def _is_brainfuck(text: str) -> int:
    """Detect Brainfuck code."""
    bf_chars = set('><+-.,[]')
    clean = ''.join(c for c in text if not c.isspace())
    if not clean:
        return 0
    ratio = sum(1 for c in clean if c in bf_chars) / len(clean)
    if ratio > 0.95 and any(c in clean for c in '[]'):
        return 95
    if ratio > 0.9 and len(clean) >= 10:
        return 80
    return 0

def _is_ook(text: str) -> int:
    """Detect Ook! language."""
    clean = text.strip()
    tokens = clean.split()
    if len(tokens) < 4:
        return 0
    ook_tokens = {'Ook.', 'Ook?', 'Ook!'}
    matches = sum(1 for t in tokens if t in ook_tokens)
    if matches >= len(tokens) * 0.8:
        return 95
    if matches >= 4:
        return 75
    return 0

def _is_utf7(text: str) -> int:
    """Detect UTF-7 encoded text."""
    text = text.strip()
    # UTF-7 uses +XXX- patterns where XXX is base64
    if '+ADw-' in text or '+AD4-' in text:
        return 90
    matches = re.findall(r'\+[A-Za-z0-9+/]+-', text)
    if matches and len(text) > 5:
        return 80
    return 0

def _is_zerowidth(text: str) -> int:
    """Detect zero-width character encoding."""
    zw_chars = {'\u200b', '\u200c', '\u200d', '\ufeff'}
    count = sum(1 for c in text if c in zw_chars)
    if count >= 4:
        return 95
    if count >= 2:
        return 75
    return 0

def _is_punycode(text: str) -> int:
    """Detect Punycode/IDNA encoding."""
    if 'xn--' in text.lower():
        if '.' in text:
            return 90
        return 80
    return 0

def _is_shellcode(text: str) -> int:
    """Detect shellcode \\x format."""
    hex_pairs = re.findall(r'\\x[0-9a-fA-F]{2}', text)
    if len(hex_pairs) >= 4:
        ratio = len(''.join(hex_pairs)) / max(len(text), 1)
        if ratio > 0.4:
            return 95
        return 80
    if len(hex_pairs) >= 2 and len(text) < 40:
        return 60
    return 0

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

def _is_base91(text: str) -> int:
    """Detect Base91 encoding."""
    charset = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"')
    text = text.strip()
    if not text:
        return 0
    match = sum(1 for c in text if c in charset)
    if match / len(text) > 0.95:
        # Check for special chars that distinguish from base64
        special = sum(1 for c in text if c in '!#$%&()*+,./:;<=>?@[]^_`{|}~')
        if special > len(text) * 0.05:
            return 80
        return 50
    return 0

def _is_base92(text: str) -> int:
    """Detect Base92 encoding."""
    charset = set("!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_abcdefghijklmnopqrstuvwxyz{|}")
    text = text.strip()
    if not text:
        return 0
    match = sum(1 for c in text if c in charset)
    if match / len(text) > 0.95 and len(text) > 4:
        # Has backslash or single quote (not in base91)
        if "'" in text or '\\' in text or '|' in text:
            return 85
        return 55
    return 0

# ═══════════════════════════════════════════════════════════
#  编码描述 & 检测器注册表
# ═══════════════════════════════════════════════════════════

ENCODING_DETECTORS: List[Tuple[str, str, Callable[[str], int]]] = [
    ("binary",     "二进制 0101",          _is_binary),
    ("octal",      "八进制 \\123",         _is_octal),
    ("decimal",    "十进制 ASCII 码",       _is_decimal),
    ("morse",      "摩斯电码 .-",          _is_morse),
    ("base16",     "Base16 / HEX",         _is_base16),
    ("base32",     "Base32",               _is_base32),
    ("base58",     "Base58 (Bitcoin)",     _is_base58),
    ("base64",     "Base64",               _is_base64),
    ("base64url",  "Base64 URL-safe",      _is_base64_urlsafe),
    ("base85",     "Base85 / ASCII85",     _is_base85),
    ("base91",     "Base91",               _is_base91),
    ("base92",     "Base92",               _is_base92),
    ("url",        "URL 编码 %xx",        _is_url_encoded),
    ("html",       "HTML 实体 &amp;",      _is_html_entity),
    ("unicode",    "Unicode 转义 \\u",   _is_unicode_escape),
    ("rot13",      "ROT13",                _is_rot13),
    ("rot47",      "ROT47",                _is_rot47),
    ("shellcode",  "Shellcode \\x 格式",  _is_shellcode),
    ("brainfuck",  "Brainfuck",            _is_brainfuck),
    ("ook",        "Ook!",                 _is_ook),
    ("quoted_printable", "Quoted-Printable", _is_quoted_printable),
    ("uuencode",   "UUEncode",             _is_uuencode),
    ("xxencode",   "XXEncode",             _is_xxencode),
    ("utf7",       "UTF-7 编码",           _is_utf7),
    ("punycode",   "Punycode / IDNA",      _is_punycode),
]


def detect_encoding(text: str) -> List[Tuple[str, str, int]]:
    """检测文本最可能的编码类型. 返回: [(编码ID, 描述, 置信度0-100), ...] 按置信度降序排列."""
    if not text or len(text.strip()) < 2:
        return []
    results = []
    for enc_id, desc, detector in ENCODING_DETECTORS:
        confidence = detector(text)
        if confidence > 0:
            results.append((enc_id, desc, confidence))
    results.sort(key=lambda x: x[2], reverse=True)
    return results


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


# ═══════════════════════════════════════════════════════════
#  编码/解码 调度表
# ═══════════════════════════════════════════════════════════

def _decode_qp_wrapper(text: str) -> str:
    """Wrapper for Quoted-Printable decode."""
    return quoted_printable_decode(text)

def _decode_uu_wrapper(text: str) -> str:
    """Wrapper for UUEncode decode."""
    return uudecode(text)

def _decode_xx_wrapper(text: str) -> str:
    """Wrapper for XXEncode decode."""
    return xxdecode(text)

def _decode_bf_wrapper(text: str) -> str:
    """Wrapper for Brainfuck decode."""
    return brainfuck_decode(text)

def _decode_ook_wrapper(text: str) -> str:
    """Wrapper for Ook! decode."""
    return ook_decode(text)

def _decode_utf7_wrapper(text: str) -> str:
    """Wrapper for UTF-7 decode."""
    return utf7_decode(text)

def _decode_punycode_wrapper(text: str) -> str:
    """Wrapper for Punycode decode."""
    return punycode_decode(text)

def _decode_shellcode_wrapper(text: str) -> str:
    """Wrapper for Shellcode decode."""
    return shellcode_decode(text)

def _decode_base91_wrapper(text: str) -> str:
    """Wrapper for Base91 decode."""
    return base91_decode(text)

def _decode_base92_wrapper(text: str) -> str:
    """Wrapper for Base92 decode."""
    return base92_decode(text)


def _encode_rot47(text: str) -> str:
    return rot47_decode(text)  # self-inverse

def _encode_rot5(text: str) -> str:
    return rot5_decode(text)

def _encode_rot18(text: str) -> str:
    return rot18_decode(text)

def _encode_shellcode(text: str) -> str:
    from .advanced_engines import shellcode_encode
    return shellcode_encode(text)

# Public aliases for GUI import
decode_base91 = _decode_base91_wrapper
decode_base92 = _decode_base92_wrapper
decode_rot47 = rot47_decode
decode_shellcode = _decode_shellcode_wrapper
decode_brainfuck = _decode_bf_wrapper
decode_ook = _decode_ook_wrapper
decode_quoted_printable = _decode_qp_wrapper
decode_uuencode = _decode_uu_wrapper
decode_xxencode = _decode_xx_wrapper
decode_utf7 = _decode_utf7_wrapper
decode_punycode = _decode_punycode_wrapper

DECODERS = {
    "base64":    (decode_base64,    _encode_base64),
    "base64url": (decode_base64url, _encode_base64url),
    "base32":    (decode_base32,    _encode_base32),
    "base16":    (decode_base16,    _encode_base16),
    "base58":    (decode_base58,    _encode_base58),
    "base85":    (decode_base85,    _encode_base85),
    "base91":    (_decode_base91_wrapper, _decode_base91_wrapper),
    "base92":    (_decode_base92_wrapper, _decode_base92_wrapper),
    "url":       (decode_url,       _encode_url),
    "html":      (decode_html,      _encode_html),
    "rot13":     (decode_rot13,     decode_rot13),
    "rot47":     (rot47_decode,     _encode_rot47),
    "binary":    (decode_binary,    _encode_binary),
    "octal":     (decode_octal,     _encode_octal),
    "decimal":   (decode_decimal,   _encode_decimal),
    "unicode":   (decode_unicode_escape, _encode_unicode_escape),
    "morse":     (decode_morse,     _encode_morse),
    "shellcode": (_decode_shellcode_wrapper, _encode_shellcode),
    "brainfuck": (_decode_bf_wrapper, _decode_bf_wrapper),
    "ook":       (_decode_ook_wrapper, _decode_ook_wrapper),
    "quoted_printable": (_decode_qp_wrapper, _decode_qp_wrapper),
    "uuencode":  (_decode_uu_wrapper, _decode_uu_wrapper),
    "xxencode":  (_decode_xx_wrapper, _decode_xx_wrapper),
    "utf7":      (_decode_utf7_wrapper, _decode_utf7_wrapper),
    "punycode":  (_decode_punycode_wrapper, _decode_punycode_wrapper),
}


# ═══════════════════════════════════════════════════════════
#  链式解码
# ═══════════════════════════════════════════════════════════

def chain_decode(text: str, max_depth: int = 10) -> List[Tuple[str, str, str]]:
    """自动检测并链式解码. 返回: [(编码ID, 编码描述, 解码结果), ...]."""
    chain = []
    current = text.strip()
    seen = {current}

    for _ in range(max_depth):
        detections = detect_encoding(current)
        if not detections:
            break

        enc_id, enc_desc, confidence = detections[0]
        if confidence < 50:
            break

        decoder = DECODERS.get(enc_id, (None, None))[0]
        try:
            decoded = decoder(current)
        except Exception:
            if len(detections) > 1:
                enc_id, enc_desc, _ = detections[1]
                decoder = DECODERS.get(enc_id, (None, None))[0]
                try:
                    decoded = decoder(current)
                except Exception:
                    break
            else:
                break

        if not decoded or decoded == current:
            break
        if decoded in seen:
            break
        seen.add(decoded)

        chain.append((enc_id, enc_desc, decoded))
        current = decoded

        if is_printable(current) and not detect_encoding(current):
            break
        # Extra stop check: if result looks like a flag or plain text, stop
        if is_printable(current) and len(current) < 200:
            text_chars = sum(1 for c in current if c.isalpha() or c in "{}_-. :/=?!@#$%^&*()")
            if text_chars / max(len(current), 1) > 0.85:
                # Looks like plaintext/flag, check if we should stop
                detections = detect_encoding(current)
                if not detections or detections[0][2] < 75:
                    break

    return chain


def brute_decode(text: str) -> List[Tuple[str, str, str, str]]:
    """尝试所有解码器, 返回所有能产生可打印结果的分支."""
    enc_desc_map = {enc_id: desc for enc_id, desc, _ in ENCODING_DETECTORS}
    results = []
    for enc_id, (decoder, _) in DECODERS.items():
        try:
            decoded = decoder(text.strip())
            if decoded and decoded != text.strip() and len(decoded) >= 2:
                readable = "✓ 可读" if is_printable(decoded) else "✗ 不可读"
                results.append((enc_id, enc_desc_map.get(enc_id, enc_id), decoded, readable))
        except Exception:
            pass
    return sorted(results, key=lambda x: "✓" in x[3], reverse=True)
