"""yang_web.core.decoder 子模块 _det_base（自 decoder.py 拆分，请勿手工重排）。"""

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
    text = text.strip()
    # 过短的纯字母数字串多为普通单词 / ID，不足以判定为 base58。
    if len(text) < 6 or not all(c in charset for c in text):
        return 0
    # 纯 hex 串(0-9a-f)整体落在 base58 字母表内，会抢占 base16 的识别，
    # 故显式降分让位给 base16。
    if re.fullmatch(r"[0-9a-fA-F]+", text):
        return 40
    return 85

def _is_base85(text: str) -> int:
    charset = set(string.printable) - set("\t\n\r\x0b\x0c'\"\\")
    if not all(c in charset for c in text):
        return 0
    special = sum(1 for c in text if c in "~!@#$%^&*()_+-=[]|:;<>,.?/")
    if special > len(text) * 0.1:
        return 70
    return 30

def _is_base91(text: str) -> int:
    """Detect Base91 encoding."""
    charset = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"')
    text = text.strip()
    if not text:
        return 0
    match = sum(1 for c in text if c in charset)
    if match / len(text) <= 0.95:
        return 0
    # base91 产物的「非常见符号」占比显著高于自然文本。
    # 注意 { } _ . 在 flag / 明文 / 代码中极常见，不能计入判据，
    # 否则 "flag{test}" 这类明文会被误判为 base91 并继续解码成乱码。
    special = sum(1 for c in text if c in '!#$%&()*+,/:;<=>?@[]^`|~"')
    if len(text) >= 6 and special > len(text) * 0.15:
        return 80
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
    # 不再对普通可打印文本返回兜底分(原 55)，否则任意明文都会被判为 base92。
    return 0
