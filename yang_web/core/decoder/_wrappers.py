"""yang_web.core.decoder 子模块 _wrappers（自 decoder.py 拆分，请勿手工重排）。"""

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
    from ..advanced_engines import shellcode_encode
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
