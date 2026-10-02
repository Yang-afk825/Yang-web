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

# 重导出全部原子符号，保持 `from yang_web.core.decoder import X` 契约不变
from ._det_base import (_is_base64, _is_base64_urlsafe, _is_base32, _is_base16, _is_base58, _is_base85, _is_base91, _is_base92)
from ._det_text import (_is_url_encoded, _is_html_entity, _is_rot13, _is_rot47, _is_binary, _is_octal, _is_decimal, _is_unicode_escape, _is_morse)
from ._det_special import (_is_buddha, _is_core_values, _is_beast, _is_bear, _is_surnames, _is_telegraph, _is_quoted_printable, _is_uuencode, _is_xxencode, _is_brainfuck, _is_ook, _is_utf7, _is_zerowidth, _is_punycode, _is_shellcode)
from ._codec_base import (decode_base64, decode_base64url, decode_base32, decode_base16, decode_base58, decode_base85)
from ._codec_text import (decode_url, decode_html, decode_rot13, decode_binary, decode_octal, decode_decimal, decode_unicode_escape, decode_morse)
from ._encoders import (_encode_base64, _encode_base64url, _encode_base32, _encode_base16, _encode_base58, _encode_base85, _encode_url, _encode_html, _encode_binary, _encode_octal, _encode_decimal, _encode_unicode_escape, _encode_morse)
from ._wrappers import (_decode_qp_wrapper, _decode_uu_wrapper, _decode_xx_wrapper, _decode_bf_wrapper, _decode_ook_wrapper, _decode_utf7_wrapper, _decode_punycode_wrapper, _decode_shellcode_wrapper, _decode_base91_wrapper, _decode_base92_wrapper, _encode_rot47, _encode_rot5, _encode_rot18, _encode_shellcode, decode_base91, decode_base92, decode_rot47, decode_shellcode, decode_brainfuck, decode_ook, decode_quoted_printable, decode_uuencode, decode_xxencode, decode_utf7, decode_punycode)
from ._registry import (ENCODING_DETECTORS, detect_encoding, DECODERS, chain_decode, brute_decode)
