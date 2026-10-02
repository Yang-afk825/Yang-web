"""yang_web.core.decoder 子模块 _registry（自 decoder.py 拆分，请勿手工重排）。"""

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

from ._codec_base import (decode_base16, decode_base32, decode_base58, decode_base64, decode_base64url, decode_base85)
from ._codec_text import (decode_binary, decode_decimal, decode_html, decode_morse, decode_octal, decode_rot13, decode_unicode_escape, decode_url)
from ._det_base import (_is_base16, _is_base32, _is_base58, _is_base64, _is_base64_urlsafe, _is_base85, _is_base91, _is_base92)
from ._det_special import (_is_bear, _is_beast, _is_brainfuck, _is_buddha, _is_core_values, _is_ook, _is_punycode, _is_quoted_printable, _is_shellcode, _is_surnames, _is_telegraph, _is_utf7, _is_uuencode, _is_xxencode)
from ._det_text import (_is_binary, _is_decimal, _is_html_entity, _is_morse, _is_octal, _is_rot13, _is_rot47, _is_unicode_escape, _is_url_encoded)
from ._encoders import (_encode_base16, _encode_base32, _encode_base58, _encode_base64, _encode_base64url, _encode_base85, _encode_binary, _encode_decimal, _encode_html, _encode_morse, _encode_octal, _encode_unicode_escape, _encode_url)
from ._wrappers import (_decode_base91_wrapper, _decode_base92_wrapper, _decode_bf_wrapper, _decode_ook_wrapper, _decode_punycode_wrapper, _decode_qp_wrapper, _decode_shellcode_wrapper, _decode_utf7_wrapper, _decode_uu_wrapper, _decode_xx_wrapper, _encode_rot47, _encode_shellcode)


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
    ("base64",     "Base64",               _is_base64),
    ("base64url",  "Base64 URL-safe",      _is_base64_urlsafe),
    ("base85",     "Base85 / ASCII85",     _is_base85),
    # base58 的判据最弱(仅字符集匹配，且其字母表是 base64 的子集)，
    # 与 base64 同分时必须让位，故注册在 base64 之后。
    ("base58",     "Base58 (Bitcoin)",     _is_base58),
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
    ("buddha",     "与佛论禅",             _is_buddha),
    ("core_values","核心价值观",           _is_core_values),
    ("beast",      "兽音",                 _is_beast),
    ("bear",       "熊曰",                 _is_bear),
    ("surnames",   "百家姓",              _is_surnames),
    ("telegraph",  "中文电码",             _is_telegraph),
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
    "buddha":    (_decode_buddha, _decode_buddha),
    "core_values": (core_values_decode, core_values_decode),
    "beast":     (beast_decode, beast_decode),
    "bear":      (bear_decode, bear_decode),
    "surnames":  (surnames_decode, surnames_decode),
    "telegraph": (telegraph_decode, telegraph_decode),
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
        # 质量回退保护：链式解码已产出可读结果后，若下一步解码反而让可读性下降
        # （典型情形是把已解出的明文又误判成 base91/base92 等编码、再解成乱码），
        # 则丢弃该步并终止。首步不启用——base58 等类型的解码产物本就是二进制，
        # 不应因此被吞掉。
        if chain and text_quality(decoded) < text_quality(current):
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
