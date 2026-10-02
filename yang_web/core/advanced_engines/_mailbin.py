"""yang_web.core.advanced_engines 子模块 _mailbin（自 advanced_engines.py 拆分，请勿手工重排）。"""

import re
import base64
import codecs
import struct
from typing import Optional, Tuple




# ═══════════════════════════════════════════
# 3. Quoted-Printable
# ═══════════════════════════════════════════

# RFC 2047 的 Q 编码字 `=?charset?Q?...?=` —— 只有在这种上下文里 '_' 才代表空格。
_RFC2047_QWORD_RE = re.compile(r'=\?[^?]+\?[Qq]\?([^?]*)\?=')


def quoted_printable_encode(text: str) -> str:
    """Encode text to Quoted-Printable format (pure Python).

    可打印 ASCII 原样保留，其余（含空格，0x20 < 33）一律写成 ``=XX``。

    此前把空格编成 ``'_'`` —— 那是 RFC 2047 Q-word 的约定，而解码侧并不还原，
    于是 ``' '`` -> ``'_'`` 单向丢失、``'a b'`` 解回来变 ``'a_b'``，往返不成立。
    现在编码端统一走 ``=20``；解码端只在 ``=?charset?Q?...?=`` 这种确凿的
    Q-word 上下文里才把 ``'_'`` 视作空格，普通字符串中的下划线不受影响。
    """
    data = text.encode('utf-8')
    result = []
    for byte in data:
        if byte < 33 or byte > 126 or byte == 61:   # 61 = '='
            result.append(f'={byte:02X}')
        else:
            result.append(chr(byte))
    return ''.join(result)


def quoted_printable_decode(cipher: str) -> str:
    """Decode Quoted-Printable text (pure Python, no quopri)."""
    s = cipher.strip()

    # 先还原 RFC 2047 Q-word 里的 '_'（空格），再做 =XX 解码
    if '=?' in s:
        s = _RFC2047_QWORD_RE.sub(lambda m: m.group(1).replace('_', ' '), s)

    result = bytearray()
    i = 0
    n = len(s)
    while i < n:
        c = s[i]
        if c == '=' and i + 2 < n:
            hex_pair = s[i + 1:i + 3]
            if hex_pair in ('\r\n', '\n'):
                i += 2 if hex_pair == '\n' else 3   # 软换行，跳过
                continue
            try:
                result.append(int(hex_pair, 16))
                i += 3
                continue
            except ValueError:
                pass
        # 非 =XX 的内容按 UTF-8 原样写入（cipher 可能含中文，
        # 旧实现用 ord(c) 会 >255 并让 bytearray 直接抛 ValueError）
        result.extend(c.encode('utf-8'))
        i += 1

    return bytes(result).decode('utf-8', errors='replace')


# ═══════════════════════════════════════════
# 4. UUEncode
# ═══════════════════════════════════════════

UU_LINE_LEN = 45


def _uu_group(triple: bytes) -> str:
    """3 字节 -> 4 个 uuencode 字符（每个 6 bit + 32；0 写成反引号）。"""
    out = []
    for v in (triple[0] >> 2,
              ((triple[0] & 0x03) << 4) | (triple[1] >> 4),
              ((triple[1] & 0x0F) << 2) | (triple[2] >> 6),
              triple[2] & 0x3F):
        out.append('`' if v == 0 else chr(v + 32))
    return ''.join(out)


def uuencode(text: str) -> str:
    """Encode text to UUEncode format.

    真正的 uuencode：每 45 字节一行，行首是 ``chr(32 + 本行字节数)``，
    每 3 字节展开成 4 个 ``chr(32 + v)``（v=0 记作反引号），
    末行为单个反引号，外面套 ``begin 644 <name>`` / ``end`` 信封。

    旧实现直接套 base64（``base64.b64encode``）—— 与标准 uuencode 不兼容，
    外部工具产生的 uuencoded 数据一律解不开。
    """
    data = text.encode('utf-8')
    lines = ['begin 644 data']
    for i in range(0, len(data), UU_LINE_LEN):
        chunk = data[i:i + UU_LINE_LEN]
        body = ''.join(_uu_group(chunk[j:j + 3].ljust(3, b'\x00'))
                       for j in range(0, len(chunk), 3))
        lines.append(chr(32 + len(chunk)) + body)
    lines.append('`')
    lines.append('end')
    return '\n'.join(lines)


def uudecode(cipher: str) -> str:
    """Decode UUEncode text（兼容带/不带 begin-end 信封、以及 CRLF）。"""
    result = bytearray()
    for raw in cipher.splitlines():
        line = raw.rstrip('\r\n')
        if not line:
            continue
        lowered = line.lower()
        if lowered.startswith('begin ') or lowered.startswith('end'):
            continue
        head = ord(line[0])
        if head == 0x60 or head == 0x20:      # 长度为 0 的结束行
            continue
        count = (head - 32) & 0x3F
        if count == 0 or count > UU_LINE_LEN:
            continue
        line_bytes = bytearray()
        for ch in line[1:]:
            o = ord(ch)
            value = 0 if o == 0x60 else (o - 32) & 0x3F
            line_bytes.append(value)
        while len(line_bytes) % 4:
            line_bytes.append(0)
        decoded = bytearray()
        for j in range(0, len(line_bytes), 4):
            v = line_bytes[j:j + 4]
            decoded.append((v[0] << 2) | (v[1] >> 4))
            decoded.append(((v[1] & 0x0F) << 4) | (v[2] >> 2))
            decoded.append(((v[2] & 0x03) << 6) | v[3])
        result.extend(decoded[:count])
    return bytes(result).decode('utf-8', errors='replace')


# ═══════════════════════════════════════════
# 5. XXEncode
# ═══════════════════════════════════════════

XXENCODE_ALPHABET = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def xxencode(text: str) -> str:
    """Encode text to XXEncode format.

    与 uuencode 同构，只是把 6 bit 值映射到 XXEncode 专用字母表。
    行首仍是 ``chr(32 + 本行字节数)``，末字符为 ``+``（字母表里的 0）。
    """
    data = text.encode('utf-8')
    lines = ['begin 644 data']
    for i in range(0, len(data), UU_LINE_LEN):
        chunk = data[i:i + UU_LINE_LEN]
        chars = []
        for j in range(0, len(chunk), 3):
            triple = chunk[j:j + 3].ljust(3, b'\x00')
            chars.append(XXENCODE_ALPHABET[triple[0] >> 2])
            chars.append(XXENCODE_ALPHABET[((triple[0] & 0x03) << 4) | (triple[1] >> 4)])
            chars.append(XXENCODE_ALPHABET[((triple[1] & 0x0F) << 2) | (triple[2] >> 6)])
            chars.append(XXENCODE_ALPHABET[triple[2] & 0x3F])
        lines.append(chr(32 + len(chunk)) + ''.join(chars))
    lines.append('+')
    lines.append('end')
    return '\n'.join(lines)


def xxdecode(cipher: str) -> str:
    """Decode XXEncode text（兼容带/不带 begin-end 信封、以及 CRLF）。"""
    result = bytearray()
    for raw in cipher.splitlines():
        line = raw.rstrip('\r\n')
        if not line:
            continue
        lowered = line.lower()
        if lowered.startswith('begin ') or lowered.startswith('end'):
            continue
        head = ord(line[0])
        if head == 0x20:                      # 长度为 0 的结束行
            continue
        count = (head - 32) & 0x3F
        if count == 0 or count > UU_LINE_LEN:
            continue
        vals = []
        for ch in line[1:]:
            if ch in XXENCODE_ALPHABET:
                vals.append(XXENCODE_ALPHABET.index(ch))
        while len(vals) % 4:
            vals.append(0)
        decoded = bytearray()
        for j in range(0, len(vals), 4):
            v = vals[j:j + 4]
            decoded.append((v[0] << 2) | (v[1] >> 4))
            decoded.append(((v[1] & 0x0F) << 4) | (v[2] >> 2))
            decoded.append(((v[2] & 0x03) << 6) | v[3])
        result.extend(decoded[:count])
    return bytes(result).decode('utf-8', errors='replace')
