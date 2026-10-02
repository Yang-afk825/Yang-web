"""yang_web.core.advanced_engines 子模块 _base9192（自 advanced_engines.py 拆分，请勿手工重排）。"""

import re
import base64
import codecs
import struct
from typing import Optional, Tuple




# ═══════════════════════════════════════════
# 8. Base91 编解码
# ═══════════════════════════════════════════

_B91_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'


def base91_encode(text: str) -> str:
    """Encode text to Base91."""
    data = text.encode('utf-8')
    result = []
    b = 0
    n = 0
    for byte in data:
        b |= byte << n
        n += 8
        if n > 13:
            v = b & 8191
            if v > 88:
                b >>= 13
                n -= 13
            else:
                v = b & 16383
                b >>= 14
                n -= 14
            result.append(_B91_ALPHABET[v % 91])
            result.append(_B91_ALPHABET[v // 91])
    if n:
        result.append(_B91_ALPHABET[b % 91])
        if n > 7 or b > 90:
            result.append(_B91_ALPHABET[b // 91])
    return ''.join(result)


def base91_decode(cipher: str) -> str:
    """Decode Base91 text.

    收尾必须是 ``b | (v << n)``：``b`` 存低 ``n`` 位，``v`` 续在高位。
    此前误写成 ``v | (b << n)``（位序颠倒），只有「末组只剩单字符」
    即编码串长度为奇数时才暴露：``HELLO`` -> ``HELL\\x80``、
    ``flag{test}`` -> ``flag{testA``。偶数长度恰好掩盖了它。
    """
    result = bytearray()
    b = 0
    n = 0
    v = -1
    for c in cipher:
        if c not in _B91_ALPHABET:
            continue
        dv = _B91_ALPHABET.index(c)
        if v < 0:
            v = dv
            continue
        v += dv * 91
        b |= v << n
        n += 13 if (v & 8191) > 88 else 14
        while n >= 8:
            result.append(b & 255)
            b >>= 8
            n -= 8
        v = -1
    if v >= 0:
        result.append((b | (v << n)) & 255)
    return bytes(result).decode('utf-8', errors='replace')


# ═══════════════════════════════════════════
# 9. Base92 编解码
# ═══════════════════════════════════════════

_B92_ALPHABET = "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_abcdefghijklmnopqrstuvwxyz{|}"


def base92_encode(text: str) -> str:
    """Encode text to Base92.

    与权威实现（base92 2.x，字母表 = ``'!' + '#'..'_' + 'a'..'}'``）逐位对齐：
    每 13 bit 出两个字符（``chr(v // 91) + chr(v % 91)``）；
    尾部余 bit ＜ 7 补到 6 bit 出 1 字符，≥ 7 补到 13 bit 出 2 字符；
    空串编码为 ``'~'``。

    旧实现尾部用「模 92」分组、且解码用 ``value * 92 + idx`` 递推，
    与分组规则不自洽 —— 任何输入都解不回来（``HELLO`` -> ``'\\x00'``）。
    """
    data = text.encode('utf-8')
    if not data:
        return '~'
    out = []
    buf = 0
    cnt = 0
    for byte in data:
        buf = (buf << 8) | byte
        cnt += 8
        while cnt >= 13:
            chunk = buf >> (cnt - 13)
            buf &= (1 << (cnt - 13)) - 1
            cnt -= 13
            out.append(_B92_ALPHABET[chunk // 91])
            out.append(_B92_ALPHABET[chunk % 91])
    if cnt:
        if cnt < 7:
            # 补到 6 bit；补零后必 < 64 < 91，可直接作下标
            out.append(_B92_ALPHABET[buf << (6 - cnt)])
        else:
            chunk = buf << (13 - cnt)
            out.append(_B92_ALPHABET[chunk // 91])
            out.append(_B92_ALPHABET[chunk % 91])
    return ''.join(out)


def base92_decode(cipher: str) -> str:
    """Decode Base92 text.

    容错策略与原实现保持一致：忽略字母表外字符（解码链会喂进各种噪声），
    长度不足两个有效字符时返回空串而不是抛异常。
    """
    valid = [c for c in cipher if c in _B92_ALPHABET]
    if not valid or len(valid) < 2:
        return ''
    buf = 0
    cnt = 0
    result = bytearray()
    total = len(valid)
    i = 0
    # 成对取 13 bit；末位为奇数字符时按 6 bit 处理
    while i < total - 1:
        chunk = _B92_ALPHABET.index(valid[i]) * 91 + _B92_ALPHABET.index(valid[i + 1])
        if chunk >= 8192:
            raise ValueError('非法的 Base92 编码：13 bit 分组越界')
        buf = (buf << 13) | chunk
        cnt += 13
        while cnt >= 8:
            result.append(buf >> (cnt - 8))
            buf &= (1 << (cnt - 8)) - 1
            cnt -= 8
        i += 2
    if i < total:
        buf = (buf << 6) | _B92_ALPHABET.index(valid[i])
        cnt += 6
        # 编码侧做了零填充，任何残余 bit 都是填充位，可以直接丢弃
        while cnt >= 8:
            result.append(buf >> (cnt - 8))
            buf &= (1 << (cnt - 8)) - 1
            cnt -= 8
    return bytes(result).decode('utf-8', errors='replace')
