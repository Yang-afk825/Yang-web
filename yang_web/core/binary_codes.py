# -*- coding: utf-8 -*-
"""binary_codes.py — 进制编码 + 校验/工具（对照随波逐流 V8.0 补齐）

包含：
  - BCD 码 (8421) — 十进制数字 ↔ 4bit 二进制
  - 格雷码 (Gray code) — 二进制 ↔ 格雷码（相邻仅差 1bit）
  - 海明码 (Hamming 7,4) — 4bit 数据 + 3 校验位，含纠错
  - IEEE754 浮点 — hex ↔ float（单/双精度）
  - 时间戳 — Unix timestamp ↔ 日期
  - 质因数分解 — Pollard rho + Miller-Rabin

纯 Python 标准库零依赖，API 与 cipher_classic / cipher_keyed 一致。
"""
import datetime
import math
import random
import struct

# ═══════════════════════════════════════════
# 1. BCD 码（8421）
# ═══════════════════════════════════════════

def bcd_encode(text: str) -> str:
    digits = ''.join(c for c in text if c.isdigit())
    if not digits:
        return "[!] 请输入十进制数字串"
    return ' '.join(f'{int(d):04b}' for d in digits)


def bcd_decode(cipher: str) -> str:
    bits = ''.join(c for c in cipher if c in '01')
    out = []
    for i in range(0, len(bits) - 3, 4):
        v = int(bits[i:i + 4], 2)
        out.append(str(v) if v <= 9 else '?')
    return ''.join(out)


# ═══════════════════════════════════════════
# 2. 格雷码（Gray code）
# ═══════════════════════════════════════════

def gray_encode(text: str) -> str:
    bits = ''.join(c for c in text if c in '01')
    if not bits:
        return "[!] 请输入二进制串"
    gray = ''
    prev = '0'
    for b in bits:
        gray += '0' if b == prev else '1'
        prev = b
    return gray


def gray_decode(cipher: str) -> str:
    bits = ''.join(c for c in cipher if c in '01')
    binary = ''
    prev = '0'
    for g in bits:
        b = '0' if g == prev else '1'
        binary += b
        prev = b
    return binary


# ═══════════════════════════════════════════
# 3. 海明码（Hamming 7,4）
# ═══════════════════════════════════════════

def hamming_encode(text: str) -> str:
    bits = ''.join(c for c in text if c in '01')
    if not bits:
        return "[!] 请输入二进制串"
    while len(bits) % 4:
        bits += '0'
    out = []
    for i in range(0, len(bits), 4):
        d1, d2, d3, d4 = (int(x) for x in bits[i:i + 4])
        p1 = d1 ^ d2 ^ d4
        p2 = d1 ^ d3 ^ d4
        p4 = d2 ^ d3 ^ d4
        out.append(f'{p1}{p2}{d1}{p4}{d2}{d3}{d4}')
    return ' '.join(out)


def hamming_decode(cipher: str) -> str:
    bits = ''.join(c for c in cipher if c in '01')
    out = []
    for i in range(0, len(bits) - 6, 7):
        b = [int(x) for x in bits[i:i + 7]]
        s1 = b[0] ^ b[2] ^ b[4] ^ b[6]
        s2 = b[1] ^ b[2] ^ b[5] ^ b[6]
        s3 = b[3] ^ b[4] ^ b[5] ^ b[6]
        err = s1 + s2 * 2 + s3 * 4
        if err > 0:
            b[err - 1] ^= 1  # 纠错
        out.append(f'{b[2]}{b[4]}{b[5]}{b[6]}')
    return ''.join(out)


# ═══════════════════════════════════════════
# 4. IEEE754 浮点
# ═══════════════════════════════════════════

def ieee754_encode(text: str) -> str:
    try:
        f = float(text.strip())
    except Exception:
        return "[!] 请输入浮点数"
    return struct.pack('<f', f).hex()


def ieee754_decode(cipher: str) -> str:
    h = ''.join(c for c in cipher if c in '0123456789abcdefABCDEF')
    try:
        b = bytes.fromhex(h)
    except Exception:
        return "[!] 请输入 4 或 8 字节 hex"
    if len(b) == 4:
        return repr(struct.unpack('<f', b)[0])
    if len(b) == 8:
        return repr(struct.unpack('<d', b)[0])
    return "[!] 需要 4 字节（单精度）或 8 字节（双精度）hex"


# ═══════════════════════════════════════════
# 5. 时间戳
# ═══════════════════════════════════════════

def timestamp_encode(text: str) -> str:
    s = text.strip()
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%Y/%m/%d %H:%M:%S', '%Y/%m/%d'):
        try:
            dt = datetime.datetime.strptime(s, fmt)
            return str(int(dt.timestamp()))
        except ValueError:
            continue
    return "[!] 日期格式: YYYY-MM-DD HH:MM:SS"


def timestamp_decode(cipher: str) -> str:
    try:
        ts = int(float(cipher.strip()))
    except Exception:
        return "[!] 请输入 Unix 时间戳"
    try:
        dt = datetime.datetime.fromtimestamp(ts)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return "[!] 时间戳超出范围"


# ═══════════════════════════════════════════
# 6. 质因数分解
# ═══════════════════════════════════════════

def _is_prime(n: int) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _pollard_rho(n: int) -> int:
    if n % 2 == 0:
        return 2
    while True:
        c = random.randrange(1, n)
        f = lambda x: (x * x + c) % n
        x = y = 2
        d = 1
        while d == 1:
            x = f(x)
            y = f(f(y))
            d = math.gcd(abs(x - y), n)
        if d != n:
            return d


def _factor(n: int) -> list:
    if n == 1:
        return []
    if n % 2 == 0:
        return [2] + _factor(n // 2)
    if _is_prime(n):
        return [n]
    d = _pollard_rho(n)
    return _factor(d) + _factor(n // d)


def prime_factorize(text: str) -> str:
    try:
        n = int(str(text).strip())
    except Exception:
        return "[!] 请输入整数"
    if n < 2:
        return "[!] n 需 >= 2"
    if _is_prime(n):
        return f"{n} 是质数"
    factors = sorted(_factor(n))
    return ' × '.join(map(str, factors))


# ═══════════════════════════════════════════
# 注册表
# ═══════════════════════════════════════════

CIPHERS = {
    "bcd": {"name": "BCD码(8421)", "aliases": ["bcd", "8421", "bcd码"], "category": "进制编码"},
    "gray_code": {"name": "格雷码", "aliases": ["gray_code", "gray", "格雷码"], "category": "进制编码"},
    "hamming": {"name": "海明码(7,4)", "aliases": ["hamming", "海明码", "hamming74"], "category": "校验编码"},
    "ieee754": {"name": "IEEE754浮点", "aliases": ["ieee754", "float", "浮点"], "category": "进制编码"},
    "timestamp": {"name": "时间戳", "aliases": ["timestamp", "时间戳", "unix时间戳"], "category": "工具"},
    "prime_factor": {"name": "质因数分解", "aliases": ["prime_factor", "质因数分解", "factorize", "pollard"], "category": "工具"},
}

_FUNCS = {
    "bcd": (bcd_encode, bcd_decode),
    "gray_code": (gray_encode, gray_decode),
    "hamming": (hamming_encode, hamming_decode),
    "ieee754": (ieee754_encode, ieee754_decode),
    "timestamp": (timestamp_encode, timestamp_decode),
    "prime_factor": (prime_factorize, prime_factorize),
}


def _norm(cipher_id: str) -> str:
    cid = cipher_id.lower().replace('-', '_').replace(' ', '_')
    alias_map = {}
    for cid_key, info in CIPHERS.items():
        for a in info.get("aliases", []):
            alias_map[a.lower().replace('-', '_').replace(' ', '_')] = cid_key
    return alias_map.get(cid, cid)


def encode(cipher_id: str, text: str, key: str = "", **kwargs) -> str:
    cid = _norm(cipher_id)
    if cid in _FUNCS:
        return _FUNCS[cid][0](text)
    return f"[!] 不支持编码: {cipher_id}"


def decode(cipher_id: str, cipher_text: str, key: str = "", **kwargs) -> str:
    cid = _norm(cipher_id)
    if cid in _FUNCS:
        return _FUNCS[cid][1](cipher_text)
    return f"[!] 不支持解码: {cipher_id}"


def list_ciphers(category: str = None) -> list:
    result = []
    for cid, info in CIPHERS.items():
        if category and info.get("category") != category:
            continue
        result.append({"id": cid, **info})
    return result


def get_cipher(cipher_id: str) -> dict:
    return CIPHERS.get(_norm(cipher_id))


def search_ciphers(query: str) -> list:
    q = query.lower()
    out = []
    for cid, info in CIPHERS.items():
        text = cid + " " + info["name"] + " " + " ".join(info.get("aliases", [])) + " " + info["category"]
        if q in text.lower():
            out.append({"id": cid, **info})
    return out


def get_categories() -> list:
    return sorted({info["category"] for info in CIPHERS.values()})
