# -*- coding: utf-8 -*-
"""RSA 与现代密码学攻击引擎。

纯标准库实现，零第三方依赖。

本模块由 ``scripts/rsa_toolkit.py`` 上提而来：原先那份实现只能作为独立脚本
手动运行，既无法被自动解题编排调用，也无法被 CLI / GUI 复用。上提为引擎后，
``yang-web crypto`` 子命令、GUI 密码面板与解题分类器共用同一套实现。

覆盖的攻击：

===============  ==========================================
攻击              适用场景
===============  ==========================================
decrypt          已知 p、q（最常见：分解成功后）
low_exponent     低加密指数 e=3 且 m^e < n（无模约减）
common_modulus   同一 n，两组不同 e
wiener           私钥指数 d 过小
fermat           p、q 非常接近
broadcast        Håstad 广播：同一明文、多组不同 n
small_e          低指数 + 小范围 k 枚举
===============  ==========================================
"""

from __future__ import annotations

import math

__all__ = [
    # 基础工具
    "egcd", "modinv", "crt", "int_to_str", "str_to_int", "isqrt", "iroot",
    # 攻击
    "rsa_decrypt", "attack_low_exponent", "attack_common_modulus",
    "attack_wiener", "attack_fermat", "attack_broadcast", "attack_small_e",
    # 编排
    "solve_rsa", "solve_rsa_auto", "RSA_ATTACKS", "COMMON_EXPONENTS",
]


# ═══════════════════════════════════════════════════════════
#  基础工具
# ═══════════════════════════════════════════════════════════

def egcd(a: int, b: int) -> tuple:
    """扩展欧几里得：返回 (g, x, y) 满足 a*x + b*y = g = gcd(a, b)。"""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = egcd(b % a, a)
    return g, y1 - (b // a) * x1, x1


def modinv(a: int, m: int) -> int:
    """模逆元；不互素时抛 ValueError。"""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError(f"不存在模逆元: gcd({a}, {m}) = {g}")
    return x % m


def crt(residues: list, moduli: list) -> int:
    """中国剩余定理：求解 x ≡ residues[i] (mod moduli[i])，要求模数两两互素。"""
    total = 1
    for m in moduli:
        total *= m
    result = 0
    for r, m in zip(residues, moduli):
        partial = total // m
        result = (result + r * partial * modinv(partial % m, m)) % total
    return result


def int_to_str(n: int) -> str:
    """大整数按大端序还原为字节串（CTF 中密文→明文的约定做法）。"""
    if n <= 0:
        return ""
    return n.to_bytes((n.bit_length() + 7) // 8, "big").decode("latin-1", errors="replace")


def str_to_int(s: str) -> int:
    """字符串按大端序编码为大整数。"""
    return int.from_bytes(s.encode("latin-1"), "big")


def isqrt(n: int) -> int:
    """整数平方根（向下取整）。"""
    if n < 0:
        raise ValueError("负数没有平方根")
    if n < 2:
        return n
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def iroot(n: int, k: int) -> int:
    """整数 k 次方根（向下取整）。k 为偶数且 n 为负时返回 None。"""
    if n < 0:
        return -iroot(-n, k) if k % 2 else None
    if n < 2:
        return n
    low, high = 1, 1 << ((n.bit_length() + k - 1) // k)
    while low < high:
        mid = (low + high + 1) // 2
        if pow(mid, k) <= n:
            low = mid
        else:
            high = mid - 1
    return low


# ═══════════════════════════════════════════════════════════
#  攻击实现
# ═══════════════════════════════════════════════════════════

def rsa_decrypt(p: int, q: int, e: int, c: int) -> int:
    """已知 p、q 的标准 RSA 解密，返回明文整数。"""
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    return pow(c, d, p * q)


def attack_low_exponent(e: int, n: int, c: int, max_k: int = 100000) -> str | None:
    """低加密指数攻击：明文很小、m^e 未超过 n，直接开 e 次方。

    若 m^e >= n，则有 c = m^e - k*n，枚举 k 试探。
    """
    for k in range(max_k):
        m_e = c + k * n
        if m_e <= 0:
            continue
        m = iroot(m_e, e)
        if m and pow(m, e) == m_e:
            return int_to_str(m)
    return None


def attack_small_e(e: int, n: int, c: int, max_k: int = 100000) -> str | None:
    """与 low_exponent 同源，保留独立入口便于按题选择枚举上界。"""
    return attack_low_exponent(e, n, c, max_k=max_k)


def attack_common_modulus(n: int, e1: int, e2: int, c1: int, c2: int) -> str | None:
    """共模攻击：同一模数 n 下用两组互素的 (e, c) 恢复明文。

    要求 gcd(e1, e2) == 1，否则无法用扩展欧几里得的线性组合消去指数。
    """
    g, s1, s2 = egcd(e1, e2)
    if g != 1:
        return None
    if s1 < 0:
        c1 = modinv(c1, n)
        s1 = -s1
    if s2 < 0:
        c2 = modinv(c2, n)
        s2 = -s2
    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    return int_to_str(m)


def attack_wiener(n: int, e: int) -> dict | None:
    """Wiener 攻击：d 过小时用 e/n 的连分数逼近恢复 d，进而分解 n。

    返回 ``{"p": p, "q": q, "d": d}``；未命中返回 None。
    """
    def _cf_expand(num: int, den: int) -> list:
        cf = []
        while den:
            q = num // den
            cf.append(q)
            num, den = den, num - q * den
        return cf

    def _convergents(cf: list):
        n0, n1 = cf[0], 1
        d0, d1 = 1, 0
        for q in cf[1:]:
            n0, n1 = q * n0 + n1, n0
            d0, d1 = q * d0 + d1, d0
            yield n0, d0

    for k, d in _convergents(_cf_expand(e, n)):
        if k == 0 or d == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        root = isqrt(disc)
        if root * root != disc or (s + root) % 2:
            continue
        p = (s + root) // 2
        q = (s - root) // 2
        if p * q == n:
            return {"p": p, "q": q, "d": d}
    return None


def attack_fermat(n: int, max_iter: int = 1000000) -> tuple | None:
    """Fermat 分解：p、q 接近时，n = a^2 - b^2 很快能解出。返回 (p, q)。"""
    a = isqrt(n)
    if a * a < n:
        a += 1
    for _ in range(max_iter):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None


def attack_broadcast(ciphertexts: list, moduli: list, e: int) -> str | None:
    """Håstad 广播攻击：同一明文用 e 组不同模数加密，用 CRT 还原 m^e 后开方。"""
    if not ciphertexts or len(ciphertexts) < e:
        return None
    m_e = crt(ciphertexts, moduli)
    m = iroot(m_e, e)
    if m and pow(m, e) == m_e:
        return int_to_str(m)
    return None


#: 攻击名 → (说明, 需要的最小参数集)，供 CLI / 分类器枚举
RSA_ATTACKS = {
    "decrypt":         ("已知 p、q 直接解密",      ("p", "q", "e", "c")),
    "low_exponent":    ("低加密指数 e=3",          ("e", "n", "c")),
    "common_modulus":  ("共模攻击（同 n 不同 e）", ("n", "e1", "e2", "c1", "c2")),
    "wiener":          ("Wiener（小私钥 d）",      ("n", "e")),
    "fermat":          ("Fermat 分解（p≈q）",      ("n",)),
    "broadcast":       ("Håstad 广播攻击",         ("broadcast_cs", "broadcast_ns")),
}


def solve_rsa(n: int = 0, e: int = 0, c: int = 0,
              e1: int = 0, e2: int = 0, c1: int = 0, c2: int = 0,
              p: int = 0, q: int = 0,
              broadcast_cs: list = None, broadcast_ns: list = None,
              broadcast_e: int = 0) -> dict:
    """按已知参数自动尝试所有可行的 RSA 攻击。

    返回 ``{"results": {...}, "tried": [...], "success": bool}``：

    - ``results`` 只收录**命中**的攻击，键为攻击名；
    - ``tried`` 列出实际尝试过的攻击名 —— 空 ``results`` 时用它解释"为什么没结果"；
    - 已知 p、q 时额外给出 ``plaintext``。
    """
    results = {}
    tried = []

    def _record(name, value):
        tried.append(name)
        if value is not None:
            results[name] = value

    if p and q and e and (c or c1):
        _record("decrypt", int_to_str(rsa_decrypt(p, q, e, c or c1)))

    if n and e1 and e2 and c1 and c2:
        _record("common_modulus", attack_common_modulus(n, e1, e2, c1, c2))

    if n and e and (c or c1) and 0 < e <= 5:
        _record("low_exponent", attack_low_exponent(e, n, c or c1))

    if n and e:
        wiener = attack_wiener(n, e)
        _record("wiener", wiener)

    if n:
        fermat = attack_fermat(n)
        # 与其余攻击保持一致：无论命中与否都记入 tried，
        # 这样"为什么没结果"才能被完整解释。
        tried.append("fermat")
        if fermat:
            results["fermat"] = {"p": fermat[0], "q": fermat[1]}
            # 分解成功后顺手解出明文
            if e and (c or c1):
                results["plaintext"] = int_to_str(
                    rsa_decrypt(fermat[0], fermat[1], e, c or c1)
                )

    if broadcast_cs and broadcast_ns:
        _record("broadcast", attack_broadcast(broadcast_cs, broadcast_ns, broadcast_e or e))

    # 统一收口：把 message 类结果也暴露为 plaintext，方便调用方直接取
    if "plaintext" not in results:
        for key in ("decrypt", "low_exponent", "common_modulus", "broadcast"):
            if isinstance(results.get(key), str):
                results["plaintext"] = results[key]
                break

    return {
        "results": results,
        "tried": tried,
        "success": bool(results),
    }


#: 常见公钥指数，按经验频率排序。题目只给 n、c 而不给 e 时用它枚举。
COMMON_EXPONENTS = (65537, 3, 17, 5, 7)


def solve_rsa_auto(n: int = 0, e: int = 0, c: int = 0, **kwargs) -> dict:
    """``solve_rsa`` 的外层兜底：处理"e 未知"的常见题面。

    真实题目里 e 多为 3 或 65537，而题干只给 n、c 的情况并不少见。此时若把
    e 当 0 传进去，低指数攻击与 Wiener 都会失去入口，白白漏解；本函数改为
    依次代入常见指数重试，命中即返回。

    ``kwargs`` 原样透传给 :func:`solve_rsa`（p / q / e1 / e2 / c1 / c2 等）。
    """
    if not e and n and c:
        tried_all = []
        for candidate in COMMON_EXPONENTS:
            result = solve_rsa(n=n, e=candidate, c=c, **kwargs)
            if result["success"]:
                result["tried"] = [f"e={candidate} → {name}" for name in result["tried"]]
                return result
            tried_all.extend(f"e={candidate} → {name}" for name in result["tried"])
        # 全部落空：把尝试过哪些 e 摊开，便于判断是"e 不在常见集合里"还是"题本身无解"
        return {"results": {}, "tried": tried_all[:15], "success": False}

    return solve_rsa(n=n, e=e, c=c, **kwargs)
