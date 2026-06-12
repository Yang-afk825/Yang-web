# -*- coding: utf-8 -*-
"""RSA 攻击工具箱 — 零依赖纯 Python 实现常见 RSA 攻击.

支持: 分解攻击 / 低加密指数 / 共模攻击 / Wiener / 广播攻击
"""

from __future__ import annotations
import math
import sys


# ═══ 基础工具 ═══

def egcd(a: int, b: int) -> tuple:
    """Extended GCD: returns (g, x, y) where ax + by = g = gcd(a,b)."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = egcd(b % a, a)
    return g, y1 - (b // a) * x1, x1


def modinv(a: int, m: int) -> int:
    """Modular inverse of a modulo m."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError(f"No inverse: gcd({a},{m})={g}")
    return x % m


def int_to_str(n: int) -> str:
    """Integer to string (big-endian)."""
    if n == 0:
        return ""
    return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode("latin-1", errors="replace")


def str_to_int(s: str) -> int:
    return int.from_bytes(s.encode("latin-1"), 'big')


def isqrt(n: int) -> int:
    """Integer square root."""
    if n < 0:
        raise ValueError("square root of negative")
    if n < 2:
        return n
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def iroot(n: int, k: int) -> int:
    """Integer k-th root floor."""
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


# ═══ 攻击方法 ═══

def rsa_decrypt(p: int, q: int, e: int, c: int) -> int:
    """Standard RSA decryption given p, q."""
    phi = (p - 1) * (q - 1)
    d = modinv(e, phi)
    return pow(c, d, p * q)


def attack_low_exponent(e: int, n: int, c: int, max_k: int = 100000) -> str | None:
    """Low encryption exponent attack (e=3)."""
    if e >= 7:
        print(f"  [warn] e={e} may not be small enough")
    for k in range(max_k):
        m_e = c + k * n
        m = iroot(m_e, e)
        if pow(m, e) == m_e:
            return int_to_str(m)
    return None


def attack_common_modulus(n: int, e1: int, e2: int, c1: int, c2: int) -> str | None:
    """Common modulus attack: same n, different e."""
    if math.gcd(e1, e2) != 1:
        print("  [warn] gcd(e1,e2)!=1, multiplying results")
        g, s1, s2 = egcd(e1, e2)
        # Not straightforward; skip for now
        return None

    g, s1, s2 = egcd(e1, e2)
    if s1 < 0:
        c1 = modinv(c1, n)
        s1 = -s1
    if s2 < 0:
        c2 = modinv(c2, n)
        s2 = -s2
    m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
    return int_to_str(m)


def attack_wiener(n: int, e: int) -> str | None:
    """Wiener attack: small private exponent d."""
    # Continued fraction expansion
    def cf_expand(num, den):
        cf = []
        while den:
            q = num // den
            cf.append(q)
            num, den = den, num - q * den
        return cf

    def cf_to_frac(cf):
        n0, n1 = cf[0], 1
        d0, d1 = 1, 0
        for q in cf[1:]:
            n0, n1 = q * n0 + n1, n0
            d0, d1 = q * d0 + d1, d0
            yield n0, d0

    cf = cf_expand(e, n)
    for k, d in cf_to_frac(cf):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # Check if n - phi + 1 is an integer
        s = n - phi + 1
        disc = s * s - 4 * n
        if disc < 0:
            continue
        root_disc = isqrt(disc)
        if root_disc * root_disc != disc:
            continue
        if (s + root_disc) % 2 == 0:
            p = (s + root_disc) // 2
            q = (s - root_disc) // 2
            if p * q == n:
                m = rsa_decrypt(p, q, e, None)
                return f"p={p}\nq={q}\nd={d}"
    return None


def attack_fermat(n: int) -> tuple | None:
    """Fermat factorization: p and q close."""
    a = isqrt(n)
    if a * a < n:
        a += 1
    max_iter = 1000000
    for _ in range(max_iter):
        b2 = a * a - n
        b = isqrt(b2)
        if b * b == b2:
            return a - b, a + b
        a += 1
    return None


def attack_broadcast(ciphertexts: list, moduli: list, e: int) -> str | None:
    """Hastad broadcast attack: same message, different n, same e."""
    if len(ciphertexts) < e:
        print(f"  [warn] need at least {e} ciphertexts, have {len(ciphertexts)}")
        return None

    # Chinese Remainder Theorem
    M = 1
    for n in moduli:
        M *= n

    x = 0
    for c, n in zip(ciphertexts, moduli):
        mi = M // n
        inv = modinv(mi, n)
        x = (x + c * mi * inv) % M

    m = iroot(x, e)
    if pow(m, e) == x:
        return int_to_str(m)
    return None


def attack_small_e_big_m(e: int, n: int, c: int, max_k: int = 1000) -> str | None:
    """Try to recover message when c = m^e mod n and m^e might be just over n."""
    for k in range(1, max_k + 1):
        m_e = c + k * n
        m = iroot(m_e, e)
        if pow(m, e) == m_e:
            return int_to_str(m)
    return None


def auto_rsa(n: int = 0, e: int = 0, c: int = 0,
             e1: int = 0, e2: int = 0, c1: int = 0, c2: int = 0,
             p: int = 0, q: int = 0,
             broadcast_cs: list = None, broadcast_ns: list = None,
             broadcast_e: int = 0) -> dict:
    """Auto-detect and run appropriate RSA attack."""
    results = {}

    # Standard decrypt if p,q known
    if p and q and e and (c or (c1 if not c else c)):
        _c = c or c1
        m = rsa_decrypt(p, q, e, _c)
        results["decrypt"] = int_to_str(m)

    # Common modulus
    if n and e1 and e2 and c1 and c2:
        results["common_modulus"] = attack_common_modulus(n, e1, e2, c1, c2)

    # Low exponent
    if e and n and (c or c1):
        _c = c or c1
        if e <= 5:
            results["low_exponent"] = attack_low_exponent(e, n, _c)

    # Wiener
    if n and e:
        results["wiener"] = attack_wiener(n, e)

    # Fermat
    if n:
        fermat = attack_fermat(n)
        if fermat:
            results["fermat"] = f"p={fermat[0]}\nq={fermat[1]}"

    # Broadcast
    if broadcast_cs and broadcast_ns:
        results["broadcast"] = attack_broadcast(broadcast_cs, broadcast_ns, broadcast_e or e)

    return results


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    print("RSA Attack Toolkit — yang_web")
    print("Usage:")
    print("  python rsa_toolkit.py --mode <mode> --n N --e E --c C")
    print()
    print("Modes: decrypt low_e common_mod wiener fermat broadcast")
    print("Example:")
    print("  python rsa_toolkit.py --mode low_e --n 123 --e 3 --c 456")

    if len(sys.argv) > 2:
        kwargs = {}
        i = 1
        while i < len(sys.argv):
            if sys.argv[i].startswith("--"):
                key = sys.argv[i][2:]
                val = int(sys.argv[i + 1]) if i + 1 < len(sys.argv) else None
                kwargs[key] = val
                i += 2
            else:
                i += 1

        results = auto_rsa(**kwargs)
        for k, v in results.items():
            print(f"\n[{k}] {v}")
