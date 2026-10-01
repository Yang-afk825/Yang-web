# -*- coding: utf-8 -*-
"""RSA / 现代密码学攻击引擎（core.crypto_attack）回归测试。

每个攻击都构造一个**已知答案**的最小算例，既验证算法本身，也顺带锁住历史缺陷：

- ``attack_wiener`` 曾经调用 ``rsa_decrypt(p, q, e, None)`` 而抛 TypeError，
  现在必须返回 ``{"p", "q", "d"}``；
- ``solve_rsa_auto`` 必须能在 ``e`` 缺失时枚举常见公钥指数。
"""
import math
import os
import random
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from yang_web.core.crypto_attack import (  # noqa: E402
    COMMON_EXPONENTS, RSA_ATTACKS, attack_broadcast, attack_common_modulus,
    attack_fermat, attack_low_exponent, attack_wiener, crt, egcd, int_to_str,
    iroot, isqrt, modinv, rsa_decrypt, solve_rsa, solve_rsa_auto, str_to_int,
)


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
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits: int = 64) -> int:
    while True:
        cand = random.getrandbits(bits) | 1 | (1 << (bits - 1))
        if _is_prime(cand):
            return cand


class TestNumberTheory(unittest.TestCase):

    def test_egcd_identity(self):
        for a, b in ((240, 46), (17, 5), (1, 1), (100, 75)):
            g, x, y = egcd(a, b)
            self.assertEqual(g, math.gcd(a, b))
            self.assertEqual(a * x + b * y, g)

    def test_modinv(self):
        self.assertEqual(modinv(3, 11), 4)
        self.assertEqual((modinv(17, 3120) * 17) % 3120, 1)

    def test_modinv_raises_when_not_coprime(self):
        with self.assertRaises(ValueError):
            modinv(4, 8)

    def test_crt(self):
        residues, moduli = [2, 3, 2], [3, 5, 7]
        x = crt(residues, moduli)
        for r, m in zip(residues, moduli):
            self.assertEqual(x % m, r)
        self.assertEqual(x, 23)

    def test_isqrt_iroot(self):
        self.assertEqual(isqrt(0), 0)
        self.assertEqual(isqrt(15), 3)
        self.assertEqual(isqrt(16), 4)
        self.assertEqual(iroot(27, 3), 3)
        self.assertEqual(iroot(26, 3), 2)
        self.assertEqual(iroot(-27, 3), -3)
        self.assertIsNone(iroot(-16, 2))

    def test_int_str_roundtrip(self):
        for raw in (b"flag{test}", b"A", b"\x01\xff\x10"):
            with self.subTest(raw=raw):
                self.assertEqual(
                    int_to_str(str_to_int(raw.decode("latin-1"))).encode("latin-1"), raw)

    def test_leading_nul_bytes_are_not_preserved(self):
        """已知限制：整数转换带不出前导零字节，`\\x00\\xff` 会退化成 `\\xff`。"""
        self.assertEqual(int_to_str(str_to_int("\x00\xff")).encode("latin-1"), b"\xff")


class TestAttacks(unittest.TestCase):

    def test_rsa_decrypt_roundtrip(self):
        p, q, e = 1000003, 1000039, 65537
        n = p * q
        message = str_to_int("Hi")
        cipher = pow(message, e, n)
        self.assertEqual(int_to_str(rsa_decrypt(p, q, e, cipher)), "Hi")

    def test_low_exponent_without_modular_reduction(self):
        m = str_to_int("flag{low}")
        e = 3
        n = m ** e + 1          # 保证 m^e < n，无需枚举 k
        self.assertEqual(attack_low_exponent(e, n, m ** e), "flag{low}")

    def test_low_exponent_respects_k_budget(self):
        """k 的搜索上界应被尊重：k=0 不成立时预算不够就返回 None，而不是死循环。"""
        n, e, c = 100, 3, 7 ** 3 % 100      # 真正的 m^e 落在 k=3 处
        self.assertIsNone(attack_low_exponent(e, n, c, max_k=1))
        self.assertEqual(attack_low_exponent(e, n, c, max_k=5), "\x07")

    def test_fermat_factorisation(self):
        pair = attack_fermat(1000003 * 1000039)
        self.assertIsNotNone(pair)
        self.assertEqual(sorted(pair), [1000003, 1000039])

    def test_fermat_fails_on_distant_primes(self):
        self.assertIsNone(attack_fermat(3 * 1000000007, max_iter=10))

    def test_wiener_returns_params_not_crash(self):
        """回归：旧实现传 None 给 rsa_decrypt 会 TypeError。"""
        p, q, d = 1009, 1013, 5
        n = p * q
        phi = (p - 1) * (q - 1)
        self.assertEqual(math.gcd(d, phi), 1)
        e = modinv(d, phi)
        hit = attack_wiener(n, e)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["d"], d)
        self.assertEqual(sorted((hit["p"], hit["q"])), sorted((p, q)))

    def test_wiener_misses_normal_key(self):
        p, q, e = 1000003, 1000039, 65537
        self.assertIsNone(attack_wiener(p * q, e))

    def test_common_modulus(self):
        p, q = 1000003, 1000039
        n = p * q
        m = str_to_int("Hi")
        e1, e2 = 7, 11
        self.assertEqual(math.gcd(e1, e2), 1)
        plain = attack_common_modulus(n, e1, e2, pow(m, e1, n), pow(m, e2, n))
        self.assertEqual(plain, "Hi")

    def test_common_modulus_requires_coprime_exponents(self):
        self.assertIsNone(attack_common_modulus(1000003 * 1000039, 4, 6, 1, 1))

    def test_broadcast(self):
        random.seed(20261001)
        m = str_to_int("flag{broadcast_ok}")
        e = 3
        while True:
            n = _prime(320) * _prime(320)
            if n > m ** e:
                break
        ns, cs = [], []
        while len(ns) < e:
            candidate = _prime(320) * _prime(320)
            if candidate > m ** e and candidate not in ns:
                ns.append(candidate)
                cs.append(pow(m, e, candidate))
        self.assertEqual(attack_broadcast(cs, ns, e), "flag{broadcast_ok}")

    def test_broadcast_rejects_insufficient_input(self):
        self.assertIsNone(attack_broadcast([1, 2], [3, 5], 3))


class TestOrchestration(unittest.TestCase):

    def test_solve_rsa_records_tried_when_no_hit(self):
        """选一对相距很远的素数 —— Fermat / Wiener 都不该命中。"""
        r = solve_rsa(n=3 * 1000000007, e=65537)
        self.assertIn("wiener", r["tried"])
        self.assertIn("fermat", r["tried"])
        self.assertFalse(r["success"])

    def test_solve_rsa_success_is_true_when_only_factored(self):
        """分解成功但没给密文时，"success" 表示"有产出"，不含明文。"""
        r = solve_rsa(n=1000003 * 1000039, e=65537)
        self.assertTrue(r["success"])
        self.assertIn("fermat", r["results"])
        self.assertNotIn("plaintext", r["results"])

    def test_solve_rsa_exposes_plaintext_alias(self):
        p, q, e = 1000003, 1000039, 65537
        n = p * q
        m = str_to_int("Hi")
        r = solve_rsa(p=p, q=q, e=e, c=pow(m, e, n))
        self.assertTrue(r["success"])
        self.assertEqual(r["results"]["plaintext"], "Hi")

    def test_solve_rsa_fermat_then_plaintext(self):
        """Fermat 分解成功后应顺手解出明文。"""
        p, q, e = 1000003, 1000039, 65537
        n = p * q
        m = str_to_int("Hi")
        r = solve_rsa(n=n, e=e, c=pow(m, e, n), p=0, q=0)
        self.assertIn("fermat", r["results"])
        self.assertEqual(r["results"].get("plaintext"), "Hi")

    def test_solve_rsa_auto_enumerates_unknown_e(self):
        m = str_to_int("flag{no_e}")
        e = 3
        n = m ** e + 1
        r = solve_rsa_auto(n=n, c=m ** e)     # 故意不给 e
        self.assertTrue(r["success"])
        self.assertEqual(r["results"]["plaintext"], "flag{no_e}")
        self.assertTrue(all("e=" in t for t in r["tried"]))

    def test_solve_rsa_auto_keeps_known_e(self):
        p, q, e = 1000003, 1000039, 65537
        m = str_to_int("Hi")
        r = solve_rsa_auto(p=p, q=q, e=e, c=pow(m, e, p * q))
        self.assertEqual(r["results"]["plaintext"], "Hi")
        self.assertNotIn("e=", r["tried"][0])

    def test_common_exponents_have_expected_members(self):
        self.assertIn(65537, COMMON_EXPONENTS)
        self.assertIn(3, COMMON_EXPONENTS)

    def test_rsa_attacks_catalogue_shape(self):
        for name, (desc, need) in RSA_ATTACKS.items():
            with self.subTest(name=name):
                self.assertTrue(desc)
                self.assertTrue(need)


if __name__ == "__main__":
    unittest.main(verbosity=2)
