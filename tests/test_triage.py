# -*- coding: utf-8 -*-
"""题型识别（core.triage）回归测试。

覆盖两类容易退化的地方：

1. **分类正确性** —— 各类输入落到预期的 ``kind``；
2. **RSA 参数解析** —— ``e`` 常是个位数（3 / 65537），不能因为"只认 20 位以上
   大整数"而漏掉；生成的可执行命令也不能把 ``c`` 误标成 ``e``。
"""
import os
import sys
import tempfile
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from yang_web.core.triage import (  # noqa: E402
    identify_bytes, parse_rsa_params, triage,
)

#: 一个可用的 RSA 题面：m = b"flag{test}"，e = 3，c = m^3，n = m^3 + 1
_M = int.from_bytes(b"flag{test}", "big")
_RSA_N = _M ** 3 + 1
_RSA_C = _M ** 3


class TestClassification(unittest.TestCase):
    """输入 → 题型 的基本映射。"""

    def test_flag_is_plaintext(self):
        self.assertEqual(triage(text="flag{hello_world}")["kind"], "plaintext")

    def test_url(self):
        self.assertEqual(triage(text="http://target.ctf.com/api")["kind"], "url")

    def test_md5_is_hash(self):
        r = triage(text="5d41402abc4b2a76b9719d911017c592")
        self.assertEqual(r["kind"], "hash")
        self.assertIn("MD5", r["evidence"])

    def test_sha256_is_hash(self):
        digest = "a" * 64
        r = triage(text=digest)
        self.assertEqual(r["kind"], "hash")
        self.assertIn("SHA256", r["evidence"])

    def test_base64_is_encoded(self):
        self.assertEqual(triage(text="ZmxhZ3t0ZXN0fQ==")["kind"], "encoded")

    def test_url_encoded_is_encoded(self):
        self.assertEqual(triage(text="%66%6c%61%67")["kind"], "encoded")

    def test_long_real_encodings_still_detected(self):
        """加了下限之后，真实编码串仍必须被识别出来。"""
        cases = {
            "ZmxhZ3t0ZXN0fQ==": "encoded",       # base64 85
            "aGVsbG8gd29ybGQ=": "encoded",       # base64 85
            "68656c6c6f": "encoded",             # hex 75
            "MZWGCZ33ORSXG5D5": "encoded",       # base32 90
            "%68%65%6c%6c%6f": "encoded",        # url 90
        }
        for payload, expected in cases.items():
            with self.subTest(payload=payload):
                self.assertEqual(triage(text=payload)["kind"], expected)

    def test_plain_english_is_not_encoded(self):
        """rot13 / rot47 对任何字母文本都给兜底分，普通英文不该被判成编码题。"""
        for plain in ("hello world", "just some plain text"):
            with self.subTest(plain=plain):
                self.assertNotEqual(triage(text=plain)["kind"], "encoded")

    def test_empty_input_is_unknown(self):
        self.assertEqual(triage(text="   ")["kind"], "unknown")

    def test_confidence_is_bounded(self):
        for payload in ("flag{x}", "http://a.b/c", "ZmxhZ3t0ZXN0fQ==", "deadbeef"):
            conf = triage(text=payload)["confidence"]
            self.assertGreaterEqual(conf, 0)
            self.assertLessEqual(conf, 100)


class TestRsaParsing(unittest.TestCase):
    """RSA 参数解析 —— 本模块最易回归的部分。"""

    def test_labeled_with_small_e(self):
        """e 只有个位数时也必须正确归位（曾被 20 位大整数规则漏掉）。"""
        text = f"n = {_RSA_N}\ne = 3\nc = {_RSA_C}"
        params = parse_rsa_params(text)
        self.assertEqual(params.get("n"), _RSA_N)
        self.assertEqual(params.get("e"), 3)
        self.assertEqual(params.get("c"), _RSA_C)

    def test_colon_separator_and_no_spaces(self):
        text = f"n:{_RSA_N};e:65537;c:{_RSA_C}"
        params = parse_rsa_params(text)
        self.assertEqual(params.get("n"), _RSA_N)
        self.assertEqual(params.get("e"), 65537)

    def test_triage_detects_rsa_with_small_e(self):
        r = triage(text=f"n = {_RSA_N}\ne = 3\nc = {_RSA_C}")
        self.assertEqual(r["kind"], "rsa")
        self.assertEqual(r["confidence"], 90)

    def test_generated_command_does_not_mislabel_c_as_e(self):
        """生成的命令必须含 --n/--e/--c 三个标签，且 e 不可能是那个大整数。"""
        r = triage(text=f"n = {_RSA_N}\ne = 3\nc = {_RSA_C}")
        cmd = r["paths"][0]["cmd"]
        self.assertIn("--n ", cmd)
        self.assertIn("--e 3", cmd)
        self.assertIn(f"--c {_RSA_C}", cmd)
        self.assertNotIn(f"--e {_RSA_N}", cmd)

    def test_bare_bigints_fallback(self):
        """无标签、全是大整数时退回 n / e / c 顺序。"""
        big_e = 10 ** 19 + 3          # 需 20 位以上才会被裸大整数规则捕获
        params = parse_rsa_params(f"{_RSA_N}\n{big_e}\n{_RSA_C}")
        self.assertEqual(params.get("n"), _RSA_N)
        self.assertEqual(params.get("e"), big_e)
        self.assertEqual(params.get("c"), _RSA_C)

    def test_bare_small_e_is_not_recoverable(self):
        """已知限制：裸数字串里 5 位的 e 无法与 n/c 区分，只能留给引擎枚举。"""
        params = parse_rsa_params(f"{_RSA_N}\n65537\n{_RSA_C}")
        self.assertEqual(params.get("n"), _RSA_N)
        self.assertEqual(params.get("c"), _RSA_C)
        self.assertNotIn("e", params)

    def test_bare_n_and_c_without_e(self):
        """只有两个大整数时按 n、c 解释，并把 e 留给调用方枚举。"""
        params = parse_rsa_params(f"{_RSA_N}\n{_RSA_C}")
        self.assertEqual(params.get("n"), _RSA_N)
        self.assertEqual(params.get("c"), _RSA_C)
        self.assertNotIn("e", params)

    def test_common_modulus_pair(self):
        text = f"n = {_RSA_N}\ne1 = 7\ne2 = 11\nc1 = {_RSA_C}\nc2 = {_RSA_C}"
        params = parse_rsa_params(text)
        self.assertEqual(params.get("e1"), 7)
        self.assertEqual(params.get("e2"), 11)
        # 统一入口需要一个 c
        self.assertEqual(params.get("c"), _RSA_C)

    def test_prose_is_not_rsa(self):
        """散文里的 "n = 1" 之类不该被判成 RSA。"""
        self.assertEqual(parse_rsa_params("n = 1\ne = 2\nc = 3"), {})
        self.assertEqual(triage(text="n = 1\ne = 2\nc = 3")["kind"], "text")

    def test_plain_text_no_params(self):
        self.assertEqual(parse_rsa_params("hello world, no numbers here"), {})


class TestMagicBytes(unittest.TestCase):
    """文件魔数识别。"""

    def test_known_magics(self):
        cases = [
            (b"PK\x03\x04rest", "zip"),
            (b"\x89PNG\r\n\x1a\nrest", "png"),
            (b"\xff\xd8\xffrest", "jpeg"),
            (b"\x7fELFrest", "elf"),
            (b"MZrest", "pe"),
            (b"%PDF-1.4 rest", "pdf"),
            (b"\x1f\x8brest", "gzip"),
        ]
        for blob, expected in cases:
            with self.subTest(expected=expected):
                hit = identify_bytes(blob)
                self.assertIsNotNone(hit)
                self.assertEqual(hit["kind"], expected)

    def test_tar_magic_at_offset_257(self):
        blob = b"\x00" * 257 + b"ustar" + b"\x00" * 64
        self.assertEqual(identify_bytes(blob)["kind"], "tar")

    def test_unknown_bytes(self):
        self.assertIsNone(identify_bytes(b"just some plain text"))
        self.assertIsNone(identify_bytes(b""))

    def test_triage_by_file_path(self):
        fd, path = tempfile.mkstemp(suffix=".zip")
        os.close(fd)
        try:
            with open(path, "wb") as fh:
                fh.write(b"PK\x03\x04" + b"A" * 500)
            r = triage(file_path=path)
            self.assertEqual(r["kind"], "zip")
            self.assertEqual(r["confidence"], 95)
        finally:
            os.remove(path)

    def test_missing_file_reports_error(self):
        r = triage(file_path=os.path.join(tempfile.gettempdir(), "definitely_not_here_12345"))
        self.assertEqual(r["kind"], "error")
        self.assertEqual(r["confidence"], 0)


class TestReportShape(unittest.TestCase):
    """返回结构稳定 —— CLI 与 GUI 都按这个形状取值。"""

    def test_keys_present(self):
        r = triage(text="ZmxhZ3t0ZXN0fQ==")
        for key in ("kind", "confidence", "evidence", "paths", "alternatives"):
            self.assertIn(key, r)

    def test_paths_are_well_formed(self):
        for payload in ("ZmxhZ3t0ZXN0fQ==", f"n = {_RSA_N}\ne = 3\nc = {_RSA_C}",
                        "5d41402abc4b2a76b9719d911017c592", "http://a.b/c"):
            with self.subTest(payload=payload[:24]):
                for path in triage(text=payload)["paths"]:
                    self.assertIn("tool", path)
                    self.assertIn("hint", path)
                    self.assertIn("cmd", path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
