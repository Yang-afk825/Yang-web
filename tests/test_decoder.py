# -*- coding: utf-8 -*-
"""解码器回归测试。

重点覆盖 2026-10-01 修复的两类缺陷：

1. 链式解码把已解出的明文再误判为 base91/base92，解成乱码后当作最终结果输出；
2. hex 串（base58 字母表的子集）被 base58 抢先识别，导致 base16 解不出。

用标准库 unittest 编写，无需安装任何第三方包：

    python -m unittest discover -s tests -v
"""
import base64
import binascii
import unittest

from yang_web.core.decoder import chain_decode, detect_encoding


def solve(text):
    """跑完整链式解码，返回最终结果；无结果返回 None。"""
    chain = chain_decode(text)
    return chain[-1][2] if chain else None


class TestChainDecode(unittest.TestCase):
    """常见编码应能正确解出。"""

    def test_base64_padded(self):
        self.assertEqual(solve("ZmxhZ3t0ZXN0fQ=="), "flag{test}")

    def test_base64_unpadded(self):
        self.assertEqual(solve("ZmxhZ3t0ZXN0fQ"), "flag{test}")

    def test_hex(self):
        self.assertEqual(solve("666c61677b746573747d"), "flag{test}")

    def test_base32(self):
        self.assertEqual(solve("MZWGCZ33ORSXG5D5"), "flag{test}")

    def test_url_encoded(self):
        self.assertEqual(solve("%66%6c%61%67%7b%74%65%73%74%7d"), "flag{test}")

    def test_base64_twice(self):
        payload = base64.b64encode(b"flag{multi}").decode()
        payload = base64.b64encode(payload.encode()).decode()
        self.assertEqual(solve(payload), "flag{multi}")

    def test_hex_then_base64(self):
        payload = binascii.hexlify(base64.b64encode(b"flag{hexb64}")).decode()
        self.assertEqual(solve(payload), "flag{hexb64}")


class TestPlaintextNotMangled(unittest.TestCase):
    """已是明文的输入，不得被继续解码成乱码（回归）。"""

    PLAINTEXTS = [
        "flag{test}",
        "DASCTF{abc_123}",
        "flag{0d3747db-16f6-4c62-9665-b3e7531cefc8}",
    ]

    def test_no_replacement_char_in_output(self):
        for text in self.PLAINTEXTS:
            with self.subTest(text=text):
                for _, _, decoded in chain_decode(text):
                    self.assertNotIn("\ufffd", decoded)

    def test_flag_not_detected_as_base91(self):
        """base91 字符集含 { } _，历史上导致 flag 明文被判为 base91。"""
        scores = {cid: conf for cid, _, conf in detect_encoding("flag{test}")}
        self.assertLess(scores.get("base91", 0), 50)
        self.assertLess(scores.get("base92", 0), 50)


class TestDetectionPriority(unittest.TestCase):
    """编码检测优先级（回归）。"""

    def test_hex_preferred_over_base58(self):
        """hex 字符集是 base58 字母表的子集，base16 必须优先。"""
        detections = detect_encoding("666c61677b746573747d")
        self.assertTrue(detections, "应至少检测出一种编码")
        self.assertEqual(detections[0][0], "base16")

    def test_base64_preferred_over_base58(self):
        """base64 远比 base58 常见，同分时必须排在前面。"""
        detections = detect_encoding("ZmxhZ3toZXhiNjR9")
        ids = [cid for cid, _, _ in detections]
        self.assertIn("base64", ids)
        self.assertLess(ids.index("base64"), ids.index("base58"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
