# -*- coding: utf-8 -*-
"""Base91 / Base92 编解码回归测试。

为什么需要它
------------
这两个函数此前**双双失效**，而既有测试完全没覆盖到：

1. ``base91_decode`` 收尾一行位序写反（``v | b << n`` 应为 ``b | v << n``）。
   只有「末组剩单字符」即编码串长度为**奇数**时才暴露：
   ``HELLO`` 解成 ``'HELL\\x80'``、``flag{test}`` 解成 ``'flag{testA'``。
   偶数长度（``abc``/``test123``）恰好掩盖了它 —— 这正是漏测的原因。
2. ``base92`` 成对实现不自洽：编码按 13 bit 分组、尾部却按「模 92」，
   解码又用 ``value * 92 + idx`` 递推。任何输入都解不出原文。

因此这里同时锁两件事：**与权威实现逐字符一致**（向量硬编码，
不依赖第三方包），以及**任意长度都能往返**（含奇/偶两类长度）。

    python -m unittest discover -s tests -t . -v
"""
import unittest

from yang_web.core.advanced_engines import (
    base91_decode, base91_encode, base92_decode, base92_encode,
)

# 权威实现（PyPI base91 1.x / base92 2.x）产出的向量，硬编码以免测试依赖三方包。
# 每项为 (明文, base91 编码, base92 编码)
REFERENCE_VECTORS = [
    ("HELLO", ">O$G+3A", ";G]Z3>B"),
    ("flag{test}", "@iH<,{!eaUo{B", "F#S<YRdM@^tw2"),
    ("abc", "#G(I", "D8<q"),
    ("test123", "fPNK,i~RD", "Jw_@lGWo."),
    ("中文", "C+Z8JQ~C", "sI)\\X;9f"),
    ("Yang-Web", ".DU=_fEebR", "AI2+Y+^D@<"),
    ("A", "%A", "8q"),
    ("?", "#A", "80"),
]

# 必须覆盖奇、偶两种编码长度：base91 的收尾缺陷只在末组为单字符时现形。
_ODD_EVEN_TEXTS = [
    "H", "HE", "HEL", "HELL", "HELLO",          # 奇数长度编码的代表
    "abc", "test123", "Yang-Web",                # 偶数长度编码的代表
    "flag{test}", "flag{th1s_1s_4_t3st}",        # 典型 CTF 明文
    "中", "中文", "中文测试", "emoji",             # 多字节 UTF-8
    " " * 7, "\t\n\r", "0", "00", "000",
    "".join(chr(c) for c in range(0x20, 0x7f)),  # 全部可打印 ASCII
]


class TestBase91(unittest.TestCase):
    """Base91 必须与参考实现一致，且任意长度都可往返。"""

    def test_encode_matches_reference(self):
        for text, enc91, _enc92 in REFERENCE_VECTORS:
            with self.subTest(text=text):
                self.assertEqual(base91_encode(text), enc91)

    def test_decode_matches_reference(self):
        for text, enc91, _enc92 in REFERENCE_VECTORS:
            with self.subTest(text=text):
                self.assertEqual(base91_decode(enc91), text)

    def test_decode_does_not_leak_extra_byte(self):
        """回归：收尾位序写反时会多吐一个字节（HELLO -> HELL\\x80）。"""
        for text, enc91, _enc92 in REFERENCE_VECTORS:
            with self.subTest(text=text):
                got = base91_decode(enc91)
                self.assertEqual(len(got), len(text))
                self.assertNotIn("\x80", got)

    def test_roundtrip_all_lengths(self):
        for text in _ODD_EVEN_TEXTS:
            with self.subTest(text=text):
                self.assertEqual(base91_decode(base91_encode(text)), text)

    def test_empty_input(self):
        self.assertEqual(base91_encode(""), "")
        self.assertEqual(base91_decode(""), "")

    def test_decode_tolerates_foreign_chars(self):
        """解码链会喂进换行/空格等分隔符，应按原实现忽略而非报错。"""
        self.assertEqual(base91_decode(">O$G+3A\n"), "HELLO")
        self.assertEqual(base91_decode(" >O$G +3A "), "HELLO")


class TestBase92(unittest.TestCase):
    """Base92 必须与参考实现一致，且任意长度都可往返。"""

    def test_encode_matches_reference(self):
        for text, _enc91, enc92 in REFERENCE_VECTORS:
            with self.subTest(text=text):
                self.assertEqual(base92_encode(text), enc92)

    def test_decode_matches_reference(self):
        for text, _enc91, enc92 in REFERENCE_VECTORS:
            with self.subTest(text=text):
                self.assertEqual(base92_decode(enc92), text)

    def test_roundtrip_all_lengths(self):
        for text in _ODD_EVEN_TEXTS:
            with self.subTest(text=text):
                self.assertEqual(base92_decode(base92_encode(text)), text)

    def test_empty_input_uses_tilde(self):
        """参考实现把空串编码成单个 '~'，解码须还原为空串。"""
        self.assertEqual(base92_encode(""), "~")
        self.assertEqual(base92_decode("~"), "")

    def test_short_or_invalid_input_returns_empty(self):
        self.assertEqual(base92_decode(""), "")
        self.assertEqual(base92_decode("A"), "")
        self.assertEqual(base92_decode("\n\t"), "")


class TestDecoderPipeline(unittest.TestCase):
    """解码链的公开包装函数必须指向修好的实现。"""

    def test_public_wrappers(self):
        from yang_web.core.decoder import decode_base91, decode_base92
        self.assertEqual(decode_base91(">O$G+3A"), "HELLO")
        self.assertEqual(decode_base92(";G]Z3>B"), "HELLO")


if __name__ == "__main__":
    unittest.main(verbosity=2)
