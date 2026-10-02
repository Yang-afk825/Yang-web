# -*- coding: utf-8 -*-
"""advanced_engines 编解码引擎回归测试。

背景
----
`tests/test_ciphers.py` 覆盖的是 misc_crypto 注册表，`tests/test_base9192.py`
刚补上 base91/92。但 advanced_engines 里另外 16 个引擎**一条测试都没有**，
于是下面这些缺陷长期潜伏（全部在 2026-10-02 一次性查出并修复）：

============  ==========================================================
rot18_encode  函数体第一行是 `return rot5_encode(rot47_encode(text)[:0])`，
              切片 [:0] 恒为空串 —— 真正的实现成了死代码，恒返回 ''。
jsfuck_decode 正则写成 `fromCharCode\\)\\(`，而编码器产出的是
              `["fromCharCode"](72)`，属性名后是引号不是右括号，
              正则永远匹配不到，连自己编出来的都解不回去。
quoted_print 编码把空格写成 '_'，解码却从不还原 —— 单向丢失。
brainfuck     用 ord(c) 取码点当字节，'中' 变成 20013，生成上千个 '+'。
shellcode     用 f'{ord(c):02x}'，'中' 写成 '\x4e2d' 四位十六进制，
              解码端只认两位，必然错位。
zerowidth     f'{ord(c):016b}' 的 16 只是最小宽度，码点 > U+FFFF 输出 17 位，
              整条比特流从此错位。
uuencode      直接套 base64.b64encode，不是 uuencode —— 外部工具产生的
              数据一律解不开。
============  ==========================================================

策略：能往返的一律往返；能对标标准库的就对标标准库（UUEncode 对
`binascii.b2a_uu` / `a2b_uu`）；确实无法往返的在 ONE_WAY_BY_DESIGN 里显式登记，
避免"漏测"和"误判"混为一谈。

    python -m unittest discover -s tests -t . -v
"""
import binascii
import unittest

from yang_web.core.advanced_engines import (
    ADVANCED_ENCODERS,
    brainfuck_decode, brainfuck_encode,
    jsfuck_decode, jsfuck_encode,
    ook_decode, ook_encode,
    quoted_printable_decode, quoted_printable_encode,
    rot18_decode, rot18_encode,
    shellcode_decode, shellcode_encode,
    uudecode, uuencode,
    xxdecode, xxencode,
    zerowidth_decode, zerowidth_encode,
)

# 需要 JavaScript 运行时才能完成编解码，本工具只能给出提示 —— 不是回归缺陷。
ONE_WAY_BY_DESIGN = {
    'aaencode': '编解码均需 Node.js / 浏览器 JS 运行时',
    'jjencode': '编解码均需 Node.js / 浏览器 JS 运行时',
}

# 往返测试的输入：覆盖 ASCII、中文、emoji（BMP 之外）、长串、全可打印字符集。
TEXTS = [
    'HELLO', 'flag{test}', 'Yang-Web 4.1.1', '中文测试', 'A', 'abc123', ' ',
    'emoji😀😀x', 'a' * 200, ''.join(chr(c) for c in range(0x20, 0x7f)),
]


class TestRegistryRoundTrip(unittest.TestCase):
    """注册表里每个引擎都必须能往返（显式登记的单向编码除外）。"""

    def test_every_roundtrippable_engine(self):
        for eid, info in ADVANCED_ENCODERS.items():
            if eid in ONE_WAY_BY_DESIGN:
                continue
            enc, dec = info['encode'], info['decode']
            for text in TEXTS:
                with self.subTest(engine=eid, text=text[:20]):
                    self.assertEqual(dec(enc(text)), text)

    def test_one_way_engines_are_documented(self):
        """登记为单向的引擎必须确实在注册表中，且必须给出可读提示。"""
        for eid in ONE_WAY_BY_DESIGN:
            with self.subTest(engine=eid):
                self.assertIn(eid, ADVANCED_ENCODERS)
                out = ADVANCED_ENCODERS[eid]['encode']('x')
                self.assertTrue(any(k in out for k in ('Node', '运行时')),
                                f"{eid} 未给出可读的运行环境提示: {out[:60]!r}")


class TestUuencodeAgainstStdlib(unittest.TestCase):
    """UUEncode 必须与标准库 binascii 双向互解。"""

    def _blob(self, raw: bytes) -> str:
        return '\n'.join(['begin 644 data']
                         + [binascii.b2a_uu(raw[i:i + 45]).decode().rstrip('\n')
                            for i in range(0, len(raw), 45)]
                         + ['`', 'end'])

    def test_stdlib_can_decode_our_output(self):
        for raw in (b'HELLO', b'flag{test}', bytes(range(128)), b'', b'A' * 45, b'B' * 46):
            with self.subTest(raw=raw[:12]):
                body = [ln for ln in uuencode(raw.decode('latin-1')).splitlines()
                        if ln and not ln.lower().startswith(('begin', 'end')) and ln != '`']
                got = b''.join(binascii.a2b_uu(ln.encode()) for ln in body) if body else b''
                self.assertEqual(got, raw)

    def test_we_can_decode_stdlib_output(self):
        for raw in (b'HELLO', b'flag{test}', bytes(range(128)), b'', b'A' * 45, b'C' * 90):
            with self.subTest(raw=raw[:12]):
                self.assertEqual(uudecode(self._blob(raw)), raw.decode('latin-1'))

    def test_uu_is_not_base64(self):
        """回归：旧实现用 base64 冒充 uuencode，字母表完全不同。"""
        enc = uuencode('HELLO')
        self.assertIn('begin 644 data', enc)
        self.assertNotIn('SEVMTE8', enc)          # base64('HELLO')


class TestSpecificRegressions(unittest.TestCase):
    """每一个曾经失灵的引擎，逐条钉死。"""

    def test_rot18_is_not_empty(self):
        """rot18_encode 曾因一行 `return ...[ :0]` 恒返回空串。"""
        self.assertEqual(rot18_encode('HELLO'), 'URYYB')
        self.assertEqual(rot18_encode('abc123'), 'nop678')
        self.assertEqual(rot18_encode('Flag-2026!'), 'Synt-7571!')
        self.assertEqual(rot18_decode(rot18_encode('Flag-2026!')), 'Flag-2026!')

    def test_jsfuck_decodes_its_own_output(self):
        for text in ('HELLO', 'flag{test}', '中文', '😀x'):
            with self.subTest(text=text):
                self.assertEqual(jsfuck_decode(jsfuck_encode(text)), text)

    def test_jsfuck_keeps_js_runtime_hint_for_real_jsfuck(self):
        """真 JSFuck（fromCharCode 参数是算式而非数字）仍应回落到提示。"""
        hint = jsfuck_decode('(![]+[])[+!+[]]+(!![]+[])[!+[]+!+[]]')
        self.assertIn('JavaScript 运行时', hint)

    def test_quoted_printable_space_is_not_underscore(self):
        self.assertEqual(quoted_printable_encode(' '), '=20')
        self.assertEqual(quoted_printable_decode(quoted_printable_encode('a b c')), 'a b c')
        self.assertEqual(quoted_printable_decode('a_b'), 'a_b')          # 普通下划线保留
        self.assertEqual(quoted_printable_decode('=?gbk?Q?a_b?='), 'a b')  # Q-word 里才是空格

    def test_quoted_printable_handles_non_ascii_input(self):
        """回归：旧解码对非 ASCII 输入用 ord(c) 直接塞 bytearray，会抛 ValueError。"""
        self.assertEqual(quoted_printable_decode('中文=20ok'), '中文 ok')

    def test_brainfuck_and_ook_use_utf8_bytes(self):
        for text in ('中文', '😀', 'flag{中文}'):
            with self.subTest(text=text):
                self.assertEqual(brainfuck_decode(brainfuck_encode(text)), text)
                self.assertEqual(ook_decode(ook_encode(text)), text)

    def test_brainfuck_takes_short_side_of_the_tape(self):
        """8 位磁带会回绕，往短的一侧走能显著缩短程序。

        '中' 的 UTF-8 是 E4 B8 AD；沿差值绝对值单调走要 283 步，
        按模 256 取短边只要 83 步。
        """
        naive = 0
        prev = 0
        for byte in '中'.encode('utf-8'):
            naive += abs(byte - prev) + 1
            prev = byte
        prog = brainfuck_encode('中')
        self.assertLess(len(prog), naive)
        self.assertLess(len(prog), 120)
        self.assertEqual(brainfuck_decode(prog), '中')

    def test_shellcode_emits_two_hex_digits_per_byte(self):
        self.assertEqual(shellcode_encode('A中'), '\\x41\\xe4\\xb8\\xad')
        for text in ('中文', 'flag{中文}'):
            with self.subTest(text=text):
                self.assertEqual(shellcode_decode(shellcode_encode(text)), text)

    def test_zerowidth_handles_astral_planes(self):
        """回归：ord(c):016b 对 > U+FFFF 输出 17 位，整条流错位。"""
        for text in ('😀x', '中文😀', 'flag{😀}'):
            with self.subTest(text=text):
                self.assertEqual(zerowidth_decode(zerowidth_encode(text)), text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
