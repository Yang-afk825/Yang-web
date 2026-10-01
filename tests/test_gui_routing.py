# -*- coding: utf-8 -*-
"""GUI 面板间数据流（「送到下一步」）回归测试。

Tkinter 不是所有环境都有，或没有可用显示；两种情况都跳过而不是报错。
"""
import os
import sys
import unittest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

try:
    import tkinter as tk
    _TK_IMPORT_ERROR = None
except Exception as exc:  # noqa: BLE001
    tk = None
    _TK_IMPORT_ERROR = exc


def _can_open_root():
    if tk is None:
        return False
    try:
        root = tk.Tk()
    except Exception:  # noqa: BLE001
        return False
    root.withdraw()
    root.destroy()
    return True


_TK_OK = _can_open_root()


@unittest.skipUnless(_TK_OK, f"tkinter 不可用: {_TK_IMPORT_ERROR}")
class TestPanelRouting(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from yang_web import gui
        cls.gui = gui
        cls.root = tk.Tk()
        cls.root.withdraw()
        gui.apply_theme(cls.root)
        cls.decode = gui.DecodePanel(cls.root)
        cls.adv = gui.AdvancedEncodePanel(cls.root)
        cls.misc = gui.MiscCryptoPanel(cls.root)
        cls.notebook = tk.Frame(cls.root)

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()

    def setUp(self):
        gui = self.gui
        gui._ROUTES.clear()

        class _NB:
            selected = None

            def select(self, panel):
                _NB.selected = panel

        self.nb = _NB()

        def route_to(target, attr):
            def _handle(text):
                gui._set_input(getattr(target, attr, None), text)
                self.nb.select(target)
            return _handle

        gui.register_route("解码", route_to(self.decode, "input_text"))
        gui.register_route("Misc Crypto", route_to(self.misc, "io_entry"))

    def test_panels_construct_with_send_bar(self):
        """五个面板都要挂上发送条并登记进 _SEND_BARS。"""
        self.assertTrue(self.gui._SEND_BARS)

    def test_send_bar_rebuilds_after_registration(self):
        """路由是面板构造之后才注册的，按钮必须在那时补上。"""
        bar = self.gui._SEND_BARS[0]
        names = [w.cget("text") for w in bar._btn_area.winfo_children()]
        self.assertIn("解码", names)
        self.assertIn("Misc Crypto", names)

    def test_route_fills_text_widget(self):
        ok, message = self.gui.route_text("解码", "flag{from_route}")
        self.assertTrue(ok, message)
        self.assertEqual(self.decode.input_text.get("1.0", tk.END).strip(), "flag{from_route}")
        self.assertIs(self.nb.selected, self.decode)

    def test_route_fills_entry_widget(self):
        """Misc Crypto 的输入是 Entry，不是 Text。"""
        ok, message = self.gui.route_text("Misc Crypto", "hello_entry")
        self.assertTrue(ok, message)
        self.assertEqual(self.misc.io_entry.get(), "hello_entry")

    def test_route_rejects_empty_and_unknown(self):
        self.assertFalse(self.gui.route_text("解码", "   ")[0])
        self.assertFalse(self.gui.route_text("不存在", "x")[0])

    def test_last_output_line_skips_separators(self):
        gui = self.gui
        gui._clear_output(self.decode.output)
        gui._append(self.decode.output, "─── 分隔线 ───")
        gui._append(self.decode.output, "ABCD1234")
        self.assertEqual(gui._last_output_line(self.decode.output), "ABCD1234")

    def test_chain_decode_records_plaintext(self):
        """链式解码后送出的应是明文，而不是尾部那条分隔线。"""
        self.decode.input_text.delete("1.0", tk.END)
        self.decode.input_text.insert("1.0", "ZmxhZ3t0ZXN0fQ==")
        self.decode._chain()
        self.assertEqual(self.decode._last_result, "flag{test}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
