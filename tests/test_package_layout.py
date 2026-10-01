# -*- coding: utf-8 -*-
"""包布局回归测试 —— 锁住"巨型文件拆包"之后的对外契约。

为什么需要它
------------
把 `a/b/c.py` 拆成 `a/b/c/` 包时, 有三类问题**编译期和常规单测都发现不了**:

1. `from .X import y` 在运行时才解析, 拆包后 `.` 的语义变了会静默失效;
2. `os.path.dirname(__file__)` 这类"按文件位置上溯"的路径会悄悄指错目录;
3. 某个原本在模块顶层导入的名字（如 `time`）在新位置没人导入 → NameError。

本文件只断言这些"结构化契约", 不重复断言业务逻辑。
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


class TestUrlAnalyzerPackage(unittest.TestCase):
    """core.url_analyzer 已拆为分层包，对外仍必须是一个完整模块。"""

    EXPECTED = [
        "analyze_url", "auto_exploit", "execute_attack",
        "SmartFingerprinter", "ConcurrentEngine", "AdaptiveScheduler",
        "get_attack_guide", "send_request", "crawl_page",
        "FLAG_RE", "FLAG_PATHS", "PARAM_SIGNATURES", "PATH_PATTERNS",
        "ATTACK_PAYLOADS", "DEFAULT_TIMEOUT", "USER_AGENT",
    ]

    def test_all_public_names_still_exported(self):
        import yang_web.core.url_analyzer as ua
        for name in self.EXPECTED:
            self.assertTrue(hasattr(ua, name), f"缺少对外符号: {name}")

    def test_submodules_are_importable(self):
        """每个分层子模块都要能被单独导入（相对导入没写错）。"""
        import importlib
        for mod in ("_http", "_signatures", "_engines", "_attacks", "_analyze"):
            m = importlib.import_module("yang_web.core.url_analyzer." + mod)
            self.assertIsNotNone(m)

    def test_flag_re_still_matches(self):
        from yang_web.core.url_analyzer import FLAG_RE
        self.assertTrue(FLAG_RE.search("noise flag{abc12345} tail"))


@unittest.skipUnless(_TK_OK, f"tkinter 不可用: {_TK_IMPORT_ERROR}")
class TestGuiPackage(unittest.TestCase):
    """gui 已拆为包，必须保住对外符号、文档路径与三个入口。"""

    EXPECTED = [
        "run_gui", "apply_theme", "_SendBar", "register_route", "route_text",
        "_set_input", "_last_output_line", "_ROUTES", "_SEND_BARS",
        "DecodePanel", "AdvancedEncodePanel", "MiscCryptoPanel",
        "UrlAttackPanel", "SQLLabsPanel", "DocsPanel",
    ]

    def test_all_public_names_still_exported(self):
        from yang_web import gui
        for name in self.EXPECTED:
            self.assertTrue(hasattr(gui, name), f"缺少对外符号: {name}")

    def test_docs_root_points_at_repo_docs(self):
        """拆包后 __file__ 深了一层，文档根必须仍指向仓库根的 docs/ctf-guide。"""
        from yang_web.gui._panels_tools import DocsPanel
        self.assertTrue(os.path.isdir(DocsPanel._DOCS_ROOT),
                        f"文档目录不存在: {DocsPanel._DOCS_ROOT}")
        for _title, filename, _desc in DocsPanel._DOCS:
            if filename:
                self.assertTrue(
                    os.path.isfile(os.path.join(DocsPanel._DOCS_ROOT, filename)),
                    f"文档缺失: {filename}")

    def test_time_is_imported_where_sleep_is_used(self):
        """SQLLabsPanel._solve_batch 用了 time.sleep，必须真有 time 可解析。"""
        import yang_web.gui._panels_attack as pa
        self.assertTrue(callable(pa.time.sleep))

    def test_entry_points_agree(self):
        """`from yang_web.gui import run_gui` 与 `python -m yang_web.gui` 指向同一函数。"""
        from yang_web import gui
        import yang_web.gui.__main__ as main_mod
        self.assertIs(main_mod.run_gui, gui.run_gui)


if __name__ == "__main__":
    unittest.main(verbosity=2)
