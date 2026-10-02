# -*- coding: utf-8 -*-
"""双模式入口：`python -m yang_web.core.smart_solver <cmd>` 或直接 `python <pkg>/__main__.py <cmd>`。"""
import os
import sys

if __package__ in (None, ""):
    # 以文件方式直接执行（scripts/runner.py 走的就是这条路）：
    # 把仓库根目录塞进 sys.path，再按包名导入，避免相对导入失效。
    _root = os.path.abspath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
    if _root not in sys.path:
        sys.path.insert(0, _root)
    from yang_web.core.smart_solver._entry import main
else:
    from ._entry import main

if __name__ == "__main__":
    main()
