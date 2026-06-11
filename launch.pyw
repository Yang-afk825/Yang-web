"""Yang-Web GUI 启动器 (.pyw = 无控制台窗口)

双击直接启动 GUI。与 python -m yang_web --gui 等效。
"""
import sys
import os

# 确保项目根目录在 sys.path 中
_project_root = os.path.dirname(os.path.abspath(__file__))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from yang_web.__main__ import main_gui

if __name__ == "__main__":
    main_gui()
