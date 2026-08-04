# -*- coding: utf-8 -*-
"""Yang-Web v4.0 启动入口 — 本地 Web UI (无窗口)。

启动 FastAPI 服务并自动打开默认浏览器。
"""
import os
import sys
import threading

# 确保可以导入 yang_web 包
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

def main():
    try:
        from yang_web.server import main as server_main
    except ImportError as e:
        # 无 fastapi 时回退到 tkinter GUI
        print(f"[Yang-Web] FastAPI 不可用 ({e})，回退到 tkinter 界面…")
        try:
            from yang_web.gui import main as gui_main
            gui_main()
        except Exception as e2:
            print(f"[Yang-Web] tkinter 也不可用: {e2}")
            input("按回车退出…")
        return
    server_main()

if __name__ == "__main__":
    main()
