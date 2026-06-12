# -*- coding: utf-8 -*-
"""Yang-Web 入口 — 支持 GUI / CLI 双模式.

用法:
    python -m yang_web              # GUI 模式
    python -m yang_web --cli        # CLI 模式
    python -m yang_web <command>    # CLI 模式 (带参数自动识別)
"""
import sys


def main_gui():
    """启动图形界面."""
    from yang_web.gui import run_gui
    run_gui()


def main_cli():
    """启动命令行."""
    from yang_web.cli import main
    main()


if __name__ == "__main__":
    if len(sys.argv) <= 1:
        main_gui()
    elif sys.argv[1] == "--gui":
        main_gui()
    elif sys.argv[1] == "--cli":
        main_cli()
    else:
        main_cli()
