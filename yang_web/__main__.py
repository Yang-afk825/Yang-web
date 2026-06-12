# -*- coding: utf-8 -*-
"""Yang-Web å¥å£ â æ¯æ GUI / CLI åæ¨¡å¼.

ç¨æ³:
    python -m yang_web              # GUI æ¨¡å¼
    python -m yang_web --cli        # CLI æ¨¡å¼
    python -m yang_web <command>    # CLI æ¨¡å¼ (å¸¦åæ°èªå¨è¯å¥)
"""
import sys


def main_gui():
    """å¯å¨å¾å½¢çé¢."""
    from yang_web.gui import run_gui
    run_gui()


def main_cli():
    """å¯å¨å½ä»¤è¡."""
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
