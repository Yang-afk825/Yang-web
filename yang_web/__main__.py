"""Yang-Web 入口 — 支持 GUI / CLI 双模式.

用法:
    python -m yang_web              # GUI 模式
    python -m yang_web --cli        # CLI 模式
    python -m yang_web <command>    # CLI 模式 (带参数自动识別)
"""
import sys

if __name__ == "__main__":
    # 无参数 或 明确指定 --gui → GUI 模式
    if len(sys.argv) == 1:
        from yang_web.gui import run_gui
        run_gui()
    elif sys.argv[1] == "--gui":
        from yang_web.gui import run_gui
        run_gui()
    else:
        from yang_web.cli import main
        main()
