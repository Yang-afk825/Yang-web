# -*- coding: utf-8 -*-
"""`python -m yang_web.gui` 入口（拆分前是 gui.py 末尾的主块）。"""
from ._app import run_gui  # noqa: F401

if __name__ == "__main__":
    run_gui()
