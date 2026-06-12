# -*- coding: utf-8 -*-
"""核心工具函数 — 颜色输出、字符检测、通用辅助。"""
import re
import os
import sys


# ── ANSI 颜色 ──────────────────────────────────────────────
class Color:
    """ANSI 终端颜色码."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    # 背景
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"


def supports_color() -> bool:
    """检测终端是否支持颜色输出."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def color(text: str, *styles: str) -> str:
    """为文本添加 ANSI 颜色样式."""
    if not supports_color():
        return text
    prefix = "".join(styles)
    return f"{prefix}{text}{Color.RESET}"


def bold(text: str) -> str: return color(text, Color.BOLD)
def red(text: str) -> str: return color(text, Color.RED)
def green(text: str) -> str: return color(text, Color.GREEN)
def yellow(text: str) -> str: return color(text, Color.YELLOW)
def blue(text: str) -> str: return color(text, Color.BLUE)
def magenta(text: str) -> str: return color(text, Color.MAGENTA)
def cyan(text: str) -> str: return color(text, Color.CYAN)
def dim(text: str) -> str: return color(text, Color.DIM)


def banner():
    """打印工具横幅."""
    lines = [
        r"   ____  _____  ______          __     __",
        r"  / __ \/ __/ |/_/ __/      ___/ /__  / /",
        r" / /_/ / _//>  </ _/  _    / _  / _ \/ / ",
        r" \____/_/ /_/|_/_/  (_)   \_,_/\___/_/  ",
        "",
        f"  {bold('CTF-Web Arsenal')}  v1.0.0  |  {dim('离线 CTF Web 瑞士军刀')}",
        "",
    ]
    return "\n".join(lines)


def is_printable(text: str) -> bool:
    """判断字符串是否全部可打印."""
    if not text:
        return False
    printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    return printable / len(text) > 0.95


def entropy(data: bytes) -> float:
    """计算字节数据的香农熵 (0-8)."""
    if not data:
        return 0.0
    from collections import Counter
    from math import log2
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * log2(c / length) for c in counts.values() if c > 0)
