# -*- coding: utf-8 -*-
"""æ ¸å¿å·¥å·å½æ° â é¢è²è¾åºãå­ç¬¦æ£æµãéç¨è¾å©ã"""
import re
import os
import sys


# ââ ANSI é¢è² ââââââââââââââââââââââââââââââââââââââââââââââ
class Color:
    """ANSI ç»ç«¯é¢è²ç ."""
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
    # èæ¯
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"


def supports_color() -> bool:
    """æ£æµç»ç«¯æ¯å¦æ¯æé¢è²è¾åº."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def color(text: str, *styles: str) -> str:
    """ä¸ºææ¬æ·»å  ANSI é¢è²æ ·å¼."""
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
    """æå°å·¥å·æ¨ªå¹."""
    lines = [
        r"   ____  _____  ______          __     __",
        r"  / __ \/ __/ |/_/ __/      ___/ /__  / /",
        r" / /_/ / _//>  </ _/  _    / _  / _ \/ / ",
        r" \____/_/ /_/|_/_/  (_)   \_,_/\___/_/  ",
        "",
        f"  {bold('CTF-Web Arsenal')}  v1.0.0  |  {dim('ç¦»çº¿ CTF Web çå£«åå')}",
        "",
    ]
    return "\n".join(lines)


def is_printable(text: str) -> bool:
    """å¤æ­å­ç¬¦ä¸²æ¯å¦å¨é¨å¯æå°."""
    if not text:
        return False
    printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    return printable / len(text) > 0.95


def entropy(data: bytes) -> float:
    """è®¡ç®å­èæ°æ®çé¦åçµ (0-8)."""
    if not data:
        return 0.0
    from collections import Counter
    from math import log2
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * log2(c / length) for c in counts.values() if c > 0)
