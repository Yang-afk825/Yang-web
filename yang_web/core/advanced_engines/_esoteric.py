"""yang_web.core.advanced_engines 子模块 _esoteric（自 advanced_engines.py 拆分，请勿手工重排）。"""

import re
import base64
import codecs
import struct
from typing import Optional, Tuple




# ═══════════════════════════════════════════
# 2. Ook! (Brainfuck变体)
# ═══════════════════════════════════════════

OOK_MAP = {
    '>': 'Ook. Ook?',
    '<': 'Ook? Ook.',
    '+': 'Ook. Ook.',
    '-': 'Ook! Ook!',
    '.': 'Ook! Ook.',
    ',': 'Ook. Ook!',
    '[': 'Ook! Ook?',
    ']': 'Ook? Ook!',
}


# ═══════════════════════════════════════════
# 1. Brainfuck 解释器
# ═══════════════════════════════════════════

def brainfuck_encode(text: str) -> str:
    """Encode text to Brainfuck program.

    Brainfuck 的 ``.`` 输出的是**字节**，因此按 UTF-8 字节逐位生成。
    旧实现用 ``ord(c)`` 取码点 —— 中文会被当作 20013 这种大数，
    生成上千个 ``+``，解出来必然是乱码。

    每个字节取「模 256 更短的一侧」：从 200 到 10 用 ``-`` 走 190 步
    不如 ``+`` 走 66 步，两者在 8 位磁带里等价。
    """
    result = []
    prev = 0
    for byte in text.encode('utf-8'):
        diff = (byte - prev) % 256
        if diff and diff <= 128:
            result.append('+' * diff)
        elif diff:
            result.append('-' * (256 - diff))
        result.append('.')
        prev = byte
    return ''.join(result)


def brainfuck_decode(code: str) -> str:
    """Decode Brainfuck program（输出按 UTF-8 还原为文本）。"""
    tape = [0] * 30000
    ptr = 0
    pc = 0
    result = bytearray()
    code_clean = ''.join(c for c in code if c in '><+-.,[]')
    code_len = len(code_clean)
    loop_stack = []

    # Pre-compute matching brackets
    match = {}
    for i, c in enumerate(code_clean):
        if c == '[':
            loop_stack.append(i)
        elif c == ']':
            if loop_stack:
                j = loop_stack.pop()
                match[i] = j
                match[j] = i

    while pc < code_len:
        cmd = code_clean[pc]
        if cmd == '>':
            ptr = (ptr + 1) % 30000
        elif cmd == '<':
            ptr = (ptr - 1) % 30000
        elif cmd == '+':
            tape[ptr] = (tape[ptr] + 1) % 256
        elif cmd == '-':
            tape[ptr] = (tape[ptr] - 1) % 256
        elif cmd == '.':
            result.append(tape[ptr])
        elif cmd == ',':
            pass  # No input support in decode mode
        elif cmd == '[':
            if tape[ptr] == 0:
                pc = match.get(pc, code_len)
        elif cmd == ']':
            if tape[ptr] != 0:
                pc = match.get(pc, 0) - 1
        pc += 1

    return bytes(result).decode('utf-8', errors='replace')


def ook_encode(text: str) -> str:
    """Encode text to Ook! program."""
    bf = brainfuck_encode(text)
    result = []
    for c in bf:
        if c in OOK_MAP:
            result.append(OOK_MAP[c])
    return ' '.join(result)


def ook_decode(code: str) -> str:
    """Decode Ook! program."""
    # Convert Ook to Brainfuck
    OOK_REV = {v: k for k, v in OOK_MAP.items()}
    # Split by spaces and normalize
    tokens = code.strip().split()
    bf = []
    i = 0
    while i < len(tokens) - 1:
        pair = f"{tokens[i]} {tokens[i+1]}"
        if pair in OOK_REV:
            bf.append(OOK_REV[pair])
            i += 2
        else:
            i += 1
    return brainfuck_decode(''.join(bf))


# ═══════════════════════════════════════════
# 10. JSFuck 编解码
# ═══════════════════════════════════════════

def jsfuck_encode(text: str) -> str:
    """Encode text into a JS expression that evaluates back to the text.

    逐 **UTF-16 码元** 生成 ``String.fromCharCode(...)`` 并串联。
    JS 字符串本就是 UTF-16，用码元（而非 Python 码点）才能让
    BMP 之外的字符（emoji 等）也正确往返。
    """
    if not text:
        return '[]'
    data = text.encode('utf-16-be')
    parts = []
    for i in range(0, len(data), 2):
        code = int.from_bytes(data[i:i + 2], 'big')
        parts.append(f"([]+[])[\"constructor\"][\"fromCharCode\"]({code})")
    return '+'.join(parts)


def jsfuck_decode(code: str) -> str:
    """Decode JSFuck / fromCharCode 链。

    旧实现的正则写的是 ``fromCharCode\\)\\(`` —— 但编码器产出的是
    ``["fromCharCode"](72)``，属性名后跟的是引号再跟着括号，
    所以正则永远匹配不到，连自己编出来的东西都解不回去。
    """
    import re as re_mod
    codes = re_mod.findall(r'fromCharCode\D{0,10}\(\s*(\d+)\s*\)', code)
    if codes:
        raw = bytearray()
        for c in codes:
            value = int(c)
            if 0 <= value < 0x10000:
                raw.extend(value.to_bytes(2, 'big'))
        if raw:
            return bytes(raw).decode('utf-16-be', errors='replace')

    # Try extracting quoted strings
    strings = re_mod.findall(r'"([^"]*)"', code)
    if strings:
        return ''.join(strings)

    return '\n'.join([
        '[!] JSFuck 解码需要 JavaScript 运行时',
        '',
        '📝 提取到的 fromCharCode 参数: ' + (', '.join(codes) if codes else '无'),
        '📝 提取到的字符串: ' + (' + '.join(strings) if strings else '无'),
        '💡 提示: 将 JSFuck 代码粘贴到浏览器 Console 中运行即可',
    ])


# ═══════════════════════════════════════════
# 11. AAEncode 识别与解码
# ═══════════════════════════════════════════

def aaencode_decode(code: str) -> str:
    """Decode AAEncode (Japanese-style JS encoding)."""
    code_clean = code.strip()
    # AAEncode uses emoticon-like characters
    # Try to extract eval'd content
    import re as re_mod

    # Look for unescape or eval chains
    if 'unescape' in code_clean.lower():
        matches = re_mod.findall(r"unescape\(['\"](.*?)['\"]\)", code_clean, re_mod.IGNORECASE)
        if matches:
            return ' | '.join(matches)
    if 'eval' in code_clean:
        matches = re_mod.findall(r"eval\(['\"](.*?)['\"]\)", code_clean)
        if matches:
            return ' | '.join(matches)

    return '\n'.join([
        '[!] AAEncode 解码需要 JavaScript 运行时',
        '',
        '💡 提示: 将 AAEncode 代码粘贴到浏览器 Console 中运行即可',
        '📋 原始代码 (前200字符): ' + code_clean[:200],
    ])


def aaencode_encode(text: str) -> str:
    """Provide hint about AAEncode (requires external tool)."""
    return f'[!] AAEncode 编码需要 Node.js 运行时。\n建议: 安装 npm aaencode 包\n原始文本: {text}'


# ═══════════════════════════════════════════
# 12. JJEncode 识别与解码
# ═══════════════════════════════════════════

def jjencode_decode(code: str) -> str:
    """Decode JJEncode."""
    code_clean = code.strip()
    return '\n'.join([
        '[!] JJEncode 解码需要 JavaScript 运行时',
        '',
        '💡 提示: 将 JJEncode 代码粘贴到浏览器 Console 中运行即可',
        '📋 原始代码 (前200字符): ' + code_clean[:200],
    ])


def jjencode_encode(text: str) -> str:
    """Provide hint about JJEncode."""
    return f'[!] JJEncode 编码需要 Node.js 运行时。\n建议: 安装 npm jjencode 包\n原始文本: {text}'
