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
    """Encode text to Brainfuck program."""
    result = []
    prev = 0
    for c in text:
        cur = ord(c)
        diff = cur - prev
        if diff > 0:
            result.append('+' * diff)
        elif diff < 0:
            result.append('-' * (-diff))
        result.append('.')
        prev = cur
    return ''.join(result)


def brainfuck_decode(code: str) -> str:
    """Decode Brainfuck program."""
    tape = [0] * 30000
    ptr = 0
    pc = 0
    result = []
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
            result.append(chr(tape[ptr]))
        elif cmd == ',':
            pass  # No input support in decode mode
        elif cmd == '[':
            if tape[ptr] == 0:
                pc = match.get(pc, code_len)
        elif cmd == ']':
            if tape[ptr] != 0:
                pc = match.get(pc, 0) - 1
        pc += 1

    return ''.join(result)


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
    """Encode text to JSFuck subset (basic mapping). Returns a JS string that evals to the text."""
    # Use simple number-to-string approach
    result = []
    for c in text:
        code = ord(c)
        if 32 <= code <= 126:
            # Use minimum JSFuck: (+([]+(+!![]+!![]+!![]+!![]+!![]+!![]+!![]+!![]+!![]+!![])))
            # Simplified: we encode each char as String.fromCharCode(code)
            result.append(f"([]+[])[\"constructor\"][\"fromCharCode\"]({code})")
        else:
            result.append(f"\"{c}\"")
    return '+'.join(result) if result else '[]'


def jsfuck_decode(code: str) -> str:
    """Attempt to decode JSFuck by evaluating common patterns."""
    # Try extracting numbers from fromCharCode() calls
    import re as re_mod
    codes = re_mod.findall(r'fromCharCode\]\((\d+)\)', code)
    if codes:
        return ''.join(chr(int(c)) for c in codes if 32 <= int(c) < 65536)

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
