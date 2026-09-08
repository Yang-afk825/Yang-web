# -*- coding: utf-8 -*-
"""esoteric_lang.py — esoteric 语言 / 特色编码（对照随波逐流 V8.0 补齐）

包含：
  - Whitespace — 空格/制表符/换行
  - Deadfish — i/d/s/o 累加器语言
  - Spoon — Brainfuck 的 0/1 编码
  - LOLCODE — VISIBLE 输出
  - 汉字数字 — 零一二三... ↔ 字节

纯 Python 标准库零依赖，API 与 cipher_classic / cipher_keyed 一致。
"""

# ═══════════════════════════════════════════
# 1. Whitespace
# ═══════════════════════════════════════════

def whitespace_encode(text: str) -> str:
    data = text.encode('utf-8')
    out = []
    for b in data:
        out.append(''.join(' ' if bit == '0' else '\t' for bit in f'{b:08b}'))
    return '\n'.join(out)


def whitespace_decode(cipher: str) -> str:
    out = bytearray()
    for line in cipher.split('\n'):
        bits = ''.join('0' if c == ' ' else '1' for c in line if c in ' \t')
        if len(bits) == 8:
            out.append(int(bits, 2))
    return out.decode('utf-8', errors='replace')


# ═══════════════════════════════════════════
# 2. Deadfish
# ═══════════════════════════════════════════

def deadfish_encode(text: str) -> str:
    acc = 0
    out = []
    for ch in text:
        target = ord(ch)
        diff = target - acc
        if diff >= 0:
            out.append('i' * diff)
        else:
            out.append('d' * (-diff))
        out.append('o')
        acc = target
    return ''.join(out)


def deadfish_decode(cipher: str) -> str:
    acc = 0
    out = []
    for c in cipher:
        if c == 'i':
            acc = (acc + 1) & 0xFF
        elif c == 'd':
            acc = (acc - 1) & 0xFF
        elif c == 's':
            acc = (acc * acc) & 0xFF
        elif c == 'o':
            out.append(chr(acc))
    return ''.join(out)


# ═══════════════════════════════════════════
# 3. Brainfuck 解释器 + Spoon 编码
# ═══════════════════════════════════════════

SPOON = {
    '+': '010',
    '-': '011',
    '>': '00100',
    '<': '00101',
    '[': '0010110',
    ']': '0010111',
    '.': '001010',
    ',': '001011',
}
_SPOON_ITEMS = sorted(SPOON.items(), key=lambda x: -len(x[1]))


def _brainfuck_run(code: str, input_str: str = "") -> str:
    cells = [0] * 30000
    ptr = 0
    code_ptr = 0
    input_ptr = 0
    output = []
    stack = []
    match = {}
    for i, c in enumerate(code):
        if c == '[':
            stack.append(i)
        elif c == ']':
            if stack:
                j = stack.pop()
                match[i] = j
                match[j] = i
    while code_ptr < len(code):
        c = code[code_ptr]
        if c == '>':
            ptr += 1
        elif c == '<':
            ptr -= 1
        elif c == '+':
            cells[ptr] = (cells[ptr] + 1) & 0xFF
        elif c == '-':
            cells[ptr] = (cells[ptr] - 1) & 0xFF
        elif c == '.':
            output.append(chr(cells[ptr]))
        elif c == ',':
            cells[ptr] = ord(input_str[input_ptr]) if input_ptr < len(input_str) else 0
            input_ptr += 1
        elif c == '[':
            if cells[ptr] == 0:
                code_ptr = match.get(code_ptr, code_ptr)
        elif c == ']':
            if cells[ptr] != 0:
                code_ptr = match.get(code_ptr, code_ptr)
        code_ptr += 1
    return ''.join(output)


def _text_to_brainfuck(text: str) -> str:
    out = []
    cell = 0
    for ch in text:
        target = ord(ch)
        diff = target - cell
        if diff >= 0:
            out.append('+' * diff)
        else:
            out.append('-' * (-diff))
        out.append('.')
        cell = target
    return ''.join(out)


def _spoon_to_bf(s: str) -> str:
    bf = ''
    i = 0
    while i < len(s):
        for cmd, code in _SPOON_ITEMS:
            if s.startswith(code, i):
                bf += cmd
                i += len(code)
                break
        else:
            i += 1
    return bf


def spoon_encode(text: str) -> str:
    bf = _text_to_brainfuck(text)
    return ''.join(SPOON[c] for c in bf if c in SPOON)


def spoon_decode(cipher: str) -> str:
    s = ''.join(c for c in cipher if c in '01')
    bf = _spoon_to_bf(s)
    return _brainfuck_run(bf)


# ═══════════════════════════════════════════
# 4. LOLCODE
# ═══════════════════════════════════════════

def lolcode_encode(text: str) -> str:
    return f'HAI 1.2\nCAN HAS STDIO?\nVISIBLE "{text}"\nKTHXBYE'


def lolcode_decode(cipher: str) -> str:
    import re
    m = re.search(r'VISIBLE\s+"([^"]*)"', cipher)
    if m:
        return m.group(1)
    return "[!] 未找到 VISIBLE 语句"


# ═══════════════════════════════════════════
# 5. 汉字数字（零一二三... ↔ 字节）
# ═══════════════════════════════════════════

CHINESE_NUMS = "零一二三四五六七八九"
CHINESE_NUMS_UPPER = "零壹贰叁肆伍陆柒捌玖"


def chinese_num_encode(text: str) -> str:
    out = []
    for b in text.encode('utf-8'):
        out.append(''.join(CHINESE_NUMS[int(d)] for d in f'{b:03d}'))
    return ''.join(out)


def chinese_num_decode(cipher: str) -> str:
    digits = ''
    for c in cipher:
        if c in CHINESE_NUMS:
            digits += str(CHINESE_NUMS.index(c))
        elif c in CHINESE_NUMS_UPPER:
            digits += str(CHINESE_NUMS_UPPER.index(c))
    out = bytearray()
    for i in range(0, len(digits) - 2, 3):
        out.append(int(digits[i:i + 3]))
    return out.decode('utf-8', errors='replace')


# ═══════════════════════════════════════════
# 注册表
# ═══════════════════════════════════════════

CIPHERS = {
    "whitespace": {"name": "Whitespace", "aliases": ["whitespace", "空白语言"], "category": "esoteric语言"},
    "deadfish": {"name": "Deadfish", "aliases": ["deadfish", "死鱼"], "category": "esoteric语言"},
    "spoon": {"name": "Spoon(Brainfuck)", "aliases": ["spoon", "勺子"], "category": "esoteric语言"},
    "lolcode": {"name": "LOLCODE", "aliases": ["lolcode", "lol"], "category": "esoteric语言"},
    "chinese_num": {"name": "汉字数字", "aliases": ["chinese_num", "汉字数字", "中文数字"], "category": "中文特色密码"},
}

_FUNCS = {
    "whitespace": (whitespace_encode, whitespace_decode),
    "deadfish": (deadfish_encode, deadfish_decode),
    "spoon": (spoon_encode, spoon_decode),
    "lolcode": (lolcode_encode, lolcode_decode),
    "chinese_num": (chinese_num_encode, chinese_num_decode),
}


def _norm(cipher_id: str) -> str:
    cid = cipher_id.lower().replace('-', '_').replace(' ', '_')
    alias_map = {}
    for cid_key, info in CIPHERS.items():
        for a in info.get("aliases", []):
            alias_map[a.lower().replace('-', '_').replace(' ', '_')] = cid_key
    return alias_map.get(cid, cid)


def encode(cipher_id: str, text: str, key: str = "", **kwargs) -> str:
    cid = _norm(cipher_id)
    if cid in _FUNCS:
        return _FUNCS[cid][0](text)
    return f"[!] 不支持编码: {cipher_id}"


def decode(cipher_id: str, cipher_text: str, key: str = "", **kwargs) -> str:
    cid = _norm(cipher_id)
    if cid in _FUNCS:
        return _FUNCS[cid][1](cipher_text)
    return f"[!] 不支持解码: {cipher_id}"


def list_ciphers(category: str = None) -> list:
    result = []
    for cid, info in CIPHERS.items():
        if category and info.get("category") != category:
            continue
        result.append({"id": cid, **info})
    return result


def get_cipher(cipher_id: str) -> dict:
    return CIPHERS.get(_norm(cipher_id))


def search_ciphers(query: str) -> list:
    q = query.lower()
    out = []
    for cid, info in CIPHERS.items():
        text = cid + " " + info["name"] + " " + " ".join(info.get("aliases", [])) + " " + info["category"]
        if q in text.lower():
            out.append({"id": cid, **info})
    return out


def get_categories() -> list:
    return sorted({info["category"] for info in CIPHERS.values()})
