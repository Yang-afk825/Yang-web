"""yang_web.core.misc_crypto 子模块 _cipher（自 misc_crypto.py 拆分，请勿手工重排）。"""

import os
import re
import base64 as b64
import binascii
import html as html_mod
import codecs
import urllib.parse
from pathlib import Path

from ._data import (JEFFERSON_ROTORS, MORSE_DECODE_MAP, MORSE_ENCODE_MAP)



# ── 二进制 ────────────────────────────────
def binary_encode(text: str) -> str:
    return ' '.join(f"{ord(c):08b}" for c in text)


def binary_decode(cipher_text: str) -> str:
    clean = cipher_text.replace(' ', '').replace('\n', '').replace('\r', '').strip()
    if not clean:
        return ''
    result = []
    # Try space-separated first
    parts = cipher_text.strip().split()
    if len(parts) > 1:
        for b in parts:
            try:
                val = int(b, 2)
                if 0 <= val <= 0x10FFFF:
                    result.append(chr(val))
            except (ValueError, OverflowError):
                pass
        if result:
            return ''.join(result)
    # Try 8-bit or 7-bit chunks
    for width in [8, 7]:
        result = []
        for i in range(0, len(clean), width):
            chunk = clean[i:i+width]
            if len(chunk) < width:
                continue
            try:
                val = int(chunk, 2)
                if 0 <= val <= 0x10FFFF:
                    result.append(chr(val))
            except (ValueError, OverflowError):
                pass
        if result:
            return ''.join(result)
    return cipher_text


# ── 倒序 ──────────────────────────────────
def reverse_encode(text: str) -> str:
    return text[::-1]


def reverse_decode(cipher_text: str) -> str:
    return cipher_text[::-1]  # self-inverse


# ── Caesar 凯撒 ────────────────────────────
def caesar_encode(text: str, key: str = "3") -> str:
    try:
        shift = int(key) % 26
    except ValueError:
        shift = sum(ord(c) for c in key) % 26
    result = []
    for c in text:
        if 'A' <= c <= 'Z':
            result.append(chr((ord(c) - ord('A') + shift) % 26 + ord('A')))
        elif 'a' <= c <= 'z':
            result.append(chr((ord(c) - ord('a') + shift) % 26 + ord('a')))
        else:
            result.append(c)
    return ''.join(result)


def caesar_decode(cipher_text: str, key: str = "3") -> str:
    try:
        shift = int(key) % 26
    except ValueError:
        shift = sum(ord(c) for c in key) % 26
    return caesar_encode(cipher_text, str(26 - shift))


# ── ROT13 ──────────────────────────────────
def rot13_encode(text: str) -> str:
    return caesar_encode(text, "13")


def rot13_decode(cipher_text: str) -> str:
    return caesar_encode(cipher_text, "13")


# ── Atbash 埃特巴什 ─────────────────────────
def atbash_encode(text: str) -> str:
    result = []
    for c in text:
        if 'A' <= c <= 'Z':
            result.append(chr(ord('Z') - (ord(c) - ord('A'))))
        elif 'a' <= c <= 'z':
            result.append(chr(ord('z') - (ord(c) - ord('a'))))
        else:
            result.append(c)
    return ''.join(result)


def atbash_decode(cipher_text: str) -> str:
    return atbash_encode(cipher_text)  # self-inverse


# ── Rail Fence 栅栏 ────────────────────────
def rail_fence_encode(text: str, key: str = "3") -> str:
    try:
        rails = max(2, int(key))
    except ValueError:
        rails = 3
    if rails >= len(text):
        return text
    fence = [[] for _ in range(rails)]
    rail, direction = 0, 1
    for c in text:
        fence[rail].append(c)
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction = -direction
    return ''.join(''.join(row) for row in fence)


def rail_fence_decode(cipher_text: str, key: str = "3") -> str:
    try:
        rails = max(2, int(key))
    except ValueError:
        rails = 3
    if rails >= len(cipher_text):
        return cipher_text
    n = len(cipher_text)
    # Build fence pattern
    pattern = []
    rail, direction = 0, 1
    for _ in range(n):
        pattern.append(rail)
        rail += direction
        if rail == 0 or rail == rails - 1:
            direction = -direction
    # Count chars per rail
    counts = [0] * rails
    for r in pattern:
        counts[r] += 1
    # Slice cipher text by rail
    rails_text = []
    idx = 0
    for cnt in counts:
        rails_text.append(cipher_text[idx:idx+cnt])
        idx += cnt
    # Reconstruct
    pointers = [0] * rails
    result = []
    for r in pattern:
        result.append(rails_text[r][pointers[r]])
        pointers[r] += 1
    return ''.join(result)


def morse_encode(text: str) -> str:
    result = []
    for c in text.upper():
        if c == ' ':
            result.append('/')
        elif c in MORSE_ENCODE_MAP:
            result.append(MORSE_ENCODE_MAP[c])
        else:
            result.append(c)
    return ' '.join(result)


def morse_decode(cipher_text: str) -> str:
    result = []
    for token in cipher_text.strip().split():
        if token == '/':
            result.append(' ')
        elif token in MORSE_DECODE_MAP:
            result.append(MORSE_DECODE_MAP[token])
        else:
            result.append('?')
    return ''.join(result)


# ── 杰斐逊转轮 ───────────────────────────
def jefferson_decode(cipher_text: str, key: list, rotors: list = None) -> list:
    """托马斯·杰斐逊转轮密码解码，返回所有可能的明文。"""
    if rotors is None:
        rotors = JEFFERSON_ROTORS
    tmp_list = []
    for i in range(len(rotors)):
        k = key[i] - 1
        rotor = rotors[k]
        target = cipher_text[i] if i < len(cipher_text) else cipher_text[-1]
        for j in range(len(rotor)):
            if target.upper() == rotor[j]:
                tmp = rotor[j:] + rotor[:j] if j > 0 else rotor
                tmp_list.append(tmp)
                break
    # Build column strings
    messages = []
    col_len = min(len(t) for t in tmp_list)
    for i in range(col_len):
        col = ''.join(t[i] for t in tmp_list)
        messages.append(col)
    return messages
