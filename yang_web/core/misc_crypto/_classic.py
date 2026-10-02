"""yang_web.core.misc_crypto 子模块 _classic（自 misc_crypto.py 拆分，请勿手工重排）。"""

import os
import re
import base64 as b64
import binascii
import html as html_mod
import codecs
import urllib.parse
from pathlib import Path

from ._data import (BACON_24, CHESSBOARD_DECODE, KEYBOARD_CHESSBOARD, PAWNSHOP_MAP, PAWNSHOP_REV, PHONE_DECODE, PHONE_KEYPAD, PIGPEN_ENCODE, POLYBIUS_GRID, QWE_DECODE, QWE_ENCODE, SGA_CHARS, SGA_DECODE)
from ._util import (_clean_text)



# ── 猪圈密码 ──────────────────────────────
def pigpen_encode(text: str) -> str:
    """将字母编码为猪圈密码符号（用 ASCII 近似表示）。"""
    result = []
    for c in _clean_text(text):
        if c in PIGPEN_ENCODE:
            result.append(PIGPEN_ENCODE[c])
        else:
            result.append(c)
    return ' '.join(result)


def pigpen_decode(symbols: str) -> str:
    """猪圈密码符号 → 字母（仅支持预定义字符）。"""
    rev = {v: k for k, v in PIGPEN_ENCODE.items()}
    # Try splitting by common separators
    for sep in [' ', '|', '/']:
        if sep in symbols:
            parts = symbols.split(sep)
            return ''.join(rev.get(p.strip(), p.strip()) for p in parts if p.strip())
    return symbols  # can't auto-parse


# ── 培根密码 ──────────────────────────────
def bacon_encode(text: str) -> str:
    return ' '.join(BACON_24.get(c, c) for c in _clean_text(text))


def bacon_decode(cipher_text: str) -> str:
    rev = {v: k for k, v in BACON_24.items()}
    result = []
    parts = cipher_text.replace(' ', '').lower()
    for i in range(0, len(parts) - 4, 5):
        chunk = parts[i:i+5].upper()
        result.append(rev.get(chunk, '?'))
    return ''.join(result)


# ── Polybius 棋盘 ─────────────────────────
def polybius_encode(text: str) -> str:
    result = []
    for c in _clean_text(text):
        if c == 'J': c = 'I'
        for row in range(5):
            for col in range(5):
                if POLYBIUS_GRID[row][col] == c:
                    result.append(f"{row+1}{col+1}")
                    break
    return ' '.join(result)


def polybius_decode(cipher_text: str) -> str:
    result = []
    nums = [n for n in cipher_text.replace(' ', '') if n.isdigit()]
    for i in range(0, len(nums) - 1, 2):
        row = int(nums[i]) - 1
        col = int(nums[i+1]) - 1
        if 0 <= row < 5 and 0 <= col < 5:
            result.append(POLYBIUS_GRID[row][col])
    return ''.join(result)


# ── 维吉尼亚密码 ─────────────────────────
def vigenere_encode(text: str, key: str) -> str:
    text, key = text.upper(), key.upper()
    result = []
    ki = 0
    for c in text:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - 65
            result.append(chr((ord(c) - 65 + shift) % 26 + 65))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)


def vigenere_decode(cipher_text: str, key: str) -> str:
    text, key = cipher_text.upper(), key.upper()
    result = []
    ki = 0
    for c in text:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - 65
            result.append(chr((ord(c) - 65 - shift) % 26 + 65))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)


# ── QWE 键盘 ──────────────────────────────
def qwe_encode(text: str) -> str:
    return ''.join(QWE_ENCODE.get(c, c) for c in _clean_text(text))


def qwe_decode(cipher_text: str) -> str:
    return ''.join(QWE_DECODE.get(c, c) for c in _clean_text(cipher_text))


# ── 键盘棋盘 ──────────────────────────────
def keyboard_chess_encode(text: str) -> str:
    return ' '.join(KEYBOARD_CHESSBOARD.get(c, '??') for c in _clean_text(text))


def keyboard_chess_decode(cipher_text: str) -> str:
    parts = cipher_text.split()
    return ''.join(CHESSBOARD_DECODE.get(p, '?') for p in parts)


# ── 手机键盘 ──────────────────────────────
def phone_encode(text: str) -> str:
    return ' '.join(PHONE_KEYPAD.get(c, '??') for c in _clean_text(text))


def phone_decode(cipher_text: str) -> str:
    parts = cipher_text.split()
    return ''.join(PHONE_DECODE.get(p, '?') for p in parts)


# ── 当铺密码 ─────────────────────────────
def pawnshat_encode(text: str) -> str:
    result = []
    for c in text:
        if c.isdigit() and int(c) in PAWNSHOP_REV:
            result.append(PAWNSHOP_REV[int(c)])
        else:
            result.append(c)
    return ' '.join(result)


def pawnshat_decode(cipher_text: str) -> str:
    result = []
    for c in cipher_text.replace(' ', ''):
        result.append(str(PAWNSHOP_MAP.get(c, c)))
    return ''.join(result)


# ── 字母表顺序 ────────────────────────────
def alphabet_order_encode(text: str) -> str:
    return ' '.join(str(ord(c) - 64) for c in _clean_text(text) if c.isalpha())


def alphabet_order_decode(cipher_text: str) -> str:
    result = []
    for n in cipher_text.split():
        try:
            result.append(chr(int(n) + 64))
        except ValueError:
            result.append('?')
    return ''.join(result)


# ── 标准银河字母 ─────────────────────────
def sga_encode(text: str) -> str:
    return ''.join(SGA_CHARS.get(c, c) for c in _clean_text(text))


def sga_decode(cipher_text: str) -> str:
    return ''.join(SGA_DECODE.get(c, c) for c in cipher_text)
