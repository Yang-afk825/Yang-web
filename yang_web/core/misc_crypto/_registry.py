"""yang_web.core.misc_crypto 子模块 _registry（自 misc_crypto.py 拆分，请勿手工重排）。"""

import os
import re
import base64 as b64
import binascii
import html as html_mod
import codecs
import urllib.parse
from pathlib import Path

from ._cipher import (atbash_decode, atbash_encode, binary_decode, binary_encode, caesar_decode, caesar_encode, jefferson_decode, morse_decode, morse_encode, rail_fence_decode, rail_fence_encode, reverse_decode, reverse_encode, rot13_decode, rot13_encode)
from ._cipher_types import (CIPHER_TYPES)
from ._classic import (alphabet_order_decode, alphabet_order_encode, bacon_decode, bacon_encode, keyboard_chess_decode, keyboard_chess_encode, pawnshat_decode, pawnshat_encode, phone_decode, phone_encode, pigpen_decode, pigpen_encode, polybius_decode, polybius_encode, qwe_decode, qwe_encode, sga_decode, sga_encode, vigenere_decode, vigenere_encode)
from ._coord import (adfgx_decode, adfgx_encode, keyboard_coordinate_decode, keyboard_coordinate_encode, number_coordinate_decode, number_coordinate_encode)
from ._data import (DATA_DIR, EXTRA_MODULES)
from ._encoding import (base16_decode, base16_encode, base32_decode, base32_encode, base58_decode, base58_encode, base64_decode, base64_encode, base85_decode, base85_encode, binary_str_decode, binary_str_encode, decimal_str_decode, decimal_str_encode, html_decode, html_encode, octal_str_decode, octal_str_encode, unicode_decode, unicode_encode, url_decode, url_encode)
from ._util import (_pad_ext)



# ═══════════════════════════════════════════
# 查询 & 工具函数
# ═══════════════════════════════════════════

def list_ciphers(category: str = None) -> list:
    """列出所有已注册的密码类型（含扩展的经典编码/带key密码）。"""
    result = []
    for cid, info in CIPHER_TYPES.items():
        if category and info.get("category") != category:
            continue
        result.append({
            "id": cid,
            **info,
        })
    for mod in EXTRA_MODULES:
        for c in mod.list_ciphers(category):
            result.append(_pad_ext(c))
    return result


def get_cipher(cipher_id: str) -> dict:
    """返回指定密码类型的完整信息。"""
    cid = cipher_id.lower()
    info = CIPHER_TYPES.get(cid)
    if info:
        return info
    for mod in EXTRA_MODULES:
        info = mod.get_cipher(cid)
        if info:
            return info
    return None


def search_ciphers(query: str) -> list:
    """按名称/别名搜索密码类型。"""
    q = query.lower()
    results = []
    for cid, info in CIPHER_TYPES.items():
        text = cid + " " + info["name"] + " " + " ".join(info.get("aliases", [])) + " " + info["category"]
        if q in text.lower():
            results.append({"id": cid, **info})
    for mod in EXTRA_MODULES:
        results.extend(_pad_ext(c) for c in mod.search_ciphers(query))
    return results


def get_image_path(cipher_id: str) -> str:
    """返回密码类型对应的参考图主图路径。"""
    info = CIPHER_TYPES.get(cipher_id.lower())
    if info and info.get("image"):
        img_path = DATA_DIR / info["image"]
        if img_path.exists():
            return str(img_path)
    return ""


def get_image2_path(cipher_id: str) -> str:
    """返回密码类型对应的参考图辅图路径（如有）。"""
    info = CIPHER_TYPES.get(cipher_id.lower())
    if info and info.get("image2"):
        img_path = DATA_DIR / info["image2"]
        if img_path.exists():
            return str(img_path)
    return ""


def get_categories() -> list:
    """返回所有类别。"""
    cats = set()
    for info in CIPHER_TYPES.values():
        cats.add(info["category"])
    for mod in EXTRA_MODULES:
        cats.update(mod.get_categories())
    return sorted(cats)


def encode(cipher_id: str, text: str, **kwargs) -> str:
    """通用编码入口。"""
    cid = cipher_id.lower().replace('-', '_').replace(' ', '_')
    funcs = {
        # 基础编码
        "base64": base64_encode,
        "base32": base32_encode,
        "base16": base16_encode, "hex": base16_encode,
        "base58": base58_encode,
        "base85": base85_encode,
        "url_encode": url_encode, "url": url_encode, "urlencode": url_encode,
        "html_entity": html_encode, "html": html_encode, "entity": html_encode,
        "unicode_escape": unicode_encode, "unicode": unicode_encode, "uescape": unicode_encode,
        "binary_str": binary_str_encode,
        "octal_str": octal_str_encode, "octal": octal_str_encode, "oct": octal_str_encode,
        "decimal_str": decimal_str_encode, "decimal": decimal_str_encode, "dec": decimal_str_encode,
        # 经典密码
        "pigpen": pigpen_encode,
        "bacon": bacon_encode, "baconian": bacon_encode,
        "polybius": polybius_encode, "polybius_square": polybius_encode,
        "vigenere": lambda t: vigenere_encode(t, kwargs.get("key", "A")),
        "caesar": lambda t: caesar_encode(t, kwargs.get("key", "3")),
        "rot13": rot13_encode,
        "atbash": atbash_encode,
        "rail_fence": lambda t: rail_fence_encode(t, kwargs.get("key", "3")),
        "morse": morse_encode,
        "qwe": qwe_encode, "qwe_keyboard": qwe_encode,
        "keyboard_chessboard": keyboard_chess_encode,
        "keyboard_coordinate": keyboard_coordinate_encode,
        "number_coordinate": number_coordinate_encode,
        "phone": phone_encode, "phone_keypad": phone_encode,
        "alphabet_order": alphabet_order_encode,
        "sga": sga_encode, "standard_galactic": sga_encode,
        "binary": binary_encode,
        "reverse": reverse_encode,
        "pawnshat": pawnshat_encode,
        "adfgx": lambda t: adfgx_encode(t, kwargs.get("key", "")),
        "jefferson_wheel": lambda t: jefferson_decode(t, kwargs.get("key", []), kwargs.get("rotors")),
    }
    if cid in funcs:
        return funcs[cid](text)
    # 扩展：经典编码 / 带key密码 / 中文特色 / esoteric 语言
    for mod in EXTRA_MODULES:
        if cid in mod._FUNCS:
            return mod.encode(cid, text, key=kwargs.get("key", ""))
    return f"[!] 不支持编码: {cipher_id}"


def decode(cipher_id: str, cipher_text: str, **kwargs) -> str:
    """通用解码入口。"""
    cid = cipher_id.lower().replace('-', '_').replace(' ', '_')
    funcs = {
        # 基础编码
        "base64": base64_decode,
        "base32": base32_decode,
        "base16": base16_decode, "hex": base16_decode,
        "base58": base58_decode,
        "base85": base85_decode,
        "url_encode": url_decode, "url": url_decode, "urlencode": url_decode,
        "html_entity": html_decode, "html": html_decode, "entity": html_decode,
        "unicode_escape": unicode_decode, "unicode": unicode_decode, "uescape": unicode_decode,
        "binary_str": binary_str_decode,
        "octal_str": octal_str_decode, "octal": octal_str_decode, "oct": octal_str_decode,
        "decimal_str": decimal_str_decode, "decimal": decimal_str_decode, "dec": decimal_str_decode,
        # 经典密码
        "pigpen": pigpen_decode,
        "bacon": bacon_decode, "baconian": bacon_decode,
        "polybius": polybius_decode, "polybius_square": polybius_decode,
        "vigenere": lambda t: vigenere_decode(t, kwargs.get("key", "A")),
        "caesar": lambda t: caesar_decode(t, kwargs.get("key", "3")),
        "rot13": rot13_decode,
        "atbash": atbash_decode,
        "rail_fence": lambda t: rail_fence_decode(t, kwargs.get("key", "3")),
        "morse": morse_decode,
        "qwe": qwe_decode, "qwe_keyboard": qwe_decode,
        "keyboard_chessboard": keyboard_chess_decode,
        "keyboard_coordinate": keyboard_coordinate_decode,
        "number_coordinate": number_coordinate_decode,
        "phone": phone_decode, "phone_keypad": phone_decode,
        "alphabet_order": alphabet_order_decode,
        "sga": sga_decode, "standard_galactic": sga_decode,
        "binary": binary_decode,
        "reverse": reverse_decode,
        "pawnshat": pawnshat_decode,
        "adfgx": lambda t: adfgx_decode(t, kwargs.get("key", "")),
        "jefferson_wheel": lambda t: jefferson_decode(t, kwargs.get("key", []), kwargs.get("rotors")),
    }
    if cid in funcs:
        return funcs[cid](cipher_text)
    # 扩展：经典编码 / 带key密码 / 中文特色 / esoteric 语言
    for mod in EXTRA_MODULES:
        if cid in mod._FUNCS:
            return mod.decode(cid, cipher_text, key=kwargs.get("key", ""))
    return f"[!] 不支持解码: {cipher_id}"


def get_text_path(cipher_id: str) -> str:
    """返回密码类型对应的说明文本文件路径（如有）。"""
    info = CIPHER_TYPES.get(cipher_id.lower())
    if not info:
        return ""
    name = info["name"]
    # Try common text file patterns
    candidates = [
        name + ".txt",
        name + "加密解密.txt",
        name + "加密解密法.txt",
        name + "编码.txt",
        name + ".txt",
    ]
    # Also try: binary -> 二进制, reverse -> 倒叙, etc.
    txt_map = {
        "jefferson_wheel": "托马斯杰斐逊 转轮密码.txt",
        "vigenere": "维吉尼亚.txt",
        "morse": "摩尔密码加密与解密.jpg",  # no txt, just image
    }
    if cipher_id.lower() in txt_map:
        target = DATA_DIR / txt_map[cipher_id.lower()]
        if target.exists():
            return str(target)
    for c in candidates:
        target = DATA_DIR / c
        if target.exists():
            return str(target)
    return ""


def get_text_content(cipher_id: str) -> str:
    """读取密码类型的说明文本内容。"""
    path = get_text_path(cipher_id)
    if path and path.endswith('.txt'):
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                return f.read()
        except Exception:
            try:
                with open(path, 'r', encoding='gbk', errors='replace') as f:
                    return f.read()
            except Exception:
                return ""
    return ""
