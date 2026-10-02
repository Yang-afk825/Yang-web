"""yang_web.core.cipher_keyed 子模块 _common（自 cipher_keyed.py 拆分，请勿手工重排）。"""

import base64
import hashlib
import hmac as hmac_mod
import re
from math import gcd
try:
    from .. import crypto_engine
except Exception:
    import crypto_engine





# ═══════════════════════════════════════════════════════════
# 工具函数
# ═══════════════════════════════════════════════════════════

def _modinv(a, m=26):
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


def _only_letters(text):
    return ''.join(c for c in text.upper() if 'A' <= c <= 'Z')


def _polybius_keyed(key=""):
    """生成 5x5 Polybius 字母表（默认无 key，I/J 合并）。"""
    base = _only_letters(key).replace('J', 'I')
    seen = set()
    grid = []
    for c in base + 'ABCDEFGHIKLMNOPQRSTUVWXYZ':  # 无 J
        if c not in seen:
            seen.add(c)
            grid.append(c)
    return ''.join(grid[:25])

# ---------- 关键字 KeywordCipher ----------
def _keyword_alphabet(key):
    base = _only_letters(key)
    seen = set()
    alpha = []
    for c in base:
        if c not in seen:
            seen.add(c)
            alpha.append(c)
    for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        if c not in seen:
            seen.add(c)
            alpha.append(c)
    return ''.join(alpha)
