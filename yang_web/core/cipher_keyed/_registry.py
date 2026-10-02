"""yang_web.core.cipher_keyed 子模块 _registry（自 cipher_keyed.py 拆分，请勿手工重排）。"""

import base64
import hashlib
import hmac as hmac_mod
import re
from math import gcd
try:
    from .. import crypto_engine
except Exception:
    import crypto_engine

from ._fractionated import (adfgvx_decode, adfgvx_encode, bifid_decode, bifid_encode, fenham_decode, fenham_encode, foursquare_decode, foursquare_encode, fractionated_morse_decode, fractionated_morse_encode, kamasutra_decode, kamasutra_encode, nihilist_decode, nihilist_encode)
from ._machine import (enigma_decode, enigma_encode, fernet_decode, fernet_encode)
from ._matrix import (hill_decode, hill_encode)
from ._poly import (autokey_decode, autokey_encode, bazeries_decode, bazeries_encode, beaufort_decode, beaufort_encode, gronsfeld_decode, gronsfeld_encode, porta_decode, porta_encode, running_key_decode, running_key_encode)
from ._simple import (affine_decode, affine_encode, keyword_decode, keyword_encode, multiplicative_decode, multiplicative_encode, otp_decode, otp_encode, simple_substitution_decode, simple_substitution_encode)
from ._transposition import (coltrans_decode, coltrans_encode, column_permutation_decode, column_permutation_encode, rows_permutation_decode, rows_permutation_encode, scytale_decode, scytale_encode)



# ═══════════════════════════════════════════════════════════
# 注册表
# ═══════════════════════════════════════════════════════════

CIPHERS = {
    "affine": {"name": "仿射密码", "aliases": ["affine", "仿射"], "category": "带key密码", "key_hint": "a,b (a与26互质)"},
    "multiplicative": {"name": "乘法密码", "aliases": ["multiplicative", "乘法"], "category": "带key密码", "key_hint": "a (与26互质)"},
    "otp": {"name": "一次一密OTP", "aliases": ["otp", "one_time_pad", "一次一密"], "category": "带key密码", "key_hint": "密钥"},
    "hill": {"name": "希尔Hill", "aliases": ["hill", "希尔"], "category": "多key密码", "key_hint": "矩阵 (如 3,3,2,5)"},
    "gronsfeld": {"name": "Gronsfeld", "aliases": ["gronsfeld"], "category": "带key密码", "key_hint": "数字串"},
    "beaufort": {"name": "博福特Beaufort", "aliases": ["beaufort", "博福特"], "category": "带key密码", "key_hint": "密钥词"},
    "autokey": {"name": "自动密钥Autokey", "aliases": ["autokey", "自动密钥"], "category": "带key密码", "key_hint": "初始密钥"},
    "bifid": {"name": "双密码Bifid", "aliases": ["bifid", "双密码"], "category": "多key密码", "key_hint": "密钥词(可选)"},
    "foursquare": {"name": "四方密码", "aliases": ["foursquare", "四方"], "category": "多key密码", "key_hint": "key1,key2"},
    "scytale": {"name": "斯巴达Scytale", "aliases": ["scytale", "斯巴达", "caesar_box"], "category": "带key密码", "key_hint": "列数"},
    "nihilist": {"name": "Nihilist", "aliases": ["nihilist"], "category": "带key密码", "key_hint": "密钥词"},
    "keyword": {"name": "关键字KeywordCipher", "aliases": ["keyword", "关键字", "keyword_cipher"], "category": "带key密码", "key_hint": "关键字"},
    "simple_substitution": {"name": "简单替换", "aliases": ["simple_substitution", "简单替换", "monoalphabetic"], "category": "带key密码", "key_hint": "26字母替换表"},
    "coltrans": {"name": "列移位ColTrans", "aliases": ["coltrans", "列移位", "columnar_transposition"], "category": "带key密码", "key_hint": "密钥词"},
    "column_permutation": {"name": "列置换", "aliases": ["column_permutation", "列置换"], "category": "带key密码", "key_hint": "密钥词"},
    "rows_permutation": {"name": "行置换", "aliases": ["rows_permutation", "行置换"], "category": "带key密码", "key_hint": "密钥词"},
    "porta": {"name": "城门Porta", "aliases": ["porta", "城门"], "category": "带key密码", "key_hint": "密钥词"},
    "bazeries": {"name": "Bazeries", "aliases": ["bazeries"], "category": "带key密码", "key_hint": "数字串"},
    "fractionated_morse": {"name": "分组摩斯", "aliases": ["fractionated_morse", "分组摩斯"], "category": "带key密码", "key_hint": "密钥词"},
    "fenham": {"name": "费娜姆Fenham", "aliases": ["fenham", "费娜姆"], "category": "带key密码", "key_hint": "密钥词"},
    "running_key": {"name": "滚动密钥", "aliases": ["running_key", "滚动密钥", "running"], "category": "带key密码", "key_hint": "长密钥"},
    "kamasutra": {"name": "爱经Kamasutra", "aliases": ["kamasutra", "爱经"], "category": "带key密码", "key_hint": "无"},
    "fernet": {"name": "Fernet", "aliases": ["fernet"], "category": "带key密码", "key_hint": "32字节base64"},
    "enigma": {"name": "恩尼格玛Enigma M3", "aliases": ["enigma", "恩尼格玛", "enigma_m3"], "category": "多key密码", "key_hint": "如 I II III,AAA|B"},
    "adfgvx": {"name": "ADFGVX", "aliases": ["adfgvx"], "category": "多key密码", "key_hint": "密钥词"},
}

_FUNCS = {
    "affine": (affine_encode, affine_decode),
    "multiplicative": (multiplicative_encode, multiplicative_decode),
    "otp": (otp_encode, otp_decode),
    "hill": (hill_encode, hill_decode),
    "gronsfeld": (gronsfeld_encode, gronsfeld_decode),
    "beaufort": (beaufort_encode, beaufort_decode),
    "autokey": (autokey_encode, autokey_decode),
    "bifid": (bifid_encode, bifid_decode),
    "foursquare": (foursquare_encode, foursquare_decode),
    "scytale": (scytale_encode, scytale_decode),
    "nihilist": (nihilist_encode, nihilist_decode),
    "keyword": (keyword_encode, keyword_decode),
    "simple_substitution": (simple_substitution_encode, simple_substitution_decode),
    "coltrans": (coltrans_encode, coltrans_decode),
    "column_permutation": (column_permutation_encode, column_permutation_decode),
    "rows_permutation": (rows_permutation_encode, rows_permutation_decode),
    "porta": (porta_encode, porta_decode),
    "bazeries": (bazeries_encode, bazeries_decode),
    "fractionated_morse": (fractionated_morse_encode, fractionated_morse_decode),
    "fenham": (fenham_encode, fenham_decode),
    "running_key": (running_key_encode, running_key_decode),
    "kamasutra": (kamasutra_encode, kamasutra_decode),
    "fernet": (fernet_encode, fernet_decode),
    "enigma": (enigma_encode, enigma_decode),
    "adfgvx": (adfgvx_encode, adfgvx_decode),
}


def _norm(cipher_id):
    cid = cipher_id.lower().replace('-', '_').replace(' ', '_')
    alias_map = {}
    for cid_key, info in CIPHERS.items():
        for a in info.get("aliases", []):
            alias_map[a.lower().replace('-', '_').replace(' ', '_')] = cid_key
    return alias_map.get(cid, cid)


def encode(cipher_id, text, key="", **kwargs):
    cid = _norm(cipher_id)
    k = kwargs.get("key", key)
    if cid in _FUNCS:
        return _FUNCS[cid][0](text, k)
    return f"[!] 不支持编码: {cipher_id}"


def decode(cipher_id, cipher_text, key="", **kwargs):
    cid = _norm(cipher_id)
    k = kwargs.get("key", key)
    if cid in _FUNCS:
        return _FUNCS[cid][1](cipher_text, k)
    return f"[!] 不支持解码: {cipher_id}"


def list_ciphers(category=None):
    result = []
    for cid, info in CIPHERS.items():
        if category and info.get("category") != category:
            continue
        result.append({"id": cid, **info})
    return result


def get_cipher(cipher_id):
    return CIPHERS.get(_norm(cipher_id))


def search_ciphers(query):
    q = query.lower()
    out = []
    for cid, info in CIPHERS.items():
        text = cid + " " + info["name"] + " " + " ".join(info.get("aliases", [])) + " " + info["category"]
        if q in text.lower():
            out.append({"id": cid, **info})
    return out


def get_categories():
    return sorted({info["category"] for info in CIPHERS.values()})
