# -*- coding: utf-8 -*-
"""cipher_keyed.py — 带 key / 多 key 古典密码

覆盖 CTF 高频带密钥密码，纯 Python 标准库零依赖实现。
API 风格与 misc_crypto.py 一致：
  - <name>_encode(text, key) / <name>_decode(cipher, key)
  - CIPHERS 注册表（每项标注 needs_key）
  - encode() / decode() 统一分发入口（key 通过 kwargs 传入）
"""

import base64
import hashlib
import hmac as hmac_mod
import re
from math import gcd
try:
    from .. import crypto_engine
except Exception:
    import crypto_engine

# 重导出全部原子符号，保持 `from yang_web.core.cipher_keyed import X` 契约不变
from ._common import (_modinv, _only_letters, _polybius_keyed, _keyword_alphabet)
from ._simple import (affine_encode, affine_decode, multiplicative_encode, multiplicative_decode, otp_encode, otp_decode, keyword_encode, keyword_decode, simple_substitution_encode, simple_substitution_decode)
from ._poly import (gronsfeld_encode, gronsfeld_decode, beaufort_encode, beaufort_decode, autokey_encode, autokey_decode, _PORTA, porta_encode, porta_decode, bazeries_encode, bazeries_decode, running_key_encode, running_key_decode)
from ._transposition import (_transposition_key_order, coltrans_encode, coltrans_decode, column_permutation_encode, column_permutation_decode, rows_permutation_encode, rows_permutation_decode, scytale_encode, scytale_decode)
from ._fractionated import (_MORSE, fractionated_morse_encode, fractionated_morse_decode, bifid_encode, bifid_decode, foursquare_encode, foursquare_decode, nihilist_encode, nihilist_decode, _KAMASUTRA_PAIRS, kamasutra_encode, kamasutra_decode, fenham_encode, fenham_decode, adfgvx_encode, adfgvx_decode)
from ._matrix import (_hill_matrix_from_key, _matrix_inv, hill_encode, hill_decode)
from ._machine import (_ROTORS, _REFLECTORS, _enigma_parse_key, _enigma_advance, _enigma_transform, enigma_encode, enigma_decode, fernet_encode, fernet_decode)
from ._registry import (CIPHERS, _FUNCS, _norm, encode, decode, list_ciphers, get_cipher, search_ciphers, get_categories)
