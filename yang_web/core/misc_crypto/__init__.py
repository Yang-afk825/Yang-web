# -*- coding: utf-8 -*-
"""Misc Crypto 知识库 — 常见密码类型编码/解码 + 参考图表.

覆盖 CTF Misc 方向 30+ 种常见密码/编码类型，提供编码/解码算法和视觉参考。
"""

import os
import re
import base64 as b64
import binascii
import html as html_mod
import codecs
import urllib.parse
from pathlib import Path

# 重导出全部原子符号，保持 `from yang_web.core.misc_crypto import X` 契约不变
from ._cipher_types import (CIPHER_TYPES)
from ._data import (DATA_DIR, EXTRA_MODULES, PIGPEN_ENCODE, BACON_24, POLYBIUS_GRID, KEYBOARD_ROWS, _QWE_ORDER, _ABC_ORDER, QWE_ENCODE, QWE_DECODE, KEYBOARD_CHESSBOARD, CHESSBOARD_DECODE, PHONE_KEYPAD, PHONE_DECODE, SGA_CHARS, SGA_DECODE, ADFGX_TABLE, PAWNSHOP_MAP, PAWNSHOP_REV, JEFFERSON_ROTORS, MORSE_ENCODE_MAP, MORSE_DECODE_MAP, _B58_ALPHABET, KEYBOARD_COORD_MAP, KEYBOARD_COORD_REV, NUMBER_COORD_MAP, NUMBER_COORD_REV, cipher_classic, cipher_keyed, chinese_ciphers2, esoteric_lang, binary_codes)
from ._util import (_clean_text, _pad_ext)
from ._classic import (pigpen_encode, pigpen_decode, bacon_encode, bacon_decode, polybius_encode, polybius_decode, vigenere_encode, vigenere_decode, qwe_encode, qwe_decode, keyboard_chess_encode, keyboard_chess_decode, phone_encode, phone_decode, pawnshat_encode, pawnshat_decode, alphabet_order_encode, alphabet_order_decode, sga_encode, sga_decode)
from ._cipher import (binary_encode, binary_decode, reverse_encode, reverse_decode, caesar_encode, caesar_decode, rot13_encode, rot13_decode, atbash_encode, atbash_decode, rail_fence_encode, rail_fence_decode, morse_encode, morse_decode, jefferson_decode)
from ._encoding import (base64_encode, base64_decode, base32_encode, base32_decode, base16_encode, base16_decode, base58_encode, base58_decode, base85_encode, base85_decode, url_encode, url_decode, html_encode, html_decode, unicode_encode, unicode_decode, binary_str_encode, binary_str_decode, octal_str_encode, octal_str_decode, decimal_str_encode, decimal_str_decode)
from ._coord import (keyboard_coordinate_encode, keyboard_coordinate_decode, number_coordinate_encode, number_coordinate_decode, _adfgx_polybius, adfgx_encode, adfgx_decode)
from ._registry import (list_ciphers, get_cipher, search_ciphers, get_image_path, get_image2_path, get_categories, encode, decode, get_text_path, get_text_content)
