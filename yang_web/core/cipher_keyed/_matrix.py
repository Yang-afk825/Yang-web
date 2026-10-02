"""yang_web.core.cipher_keyed 子模块 _matrix（自 cipher_keyed.py 拆分，请勿手工重排）。"""

import base64
import hashlib
import hmac as hmac_mod
import re
from math import gcd
try:
    from .. import crypto_engine
except Exception:
    import crypto_engine

from ._common import (_modinv, _only_letters)


# ---------- 希尔 Hill（2x2 / 3x3）----------
def _hill_matrix_from_key(key):
    key = str(key).strip().replace(' ', '')
    # 尝试解析为数字矩阵 "3,3,2,5" 或 "6,24,1,13,16,10,20,17,15"
    nums = re.findall(r'-?\d+', key)
    if len(nums) == 4:
        return [[int(nums[0]), int(nums[1])], [int(nums[2]), int(nums[3])]], 2
    if len(nums) == 9:
        m = [int(x) for x in nums]
        return [[m[0], m[1], m[2]], [m[3], m[4], m[5]], [m[6], m[7], m[8]]], 3
    # 否则用默认矩阵
    return [[3, 3], [2, 5]], 2

def _matrix_inv(matrix, n):
    if n == 2:
        a, b = matrix[0][0], matrix[0][1]
        c, d = matrix[1][0], matrix[1][1]
        det = (a * d - b * c) % 26
        inv = _modinv(det, 26)
        if inv is None:
            return None
        return [[(d * inv) % 26, (-b * inv) % 26], [(-c * inv) % 26, (a * inv) % 26]]
    # 3x3 逆矩阵
    m = matrix
    det = 0
    for i in range(3):
        det += m[0][i] * (m[1][(i + 1) % 3] * m[2][(i + 2) % 3] - m[1][(i + 2) % 3] * m[2][(i + 1) % 3])
    det %= 26
    inv = _modinv(det, 26)
    if inv is None:
        return None
    adj = [[0] * 3 for _ in range(3)]
    for i in range(3):
        for j in range(3):
            minor = [[m[r][c] for c in range(3) if c != j] for r in range(3) if r != i]
            cof = (minor[0][0] * minor[1][1] - minor[0][1] * minor[1][0])
            adj[j][i] = (cof * ((-1) ** (i + j))) % 26
    return [[(adj[i][j] * inv) % 26 for j in range(3)] for i in range(3)]

def hill_encode(text, key="3,3,2,5"):
    matrix, n = _hill_matrix_from_key(key)
    letters = _only_letters(text)
    while len(letters) % n != 0:
        letters += 'X'
    out = []
    for i in range(0, len(letters), n):
        block = [ord(c) - 65 for c in letters[i:i + n]]
        res = [sum(matrix[r][k] * block[k] for k in range(n)) % 26 for r in range(n)]
        out.extend(chr(x + 65) for x in res)
    return ''.join(out)

def hill_decode(cipher, key="3,3,2,5"):
    matrix, n = _hill_matrix_from_key(key)
    inv = _matrix_inv(matrix, n)
    if inv is None:
        return "[!] 矩阵不可逆（det 与 26 不互质）"
    letters = _only_letters(cipher)
    out = []
    for i in range(0, len(letters), n):
        block = [ord(c) - 65 for c in letters[i:i + n]]
        res = [sum(inv[r][k] * block[k] for k in range(n)) % 26 for r in range(n)]
        out.extend(chr(x + 65) for x in res)
    return ''.join(out)
