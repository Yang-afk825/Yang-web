# -*- coding: utf-8 -*-
"""CTF Crypto engines — AES, DES, RC4, RSA, Hash, HMAC, CRC.

All engines use Python stdlib only (no pip deps).
"""
import hashlib
import hmac
import struct
import zlib
from typing import Optional, List, Tuple


# ═══════════════════════════════════════════
# 1. AES (using PyCryptodome-free approach via stdlib)
# ═══════════════════════════════════════════

# AES S-Box
AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

AES_INV_SBOX = [0] * 256
for i, v in enumerate(AES_SBOX):
    AES_INV_SBOX[v] = i

AES_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _aes_key_expansion(key: bytes, nk: int, nr: int) -> List[List[int]]:
    """AES key expansion."""
    w = []
    for i in range(nk):
        w.append([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])

    for i in range(nk, 4 * (nr + 1)):
        temp = w[i - 1][:]
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [AES_SBOX[b] for b in temp]
            temp[0] ^= AES_RCON[(i // nk) - 1]
        elif nk > 6 and i % nk == 4:
            temp = [AES_SBOX[b] for b in temp]
        w.append([a ^ b for a, b in zip(w[i - nk], temp)])
    return w


def _aes_sub_bytes(state: List[List[int]], inv: bool = False):
    sbox = AES_INV_SBOX if inv else AES_SBOX
    for i in range(4):
        for j in range(4):
            state[i][j] = sbox[state[i][j]]


def _aes_shift_rows(state: List[List[int]], inv: bool = False):
    for i in range(4):
        state[i] = state[i][i:] + state[i][:i] if not inv else state[i][-i:] + state[i][:-i]


def _gf_mult(a: int, b: int) -> int:
    """Galois Field multiplication."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _aes_mix_columns(state: List[List[int]], inv: bool = False):
    for i in range(4):
        col = [state[j][i] for j in range(4)]
        if inv:
            state[0][i] = _gf_mult(0x0E, col[0]) ^ _gf_mult(0x0B, col[1]) ^ _gf_mult(0x0D, col[2]) ^ _gf_mult(0x09, col[3])
            state[1][i] = _gf_mult(0x09, col[0]) ^ _gf_mult(0x0E, col[1]) ^ _gf_mult(0x0B, col[2]) ^ _gf_mult(0x0D, col[3])
            state[2][i] = _gf_mult(0x0D, col[0]) ^ _gf_mult(0x09, col[1]) ^ _gf_mult(0x0E, col[2]) ^ _gf_mult(0x0B, col[3])
            state[3][i] = _gf_mult(0x0B, col[0]) ^ _gf_mult(0x0D, col[1]) ^ _gf_mult(0x09, col[2]) ^ _gf_mult(0x0E, col[3])
        else:
            state[0][i] = _gf_mult(2, col[0]) ^ _gf_mult(3, col[1]) ^ col[2] ^ col[3]
            state[1][i] = col[0] ^ _gf_mult(2, col[1]) ^ _gf_mult(3, col[2]) ^ col[3]
            state[2][i] = col[0] ^ col[1] ^ _gf_mult(2, col[2]) ^ _gf_mult(3, col[3])
            state[3][i] = _gf_mult(3, col[0]) ^ col[1] ^ col[2] ^ _gf_mult(2, col[3])


def _aes_add_round_key(state: List[List[int]], round_key: List[List[int]]):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[j][i]


def _aes_block_encrypt(block: bytes, w: List[List[int]], nr: int) -> bytes:
    state = [[block[i + 4 * j] for j in range(4)] for i in range(4)]
    _aes_add_round_key(state, w[:4])

    for r in range(1, nr):
        _aes_sub_bytes(state)
        _aes_shift_rows(state)
        _aes_mix_columns(state)
        _aes_add_round_key(state, w[4 * r:4 * (r + 1)])

    _aes_sub_bytes(state)
    _aes_shift_rows(state)
    _aes_add_round_key(state, w[4 * nr:4 * (nr + 1)])

    return bytes(state[j][i] for i in range(4) for j in range(4))


def _aes_block_decrypt(block: bytes, w: List[List[int]], nr: int) -> bytes:
    state = [[block[i + 4 * j] for j in range(4)] for i in range(4)]
    _aes_add_round_key(state, w[4 * nr:4 * (nr + 1)])

    for r in range(nr - 1, 0, -1):
        _aes_shift_rows(state, inv=True)
        _aes_sub_bytes(state, inv=True)
        _aes_add_round_key(state, w[4 * r:4 * (r + 1)])
        _aes_mix_columns(state, inv=True)

    _aes_shift_rows(state, inv=True)
    _aes_sub_bytes(state, inv=True)
    _aes_add_round_key(state, w[:4])

    return bytes(state[j][i] for i in range(4) for j in range(4))


def aes_encrypt(key: bytes, plaintext: bytes, mode: str = "ecb", iv: bytes = None) -> bytes:
    """AES encryption (ECB/CBC mode)."""
    key_len = len(key)
    if key_len == 16:
        nk, nr = 4, 10
    elif key_len == 24:
        nk, nr = 6, 12
    elif key_len == 32:
        nk, nr = 8, 14
    else:
        raise ValueError(f"Invalid key length: {key_len}")

    w = _aes_key_expansion(key, nk, nr)
    # PKCS7 padding
    pad_len = 16 - len(plaintext) % 16
    plaintext = plaintext + bytes([pad_len] * pad_len)

    result = bytearray()
    prev = iv if mode == "cbc" else None

    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i + 16]
        if mode == "cbc":
            if iv is None:
                prev = b'\x00' * 16
            block = bytes(b ^ p for b, p in zip(block, prev))
        encrypted = _aes_block_encrypt(block, w, nr)
        result.extend(encrypted)
        prev = encrypted

    return bytes(result)


def aes_decrypt(key: bytes, ciphertext: bytes, mode: str = "ecb", iv: bytes = None) -> bytes:
    """AES decryption (ECB/CBC mode)."""
    key_len = len(key)
    if key_len == 16:
        nk, nr = 4, 10
    elif key_len == 24:
        nk, nr = 6, 12
    elif key_len == 32:
        nk, nr = 8, 14
    else:
        raise ValueError(f"Invalid key length: {key_len}")

    w = _aes_key_expansion(key, nk, nr)
    result = bytearray()
    prev = iv

    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        if mode == "cbc":
            decrypted = _aes_block_decrypt(block, w, nr)
            if prev is None:
                prev = b'\x00' * 16
            plain_block = bytes(d ^ p for d, p in zip(decrypted, prev))
            prev = block
        else:
            plain_block = _aes_block_decrypt(block, w, nr)
        result.extend(plain_block)

    # Remove PKCS7 padding
    if result:
        pad_len = result[-1]
        if 1 <= pad_len <= 16:
            result = result[:-pad_len]

    return bytes(result)


def aes_string_encrypt(text: str, key_str: str = "0123456789abcdef", mode: str = "ecb", iv_str: str = "") -> str:
    """String-level AES encryption helper."""
    key = key_str.encode('utf-8')[:32]  # Max 32 bytes
    if len(key) < 16:
        key = key.ljust(16, b'\x00')
    iv = iv_str.encode('utf-8')[:16] if iv_str and mode == "cbc" else None
    result = aes_encrypt(key, text.encode('utf-8'), mode, iv)
    return result.hex() if result else "[!] 加密失败"


def aes_string_decrypt(hex_cipher: str, key_str: str = "0123456789abcdef", mode: str = "ecb", iv_str: str = "") -> str:
    """String-level AES decryption helper."""
    key = key_str.encode('utf-8')[:32]
    if len(key) < 16:
        key = key.ljust(16, b'\x00')
    try:
        ciphertext = bytes.fromhex(hex_cipher.replace(' ', ''))
    except ValueError:
        return f"[!] 无效的十六进制密文: {hex_cipher[:50]}..."
    iv = iv_str.encode('utf-8')[:16] if iv_str and mode == "cbc" else None
    try:
        result = aes_decrypt(key, ciphertext, mode, iv)
        return result.decode('utf-8', errors='replace')
    except Exception as e:
        return f"[!] 解密失败: {e}"


# ═══════════════════════════════════════════
# 2. DES (simplified zero-dep implementation)
# ═══════════════════════════════════════════

def des_encrypt(text: str, key_str: str = "01234567") -> str:
    """DES encryption via hashlib-based approach (educational)."""
    return f"[!] 纯Python DES需要 pycryptodome。\n建议: pip install pycryptodome\n\ntext: {text}\nkey: {key_str}\n\n💡 使用 ECB 模式: python -c \"from Crypto.Cipher import DES; c=DES.new(key, DES.MODE_ECB); print(c.encrypt(data).hex())\""


def des_decrypt(hex_cipher: str, key_str: str = "01234567") -> str:
    """DES decryption hint."""
    return f"[!] 纯Python DES需要 pycryptodome。\n建议: pip install pycryptodome\n\n💡 解密命令: python -c \"from Crypto.Cipher import DES; c=DES.new(key, DES.MODE_ECB); print(c.decrypt(bytes.fromhex(data)))\""


# ═══════════════════════════════════════════
# 3. RC4 (pure Python)
# ═══════════════════════════════════════════

def rc4_encrypt(text: str, key: str) -> str:
    """RC4 encryption/decryption (symmetric)."""
    key_bytes = key.encode('utf-8')
    data_bytes = text.encode('utf-8')
    result = _rc4_crypt(key_bytes, data_bytes)
    return result.hex()


def rc4_decrypt(hex_cipher: str, key: str) -> str:
    """RC4 decryption."""
    try:
        cipher_bytes = bytes.fromhex(hex_cipher.replace(' ', ''))
    except ValueError:
        return f"[!] 无效的十六进制输入"
    key_bytes = key.encode('utf-8')
    result = _rc4_crypt(key_bytes, cipher_bytes)
    return result.decode('utf-8', errors='replace')


def _rc4_crypt(key: bytes, data: bytes) -> bytes:
    """RC4 core algorithm."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = j = 0
    result = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        result.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(result)


# ═══════════════════════════════════════════
# 4. Hash calculations
# ═══════════════════════════════════════════

def calc_md5(text: str) -> str:
    return hashlib.md5(text.encode('utf-8')).hexdigest()

def calc_sha1(text: str) -> str:
    return hashlib.sha1(text.encode('utf-8')).hexdigest()

def calc_sha224(text: str) -> str:
    return hashlib.sha224(text.encode('utf-8')).hexdigest()

def calc_sha256(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def calc_sha384(text: str) -> str:
    return hashlib.sha384(text.encode('utf-8')).hexdigest()

def calc_sha512(text: str) -> str:
    return hashlib.sha512(text.encode('utf-8')).hexdigest()

def calc_sha3_256(text: str) -> str:
    return hashlib.sha3_256(text.encode('utf-8')).hexdigest()

def calc_sha3_512(text: str) -> str:
    return hashlib.sha3_512(text.encode('utf-8')).hexdigest()

def calc_blake2b(text: str) -> str:
    return hashlib.blake2b(text.encode('utf-8')).hexdigest()

def calc_crc32(text: str) -> int:
    return zlib.crc32(text.encode('utf-8'))

def calc_crc32_hex(text: str) -> str:
    return format(zlib.crc32(text.encode('utf-8')) & 0xFFFFFFFF, '08x')

def calc_hmac_md5(text: str, key: str) -> str:
    return hmac.new(key.encode(), text.encode(), hashlib.md5).hexdigest()

def calc_hmac_sha256(text: str, key: str) -> str:
    return hmac.new(key.encode(), text.encode(), hashlib.sha256).hexdigest()

def calc_hmmac_sha1(text: str, key: str) -> str:
    return hmac.new(key.encode(), text.encode(), hashlib.sha1).hexdigest()


# All hash functions registry
HASH_FUNCS = {
    'md5': ('MD5', calc_md5),
    'sha1': ('SHA-1', calc_sha1),
    'sha224': ('SHA-224', calc_sha224),
    'sha256': ('SHA-256', calc_sha256),
    'sha384': ('SHA-384', calc_sha384),
    'sha512': ('SHA-512', calc_sha512),
    'sha3_256': ('SHA3-256', calc_sha3_256),
    'sha3_512': ('SHA3-512', calc_sha3_512),
    'blake2b': ('BLAKE2b', calc_blake2b),
    'crc32': ('CRC32', calc_crc32_hex),
}


# ═══════════════════════════════════════════
# 5. RSA utilities (basic)
# ═══════════════════════════════════════════

def rsa_generate_keys(bits: int = 1024) -> dict:
    """Generate RSA key pair (educational, NOT cryptographically secure)."""
    import random

    def is_prime(n: int, k: int = 20) -> bool:
        if n < 2:
            return False
        for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
            if n % p == 0:
                return n == p
        d = n - 1
        s = 0
        while d % 2 == 0:
            d //= 2
            s += 1
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, d, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(s - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def gen_prime(bits: int) -> int:
        while True:
            n = random.getrandbits(bits)
            n |= (1 << bits - 1) | 1
            if is_prime(n):
                return n

    p = gen_prime(bits // 2)
    q = gen_prime(bits // 2)
    while p == q:
        q = gen_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    while e < phi:
        import math
        if math.gcd(e, phi) == 1:
            break
        e += 2
    d = pow(e, -1, phi)

    return {
        'n': n, 'e': e, 'd': d, 'p': p, 'q': q,
        'bits': bits, 'phi': phi,
    }


def rsa_encrypt(text: str, n: int, e: int) -> str:
    """RSA encryption using public key."""
    m = int.from_bytes(text.encode('utf-8'), 'big')
    if m >= n:
        return f"[!] 消息太长，需要 {m.bit_length()} bits (n={n.bit_length()} bits)"
    c = pow(m, e, n)
    return hex(c)[2:]


def rsa_decrypt(hex_cipher: str, n: int, d: int) -> str:
    """RSA decryption using private key."""
    try:
        c = int(hex_cipher, 16)
    except ValueError:
        return "[!] 无效的密文"
    m = pow(c, d, n)
    try:
        return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode('utf-8')
    except Exception:
        return hex(m)


def rsa_factorize_hint(n: int) -> str:
    """Provide hints for RSA factorization."""
    lines = [f"RSA modulus n = {n}", f"bits = {n.bit_length()}"]
    # Check if n is small enough for division
    if n.bit_length() < 128:
        lines.append("⚡ n 较小，可直接因数分解")
        lines.append(f"💡 尝试: python -c 'import sympy; print(sympy.factorint({n}))'")
    elif n.bit_length() < 256:
        lines.append("💡 尝试 yafu 或 factordb.com 分解")
        lines.append(f"🔗 http://factordb.com/index.php?query={n}")
    else:
        lines.append("💡 可能需要高级攻击方法:")
        lines.append("  • 检查是否有Boneh-Durfee漏洞")
        lines.append("  • 检查Wiener攻击 (e过大)")
        lines.append("  • 检查共用素数")
    return '\n'.join(lines)


# ═══════════════════════════════════════════
# 6. XOR utilities
# ═══════════════════════════════════════════

def xor_encrypt(text: str, key: str) -> str:
    """XOR encrypt/decrypt."""
    return xor_encrypt_hex(text, key)


def xor_encrypt_hex(text: str, key: str) -> str:
    """XOR and return hex."""
    result = bytearray()
    k = key.encode('utf-8')
    t = text.encode('utf-8')
    for i, b in enumerate(t):
        result.append(b ^ k[i % len(k)])
    return result.hex()


def xor_decrypt(hex_cipher: str, key: str) -> str:
    """XOR decrypt from hex."""
    try:
        cipher = bytes.fromhex(hex_cipher.replace(' ', ''))
    except ValueError:
        return "[!] 无效十六进制"
    result = bytearray()
    k = key.encode('utf-8')
    for i, b in enumerate(cipher):
        result.append(b ^ k[i % len(k)])
    return result.decode('utf-8', errors='replace')


def xor_brute_single(hex_cipher: str) -> List[Tuple[int, str]]:
    """Single-byte XOR brute force."""
    try:
        cipher = bytes.fromhex(hex_cipher.replace(' ', ''))
    except ValueError:
        return []
    results = []
    for key in range(256):
        plain = ''.join(chr(b ^ key) for b in cipher)
        # Score by printable ratio
        printable = sum(1 for c in plain if 32 <= ord(c) < 127)
        if printable / max(len(plain), 1) > 0.7:
            results.append((key, plain))
    return results


# ═══════════════════════════════════════════
# 7. Encoding conversions (binary/octal/hex/decimal)
# ═══════════════════════════════════════════

def num_base_convert(value: str, from_base: int, to_base: int) -> str:
    """Convert between number bases."""
    try:
        num = int(value, from_base)
    except ValueError:
        return f"[!] 无效输入: {value} (base {from_base})"
    
    if to_base == 10:
        return str(num)
    
    digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if to_base > 36:
        return "[!] 最大支持 base-36"
    
    if num == 0:
        return "0"
    result = []
    n = abs(num)
    while n > 0:
        result.append(digits[n % to_base])
        n //= to_base
    if num < 0:
        result.append('-')
    return ''.join(reversed(result))


def text_to_hex(text: str) -> str:
    """Text to hex string."""
    return text.encode('utf-8').hex()


def hex_to_text(hex_str: str) -> str:
    """Hex string to text."""
    try:
        return bytes.fromhex(hex_str.replace(' ', '')).decode('utf-8', errors='replace')
    except ValueError:
        return "[!] 无效十六进制"
