# -*- coding: utf-8 -*-
"""AES 加密/解密工具 — 支持 ECB / CBC 模式 (zero-dependency)."""

from __future__ import annotations

# Pure-Python AES implementation (no external deps)
# Based on the standard AES-128/192/256 specification

SBOX = [
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
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]

INV_SBOX = [0] * 256
for i in range(256):
    INV_SBOX[SBOX[i]] = i

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _sub_bytes(state):
    for i in range(16):
        state[i] = SBOX[state[i]]


def _inv_sub_bytes(state):
    for i in range(16):
        state[i] = INV_SBOX[state[i]]


def _shift_rows(state):
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]


def _inv_shift_rows(state):
    state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]


def _gmult(a, b):
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


def _mix_columns(state):
    for i in range(0, 16, 4):
        a = state[i:i+4]
        state[i] = _gmult(2, a[0]) ^ _gmult(3, a[1]) ^ a[2] ^ a[3]
        state[i+1] = a[0] ^ _gmult(2, a[1]) ^ _gmult(3, a[2]) ^ a[3]
        state[i+2] = a[0] ^ a[1] ^ _gmult(2, a[2]) ^ _gmult(3, a[3])
        state[i+3] = _gmult(3, a[0]) ^ a[1] ^ a[2] ^ _gmult(2, a[3])


def _inv_mix_columns(state):
    for i in range(0, 16, 4):
        a = state[i:i+4]
        state[i] = _gmult(14, a[0]) ^ _gmult(11, a[1]) ^ _gmult(13, a[2]) ^ _gmult(9, a[3])
        state[i+1] = _gmult(9, a[0]) ^ _gmult(14, a[1]) ^ _gmult(11, a[2]) ^ _gmult(13, a[3])
        state[i+2] = _gmult(13, a[0]) ^ _gmult(9, a[1]) ^ _gmult(14, a[2]) ^ _gmult(11, a[3])
        state[i+3] = _gmult(11, a[0]) ^ _gmult(13, a[1]) ^ _gmult(9, a[2]) ^ _gmult(14, a[3])


def _key_expansion(key):
    nk = len(key) // 4
    nr = {4: 10, 6: 12, 8: 14}[nk]
    w = list(key)
    for i in range(nk, 4 * (nr + 1)):
        t = w[-4:]
        if i % nk == 0:
            t = [SBOX[t[1]], SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]
            t[0] ^= RCON[i // nk - 1]
        elif nk > 6 and i % nk == 4:
            t = [SBOX[t[0]], SBOX[t[1]], SBOX[t[2]], SBOX[t[3]]]
        prev = w[-4*nk:]
        w.extend([t[j] ^ prev[j] for j in range(4)])
    return w, nr


def _add_round_key(state, round_key):
    for i in range(16):
        state[i] ^= round_key[i]


def _aes_block(state, round_keys, decrypt=False):
    nr = len(round_keys) - 1
    if decrypt:
        _add_round_key(state, round_keys[nr])
        for r in range(nr - 1, 0, -1):
            _inv_shift_rows(state)
            _inv_sub_bytes(state)
            _add_round_key(state, round_keys[r])
            _inv_mix_columns(state)
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, round_keys[0])
    else:
        _add_round_key(state, round_keys[0])
        for r in range(1, nr):
            _sub_bytes(state)
            _shift_rows(state)
            _mix_columns(state)
            _add_round_key(state, round_keys[r])
        _sub_bytes(state)
        _shift_rows(state)
        _add_round_key(state, round_keys[nr])


def _pkcs7_pad(data, block_size=16):
    pad_len = block_size - len(data) % block_size
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("bad padding")
    return data[:-pad_len]


def aes_encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    key = key[:32]  # AES-256 max
    w, nr = _key_expansion(key)
    round_keys = [w[i*16:(i+1)*16] for i in range(nr + 1)]
    padded = _pkcs7_pad(plaintext)
    result = bytearray()
    for i in range(0, len(padded), 16):
        block = list(padded[i:i+16])
        _aes_block(block, round_keys)
        result.extend(block)
    return bytes(result)


def aes_decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    key = key[:32]
    w, nr = _key_expansion(key)
    round_keys = [w[i*16:(i+1)*16] for i in range(nr + 1)]
    result = bytearray()
    for i in range(0, len(ciphertext), 16):
        block = list(ciphertext[i:i+16])
        _aes_block(block, round_keys, decrypt=True)
        result.extend(block)
    return _pkcs7_unpad(bytes(result))


def aes_encrypt_cbc(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    key = key[:32]
    w, nr = _key_expansion(key)
    round_keys = [w[i*16:(i+1)*16] for i in range(nr + 1)]
    padded = _pkcs7_pad(plaintext)
    result = bytearray()
    prev = list(iv)
    for i in range(0, len(padded), 16):
        pt = list(padded[i:i+16])
        for j in range(16):
            pt[j] ^= prev[j]
        _aes_block(pt, round_keys)
        result.extend(pt)
        prev = pt
    return bytes(result)


def aes_decrypt_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    key = key[:32]
    w, nr = _key_expansion(key)
    round_keys = [w[i*16:(i+1)*16] for i in range(nr + 1)]
    result = bytearray()
    prev = list(iv)
    for i in range(0, len(ciphertext), 16):
        block = list(ciphertext[i:i+16])
        current = list(block)
        _aes_block(block, round_keys, decrypt=True)
        for j in range(16):
            block[j] ^= prev[j]
        result.extend(block)
        prev = current
    return _pkcs7_unpad(bytes(result))


# ════ CLI ════
if __name__ == "__main__":
    import sys
    import base64

    key = b"yangweb_key45678"
    iv = bytes(16)

    if len(sys.argv) > 1 and sys.argv[1] == "decrypt":
        mode = sys.argv[2] if len(sys.argv) > 2 else "ecb"
        ct_b64 = sys.argv[3] if len(sys.argv) > 3 else input("base64 cipher: ")
        ct = base64.b64decode(ct_b64)
        if mode == "cbc":
            pt = aes_decrypt_cbc(key, iv, ct)
        else:
            pt = aes_decrypt_ecb(key, ct)
        print(pt.decode("utf-8", errors="replace"))
    else:
        mode = sys.argv[1] if len(sys.argv) > 1 else "ecb"
        pt = sys.argv[2] if len(sys.argv) > 2 else "flag{test_aes_flag}".encode()
        if mode == "cbc":
            ct = aes_encrypt_cbc(key, iv, pt)
        else:
            ct = aes_encrypt_ecb(key, pt)
        print("ECB" if mode == "ecb" else "CBC", base64.b64encode(ct).decode())
