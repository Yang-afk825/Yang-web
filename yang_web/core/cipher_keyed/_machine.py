"""yang_web.core.cipher_keyed 子模块 _machine（自 cipher_keyed.py 拆分，请勿手工重排）。"""

import base64
import hashlib
import hmac as hmac_mod
import re
from math import gcd
try:
    from .. import crypto_engine
except Exception:
    import crypto_engine

from ._common import (_only_letters)


# ---------- Enigma M3 ----------
_ROTORS = {
    'I': ('EKMFLGDQVZNTOWYHXUSPAIBRCJ', 'Q'),
    'II': ('AJDKSIRUXBLHWTMCQGZNPYFVOE', 'E'),
    'III': ('BDFHJLCPRTXVZNYEIWGAKMUSQO', 'V'),
    'IV': ('ESOVPZJAYQUIRHXLNFTGKDCMWB', 'J'),
    'V': ('VZBRGITYUPSDNHLXAWMJQOFECK', 'Z'),
}
_REFLECTORS = {
    'B': 'YRUHQSLDPXNGOKMIEBFZCWVJAT',
    'C': 'FVPJIAOYEDRZXWGCTKUQSBNMHL',
}

def _enigma_parse_key(key):
    # key 格式："转子名,起始位置" 如 "I II III,AAA" 或 "I,II,III|AAA|B" 简化："AAA"
    s = str(key).strip()
    rotor_names = ['I', 'II', 'III']
    positions = 'AAA'
    reflector = 'B'
    plugboard = ''
    if ',' in s:
        left, right = s.split(',', 1)
        rn = [x.strip().upper() for x in left.split()]
        if all(r in _ROTORS for r in rn):
            rotor_names = rn
        pos_part = right.strip()
        if '|' in pos_part:
            parts = pos_part.split('|')
            positions = parts[0].upper()[:3]
            if len(parts) > 1:
                reflector = parts[1].upper()[:1]
            if len(parts) > 2:
                plugboard = parts[2].upper()
        else:
            positions = pos_part.upper()[:3]
    elif len(s) >= 3:
        positions = s.upper()[:3]
    return rotor_names, positions.ljust(3, 'A'), reflector, plugboard

def _enigma_advance(rotors, rotor_names):
    # 双步进机制
    notch_positions = [_ROTORS[rn][1] for rn in rotor_names]
    # 检查中间转子是否在 notch（触发左转子步进）
    middle_at_notch = chr(rotors[1] + 65) in notch_positions[1]
    right_at_notch = chr(rotors[2] + 65) in notch_positions[2]
    if middle_at_notch:
        rotors[1] = (rotors[1] + 1) % 26
        rotors[0] = (rotors[0] + 1) % 26
    if right_at_notch:
        rotors[1] = (rotors[1] + 1) % 26
    rotors[2] = (rotors[2] + 1) % 26

def _enigma_transform(c, rotors, rotor_names, reflector):
    x = ord(c) - 65
    # 正向：右 -> 中 -> 左
    for i in range(2, -1, -1):
        wiring = _ROTORS[rotor_names[i]][0]
        offset = rotors[i]
        x = (ord(wiring[(x + offset) % 26]) - 65 - offset) % 26
    # 反射器
    x = ord(_REFLECTORS[reflector][x]) - 65
    # 反向：左 -> 中 -> 右
    for i in range(3):
        wiring = _ROTORS[rotor_names[i]][0]
        offset = rotors[i]
        pos = (x + offset) % 26
        x = (wiring.index(chr(pos + 65)) - offset) % 26
    return chr(x + 65)

def enigma_encode(text, key=""):
    rotor_names, positions, reflector, plugboard = _enigma_parse_key(key)
    plug = {}
    if plugboard:
        pairs = re.findall(r'([A-Z]{2})', plugboard)
        for a, b in pairs:
            plug[a] = b
            plug[b] = a
    rotors = [ord(p) - 65 for p in positions]
    letters = _only_letters(text)
    out = []
    for c in letters:
        _enigma_advance(rotors, rotor_names)
        c2 = plug.get(c, c)
        c3 = _enigma_transform(c2, rotors, rotor_names, reflector)
        out.append(plug.get(c3, c3))
    return ''.join(out)

def enigma_decode(cipher, key=""):
    return enigma_encode(cipher, key)  # Enigma 对合

# ---------- Fernet ----------
def fernet_encode(text, key=""):
    try:
        key_bytes = base64.urlsafe_b64decode(key + '=' * (-len(key) % 4))
    except Exception:
        return "[!] key 应为 urlsafe base64 的 32 字节"
    if len(key_bytes) != 32:
        return "[!] key 应为 32 字节（16 签名 + 16 加密）"
    sign_key, enc_key = key_bytes[:16], key_bytes[16:]
    iv = __import__('os').urandom(16)
    data = text.encode('utf-8')
    # PKCS7 填充 + AES-128-CBC
    pad = 16 - len(data) % 16
    padded = data + bytes([pad]) * pad
    ciphertext = crypto_engine.aes_encrypt(enc_key, padded, 'cbc', iv)
    payload = b'\x80' + int(__import__('time').time()).to_bytes(8, 'big') + iv + ciphertext
    sig = hmac_mod.new(sign_key, payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(payload + sig).decode().rstrip('=')

def fernet_decode(cipher, key=""):
    try:
        key_bytes = base64.urlsafe_b64decode(key + '=' * (-len(key) % 4))
    except Exception:
        return "[!] key 格式错误"
    if len(key_bytes) != 32:
        return "[!] key 应为 32 字节"
    sign_key, enc_key = key_bytes[:16], key_bytes[16:]
    try:
        raw = base64.urlsafe_b64decode(cipher + '=' * (-len(cipher) % 4))
    except Exception:
        return "[!] 密文格式错误"
    if len(raw) < 1 + 8 + 16 + 32:
        return "[!] 密文过短"
    payload, sig = raw[:-32], raw[-32:]
    if not hmac_mod.compare_digest(hmac_mod.new(sign_key, payload, hashlib.sha256).digest(), sig):
        return "[!] HMAC 校验失败（key 错误或密文被篡改）"
    iv = payload[9:25]
    ciphertext = payload[25:]
    plain = crypto_engine.aes_decrypt(enc_key, ciphertext, 'cbc', iv)
    if not plain:
        return "[!] 解密失败"
    pad = plain[-1]
    return plain[:-pad].decode('utf-8', errors='replace')
