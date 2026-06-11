"""Hash 类型识别器 — 根据 hash 格式识别加密算法.

支持 40+ 种常见 hash 格式: MD5, SHA1/256/512, NTLM, MySQL, bcrypt, CRC32 等.
"""
import re
from typing import List, Tuple


# ═══════════════════════════════════════════════════════════
#  Hash 签名数据库 — (regex, 算法名, 类别)
# ═══════════════════════════════════════════════════════════

HASH_SIGNATURES: List[Tuple[str, str, str]] = [
    # ── MD 家族 ──
    (r"^[a-fA-F0-9]{32}$",                    "MD5",                       "MD"),
    (r"^[a-fA-F0-9]{16}$",                    "MD5 (MySQL / 16位)",        "MD"),
    (r"^[a-fA-F0-9]{48}$",                    "MD5 (SHA-384 truncated?)",   "MD"),
    # ── SHA 家族 ──
    (r"^[a-fA-F0-9]{40}$",                    "SHA-1",                     "SHA"),
    (r"^[a-fA-F0-9]{56}$",                    "SHA-224",                   "SHA"),
    (r"^[a-fA-F0-9]{64}$",                    "SHA-256",                   "SHA"),
    (r"^[a-fA-F0-9]{96}$",                    "SHA-384",                   "SHA"),
    (r"^[a-fA-F0-9]{128}$",                   "SHA-512",                   "SHA"),
    # ── NTLM / LM ──
    (r"^[a-fA-F0-9]{32}$",                    "NTLM (Windows)",            "Windows"),
    (r"^[a-fA-F0-9]{32}$",                    "LM (Windows, uppercase)",   "Windows"),
    # ── MySQL ──
    (r"^\*[a-fA-F0-9]{40}$",                  "MySQL 4.1+ / 5.x",         "Database"),
    (r"^[a-fA-F0-9]{16}$",                    "MySQL 3.x / OLD_PASSWORD",  "Database"),
    # ── 盐值格式 ──
    (r"^\$2[aby]\$\d{1,2}\$[./a-zA-Z0-9]{53}$", "bcrypt (Blowfish)",     "Salted"),
    (r"^\$1\$[./a-zA-Z0-9]{1,8}\$[./a-zA-Z0-9]{22}$", "MD5 Crypt ($1$)", "Salted"),
    (r"^\$5\$[./a-zA-Z0-9]{1,16}\$[./a-zA-Z0-9]{43}$", "SHA-256 Crypt ($5$)", "Salted"),
    (r"^\$6\$[./a-zA-Z0-9]{1,16}\$[./a-zA-Z0-9]{86}$", "SHA-512 Crypt ($6$)", "Salted"),
    (r"^\$argon2",                             "Argon2",                   "Salted"),
    (r"^\$scrypt",                             "scrypt",                   "Salted"),
    (r"^\$pbkdf2",                             "PBKDF2",                   "Salted"),
    # ── CRC ──
    (r"^[a-fA-F0-9]{8}$",                     "CRC32 / Adler32",          "Checksum"),
    (r"^[a-fA-F0-9]{4}$",                     "CRC16",                     "Checksum"),
    # ── 其他 ──
    (r"^[a-fA-F0-9]{56}$",                    "SHA-3-224",                 "SHA-3"),
    (r"^[a-fA-F0-9]{64}$",                    "SHA-3-256",                 "SHA-3"),
    (r"^[a-fA-F0-9]{96}$",                    "SHA-3-384",                 "SHA-3"),
    (r"^[a-fA-F0-9]{128}$",                   "SHA-3-512",                 "SHA-3"),
    (r"^[a-fA-F0-9]{64}$",                    "SHA-3-256 / Keccak-256",   "SHA-3"),
    (r"^[a-fA-F0-9]{64}$",                    "SHA-256 (Ethereum)",        "SHA"),
    (r"^[a-fA-F0-9]{40}$",                    "RIPEMD-160",               "RIPEMD"),
    (r"^[a-fA-F0-9]{64}$",                    "RIPEMD-256",               "RIPEMD"),
    (r"^[a-fA-F0-9]{80}$",                    "RIPEMD-320",               "RIPEMD"),
    (r"^[a-fA-F0-9]{64}$",                    "Whirlpool",                "Other"),
    (r"^[a-fA-F0-9]{32}$",                    "MD4",                       "MD"),
    (r"^[a-fA-F0-9]{32}$",                    "LM Hash (16 bytes hex)",   "Windows"),
    (r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$",    "LM:NTLM",                  "Windows"),
    (r"^[a-f0-9]{32}(:.*)?$",                  "MD5 (Unix)",               "MD"),
    # ── JWT / Base64 签名 ──
    (r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", "JWT Token", "Token"),
    # ── UUID ──
    (r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", "UUID (Version 4)", "Other"),
]


def identify(text: str) -> List[Tuple[str, str, str]]:
    """识别 hash 类型.

    返回: [(算法名, 类别, 详细说明), ...] 可能返回多个匹配.
    """
    text = text.strip()
    results = []

    for pattern, algo, category in HASH_SIGNATURES:
        if re.fullmatch(pattern, text):
            results.append((algo, category, pattern))

    # 如果没有精确匹配, 尝试基于长度和字符集的模糊匹配
    if not results:
        hex_chars = all(c in "0123456789abcdefABCDEF" for c in text)
        if hex_chars:
            length_hints = {
                32: [("MD5 / MD4 / NTLM / LM", "MD/Windows")],
                40: [("SHA-1 / RIPEMD-160 / Tiger-160", "SHA/RIPEMD")],
                48: [("Haval-192 / Tiger-192", "Other")],
                56: [("SHA-224 / SHA-3-224 / Haval-224", "SHA")],
                64: [("SHA-256 / SHA-3-256 / RIPEMD-256 / Keccak-256", "SHA")],
                80: [("RIPEMD-320", "RIPEMD")],
                96: [("SHA-384 / SHA-3-384", "SHA")],
                128: [("SHA-512 / SHA-3-512 / Whirlpool", "SHA")],
            }
            hints = length_hints.get(len(text), [])
            for algo, cat in hints:
                results.append((algo, cat, f"长度 {len(text)} 字符"))

    return results


def identify_all(text: str) -> dict:
    """详细识别, 返回完整信息字典."""
    matches = identify(text)
    return {
        "input": text,
        "length": len(text),
        "charset": "hex" if all(c in "0123456789abcdefABCDEF" for c in text) else "mixed",
        "matches": [{"algorithm": m[0], "category": m[1]} for m in matches],
    }
