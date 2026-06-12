# -*- coding: utf-8 -*-
"""Hash ç±»åè¯å«å¨ â æ ¹æ® hash æ ¼å¼è¯å«å å¯ç®æ³.

æ¯æ 40+ ç§å¸¸è§ hash æ ¼å¼: MD5, SHA1/256/512, NTLM, MySQL, bcrypt, CRC32 ç­.
"""
import re
from typing import List, Tuple


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  Hash ç­¾åæ°æ®åº â (regex, ç®æ³å, ç±»å«)
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

HASH_SIGNATURES: List[Tuple[str, str, str]] = [
    # ââ MD å®¶æ ââ
    (r"^[a-fA-F0-9]{32}$",                    "MD5",                       "MD"),
    (r"^[a-fA-F0-9]{16}$",                    "MD5 (MySQL / 16ä½)",        "MD"),
    (r"^[a-fA-F0-9]{48}$",                    "MD5 (SHA-384 truncated?)",   "MD"),
    # ââ SHA å®¶æ ââ
    (r"^[a-fA-F0-9]{40}$",                    "SHA-1",                     "SHA"),
    (r"^[a-fA-F0-9]{56}$",                    "SHA-224",                   "SHA"),
    (r"^[a-fA-F0-9]{64}$",                    "SHA-256",                   "SHA"),
    (r"^[a-fA-F0-9]{96}$",                    "SHA-384",                   "SHA"),
    (r"^[a-fA-F0-9]{128}$",                   "SHA-512",                   "SHA"),
    # ââ NTLM / LM ââ
    (r"^[a-fA-F0-9]{32}$",                    "NTLM (Windows)",            "Windows"),
    (r"^[a-fA-F0-9]{32}$",                    "LM (Windows, uppercase)",   "Windows"),
    # ââ MySQL ââ
    (r"^\*[a-fA-F0-9]{40}$",                  "MySQL 4.1+ / 5.x",         "Database"),
    (r"^[a-fA-F0-9]{16}$",                    "MySQL 3.x / OLD_PASSWORD",  "Database"),
    # ââ çå¼æ ¼å¼ ââ
    (r"^\$2[aby]\$\d{1,2}\$[./a-zA-Z0-9]{53}$", "bcrypt (Blowfish)",     "Salted"),
    (r"^\$1\$[./a-zA-Z0-9]{1,8}\$[./a-zA-Z0-9]{22}$", "MD5 Crypt ($1$)", "Salted"),
    (r"^\$5\$[./a-zA-Z0-9]{1,16}\$[./a-zA-Z0-9]{43}$", "SHA-256 Crypt ($5$)", "Salted"),
    (r"^\$6\$[./a-zA-Z0-9]{1,16}\$[./a-zA-Z0-9]{86}$", "SHA-512 Crypt ($6$)", "Salted"),
    (r"^\$argon2",                             "Argon2",                   "Salted"),
    (r"^\$scrypt",                             "scrypt",                   "Salted"),
    (r"^\$pbkdf2",                             "PBKDF2",                   "Salted"),
    # ââ CRC ââ
    (r"^[a-fA-F0-9]{8}$",                     "CRC32 / Adler32",          "Checksum"),
    (r"^[a-fA-F0-9]{4}$",                     "CRC16",                     "Checksum"),
    # ââ å¶ä» ââ
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
    # ââ JWT / Base64 ç­¾å ââ
    (r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$", "JWT Token", "Token"),
    # ââ UUID ââ
    (r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$", "UUID (Version 4)", "Other"),
]


def identify(text: str) -> List[Tuple[str, str, str]]:
    """è¯å« hash ç±»å.

    è¿å: [(ç®æ³å, ç±»å«, è¯¦ç»è¯´æ), ...] å¯è½è¿åå¤ä¸ªå¹é.
    """
    text = text.strip()
    results = []

    for pattern, algo, category in HASH_SIGNATURES:
        if re.fullmatch(pattern, text):
            results.append((algo, category, pattern))

    # å¦ææ²¡æç²¾ç¡®å¹é, å°è¯åºäºé¿åº¦åå­ç¬¦éçæ¨¡ç³å¹é
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
                results.append((algo, cat, f"é¿åº¦ {len(text)} å­ç¬¦"))

    return results


def identify_all(text: str) -> dict:
    """è¯¦ç»è¯å«, è¿åå®æ´ä¿¡æ¯å­å¸."""
    matches = identify(text)
    return {
        "input": text,
        "length": len(text),
        "charset": "hex" if all(c in "0123456789abcdefABCDEF" for c in text) else "mixed",
        "matches": [{"algorithm": m[0], "category": m[1]} for m in matches],
    }
