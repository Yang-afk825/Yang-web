"""yang_web.core.smart_solver 子模块 _crypto（自 smart_solver.py 拆分，请勿手工重排）。"""

from __future__ import annotations
import re
import json
import ssl
import socket
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, List, Optional, Tuple, Callable, Any

from ._common import (find_flag)



# ═══════════════════════════════════════════════════════════
#  密码自动求解引擎
# ═══════════════════════════════════════════════════════════

class CryptoSmartSolver:
    """密码学自动求解 — 链式解码 + 古典密码检测."""
    
    # Base 家族编码特征
    BASE_FEATURES = {
        "base64": r'^[A-Za-z0-9+/]+=*$',
        "base32": r'^[A-Z2-7]+=*$',
        "base16": r'^[0-9A-Fa-f]+$',
        "base58": r'^[1-9A-HJ-NP-Za-km-z]+$',
        "base85": r'^[A-Za-z0-9!#$%&()*+,\-./:;<=>?@[\]^_`{|}~]+$',
    }
    
    def __init__(self, ciphertext: str):
        self.ciphertext = ciphertext
        self.results: List[dict] = []
        self.flag: Optional[str] = None
    
    def log(self, step: str, status: str, detail: str = ""):
        self.results.append({"step": step, "status": status, "detail": detail})
    
    def solve(self) -> dict:
        """自动求解密码."""
        ct = self.ciphertext.strip()
        
        # Check if it's already a flag
        f = find_flag(ct)
        if f:
            self.flag = f
            self.log("Input", "flag!", "Already contains flag")
            return self._result(True)
        
        # 1. Base family chain decoding
        self._try_base_chain(ct)
        if self.flag:
            return self._result(True)
        
        # 2. Hex decoding
        self._try_hex(ct)
        if self.flag:
            return self._result(True)
        
        # 3. ROT family
        self._try_rot(ct)
        if self.flag:
            return self._result(True)
        
        # 4. XOR brute force
        self._try_xor_brute(ct)
        if self.flag:
            return self._result(True)
        
        # 5. Hash identification
        self._identify_hash(ct)
        
        return self._result(False)
    
    def _try_base_chain(self, ct: str, depth: int = 0, max_depth: int = 10):
        """链式 Base 解码."""
        if depth >= max_depth or len(ct) < 4:
            return
        
        import base64
        
        decoders = [
            ("base64", lambda s: base64.b64decode(s, validate=False)),
            ("base32", lambda s: base64.b32decode(s, casefold=True)),
            ("base16", lambda s: base64.b16decode(s, casefold=True)),
        ]
        
        for name, decoder in decoders:
            try:
                decoded = decoder(ct).decode('utf-8', errors='replace')
                if len(decoded) < len(ct) * 0.8 and len(decoded) > 0:  # 合理缩小
                    self.log(f"Decode", "step", f"{name}: {decoded[:80]}")
                    f = find_flag(decoded)
                    if f:
                        self.flag = f
                        self.log("Decode", "flag!", f"{name} chain: {f}")
                        return
                    # 继续链式解码
                    if any(c.isalpha() for c in decoded):
                        self._try_base_chain(decoded, depth + 1, max_depth)
            except Exception:
                continue
    
    def _try_hex(self, ct: str):
        """Hex 解码."""
        try:
            if all(c in '0123456789abcdefABCDEF' for c in ct) and len(ct) % 2 == 0:
                decoded = bytes.fromhex(ct).decode('utf-8', errors='replace')
                self.log("Hex", "decode", decoded[:80])
                f = find_flag(decoded)
                if f:
                    self.flag = f
                    self.log("Hex", "flag!", f)
                    return
                # Continue base chain on hex-decoded result
                self._try_base_chain(decoded)
        except Exception:
            pass
    
    def _try_rot(self, ct: str):
        """ROT 系列爆破."""
        for shift in range(1, 26):
            result = ""
            for c in ct:
                if 'a' <= c <= 'z':
                    result += chr((ord(c) - ord('a') + shift) % 26 + ord('a'))
                elif 'A' <= c <= 'Z':
                    result += chr((ord(c) - ord('A') + shift) % 26 + ord('A'))
                else:
                    result += c
            f = find_flag(result)
            if f:
                self.flag = f
                self.log("ROT", "flag!", f"ROT{shift}: {f}")
                return
        self.log("ROT", "none", "No flag found in ROT 1-25")
    
    def _try_xor_brute(self, ct: str):
        """XOR 字节爆破（0-255）."""
        try:
            raw = ct.encode('latin-1')
        except Exception:
            return
        
        for key in range(256):
            result = bytes(b ^ key for b in raw)
            try:
                text = result.decode('utf-8', errors='replace')
                f = find_flag(text)
                if f:
                    self.flag = f
                    self.log("XOR", "flag!", f"key=0x{key:02x}: {f}")
                    return
            except Exception:
                pass
        self.log("XOR", "none", "No flag in single-byte XOR")
    
    def _identify_hash(self, ct: str):
        """Hash 类型识别."""
        patterns = {
            "MD5": r'^[a-f0-9]{32}$',
            "SHA1": r'^[a-f0-9]{40}$',
            "SHA256": r'^[a-f0-9]{64}$',
            "SHA512": r'^[a-f0-9]{128}$',
            "NTLM": r'^[A-F0-9]{32}$',
            "MySQL5": r'^\*[A-F0-9]{40}$',
            "bcrypt": r'^\$2[aby]\$\d+\$[./A-Za-z0-9]{53}$',
        }
        for hash_type, pattern in patterns.items():
            if re.match(pattern, ct):
                self.log("Hash", "found", f"Detected {hash_type}")
                return
    
    def _result(self, success: bool) -> dict:
        return {
            "success": success,
            "flag": self.flag,
            "results": self.results,
            "category": "crypto",
            "input": self.ciphertext[:100],
        }
