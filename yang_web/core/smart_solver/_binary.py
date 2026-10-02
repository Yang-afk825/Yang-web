"""yang_web.core.smart_solver 子模块 _binary（自 smart_solver.py 拆分，请勿手工重排）。"""

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
#  二进制分析引擎 (PWN / Reverse)
# ═══════════════════════════════════════════════════════════

class BinaryAnalyzer:
    """二进制文件分析器 — PE/ELF 检测、保护机制、字符串提取."""
    
    # Magic bytes
    MAGIC = {
        b'\x7fELF': 'ELF (Linux executable)',
        b'MZ': 'PE (Windows executable)',
        b'\xca\xfe\xba\xbe': 'Mach-O (macOS)',
        b'\xce\xfa\xed\xfe': 'Mach-O (32-bit)',
        b'PK\x03\x04': 'ZIP/JAR/APK',
        b'\x89PNG': 'PNG image',
        b'\xff\xd8\xff': 'JPEG image',
        b'GIF8': 'GIF image',
        b'%PDF': 'PDF document',
    }
    
    # ELF protection flags
    ELF_PROTECTIONS = {
        "RELRO": ["Full RELRO", "Partial RELRO", "No RELRO"],
        "STACK CANARY": ["Canary found", "No canary"],
        "NX": ["NX enabled", "NX disabled"],
        "PIE": ["PIE enabled", "PIE disabled"],
        "RPATH": ["RPATH found", "No RPATH"],
        "RUNPATH": ["RUNPATH found", "No RUNPATH"],
        "FORTIFY": ["Fortify enabled", "Fortify disabled"],
    }
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.data: bytes = b""
        self.results: List[dict] = []
        self.file_type: str = "unknown"
    
    def log(self, step: str, status: str, detail: str = ""):
        self.results.append({"step": step, "status": status, "detail": detail})
    
    def load(self) -> bool:
        """加载文件."""
        try:
            with open(self.filepath, 'rb') as f:
                self.data = f.read()
            self.log("Load", "ok", f"{len(self.data)} bytes from {self.filepath}")
            return True
        except Exception as e:
            self.log("Load", "fail", str(e)[:100])
            return False
    
    def analyze(self) -> dict:
        """完整分析流程."""
        if not self.load():
            return self._result(False)
        
        # 1. 文件类型检测
        self._detect_type()
        
        # 2. 字符串提取 + flag 搜索
        self._extract_strings()
        
        # 3. 熵分析
        self._entropy_analysis()
        
        # 4. PE 分析
        if self.file_type == "PE":
            self._analyze_pe()
        
        # 5. ELF 分析
        if self.file_type == "ELF":
            self._analyze_elf()
        
        # 6. APK 提示
        if self.file_type == "ZIP/APK":
            self._apk_hints()
        
        return self._result(True)
    
    def _detect_type(self):
        """Magic bytes 检测."""
        for magic, ftype in self.MAGIC.items():
            if self.data.startswith(magic):
                self.file_type = ftype.split(" ")[0]
                self.log("File Type", "found", ftype)
                return
        
        # Text-based fallback
        try:
            text = self.data.decode('utf-8')[:200]
            if text.isprintable() and len(text) > 10:
                self.file_type = "text"
                self.log("File Type", "found", "Plain text")
        except Exception:
            self.file_type = "unknown"
            self.log("File Type", "unknown", f"Magic: {self.data[:16].hex()}")
    
    def _extract_strings(self):
        """提取可读字符串并搜索 flag."""
        strings_found = []
        current = b""
        
        for b in self.data:
            if 0x20 <= b <= 0x7e:
                current += bytes([b])
            else:
                if len(current) >= 4:
                    s = current.decode('ascii', errors='replace')
                    strings_found.append(s)
                current = b""
        
        if len(current) >= 4:
            strings_found.append(current.decode('ascii', errors='replace'))
        
        # Search for flags in strings
        flags = []
        for s in strings_found:
            f = find_flag(s)
            if f:
                flags.append(f)
                self.flag = f
        
        # Interesting strings (URLs, paths, passwords, keys)
        interesting = []
        for s in strings_found:
            if any(kw in s.lower() for kw in 
                   ['password', 'secret', 'key', 'flag', 'token', 'admin',
                    '/bin/sh', '/bin/bash', 'system', 'exec', 'http://', 'https://',
                    '@', '.php', '.py', '.so', '.dll']):
                interesting.append(s)
        
        self.log("Strings", "ok", f"{len(strings_found)} strings, {len(interesting)} interesting")
        for intr in interesting[:20]:
            self.log("  String", "info", intr[:100])
        
        if flags:
            self.log("Flag in strings", "flag!", flags[0])
    
    def _entropy_analysis(self):
        """熵分析 — 检测加密/压缩."""
        if len(self.data) < 256:
            return
        
        # Simple Shannon entropy
        from collections import Counter
        counts = Counter(self.data)
        total = len(self.data)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                import math
                entropy -= p * math.log2(p)
        
        entropy_norm = entropy / 8.0  # Normalized
        
        if entropy_norm > 0.9:
            self.log("Entropy", "high", "Likely encrypted or compressed")
        elif entropy_norm > 0.7:
            self.log("Entropy", "medium", "Partially encrypted/compressed")
        else:
            self.log("Entropy", "normal", "Likely plain binary/code")
    
    def _analyze_pe(self):
        """PE 文件简易分析."""
        self.log("PE Analysis", "info", "Windows executable detected")
        # Check if x86 or x64
        if self.data[0x3c:0x3c+2]:
            pe_offset = int.from_bytes(self.data[0x3c:0x3c+2], 'little')
            if len(self.data) > pe_offset + 4:
                if self.data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                    machine = int.from_bytes(self.data[pe_offset+4:pe_offset+6], 'little')
                    arch = "x86" if machine == 0x14c else "x64" if machine == 0x8664 else f"arch={machine}"
                    self.log("PE Arch", "info", arch)
                    # Check for .NET
                    # Look for sections
                    for s in ['.NET', 'mscoree', 'CorExeMain']:
                        if s.encode() in self.data:
                            self.log("PE .NET", "info", ".NET assembly detected")
                            break
    
    def _analyze_elf(self):
        """ELF 文件简易分析."""
        self.log("ELF Analysis", "info", "Linux executable detected")
        
        if len(self.data) < 20:
            return
        
        # Bits (32/64)
        bits = self.data[4]
        arch_map = {1: "x86-32", 2: "x86-64"}
        self.log("ELF Arch", "info", arch_map.get(bits, f"bits={bits}"))
        
        # Endian
        endian = "Little-endian" if self.data[5] == 1 else "Big-endian"
        self.log("ELF Endian", "info", endian)
        
        # Check for basic protections via section analysis
        # NX bit
        has_nx = b'GNU_STACK' in self.data and b'RWE' not in self.data[:self.data.index(b'GNU_STACK')+20] if b'GNU_STACK' in self.data else False
        self.log("ELF NX", "info", "NX likely enabled" if has_nx else "NX status unknown")
        
        # Check for common vulnerability patterns in strings
        vuln_hints = []
        if b'gets(' in self.data or b'system(' in self.data:
            vuln_hints.append("gets()/system() calls")
        if b'strcpy' in self.data or b'sprintf' in self.data or b'strcat' in self.data:
            vuln_hints.append("Unsafe string functions")
        if b'/bin/sh' in self.data:
            vuln_hints.append("Contains /bin/sh")
        
        if vuln_hints:
            self.log("ELF Vuln Hints", "info", ", ".join(vuln_hints))
    
    def _apk_hints(self):
        """APK/ZIP 分析提示."""
        self.log("APK Hints", "info", "Android APK or ZIP detected")
        self.log("APK Action", "info", 
                 "Use: jadx-gui or APK逆向Solver.py for analysis")
    
    def _result(self, success: bool) -> dict:
        return {
            "success": success,
            "flag": getattr(self, 'flag', None),
            "results": self.results,
            "category": "binary",
            "file_type": self.file_type,
            "filepath": self.filepath,
        }
