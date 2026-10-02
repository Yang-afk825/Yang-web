"""yang_web.core.smart_solver 子模块 _misc（自 smart_solver.py 拆分，请勿手工重排）。"""

from __future__ import annotations
import re
import json
import ssl
import socket
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, List, Optional, Tuple, Callable, Any




# ═══════════════════════════════════════════════════════════
#  Misc / 取证 / 隐写 分析引擎
# ═══════════════════════════════════════════════════════════

class MiscAnalyzer:
    """杂项/取证/隐写题目分析器（文件路由）."""
    
    FILE_TYPE_HINTS = {
        "PK": ("ZIP/Archive", ["zip_tools.py", "Try binwalk/foremost for embedded files"]),
        "\x89PNG": ("PNG Image", ["img_stego.py", "Check LSB, palette, chunk structure"]),
        "\xff\xd8": ("JPEG Image", ["img_stego.py", "Check EXIF, appended data"]),
        "GIF8": ("GIF Image", ["img_stego.py", "Check frame delays, palette"]),
        "%PDF": ("PDF Document", ["Check embedded objects, JavaScript"]),
        "RIFF": ("WAV/AVI", ["Check audio stego (spectrogram, LSB)"]),
        "BM": ("BMP Image", ["img_stego.py", "LSB stego"]),
        "\xd4\xc3\xb2\xa1": ("PCAP", ["pcap_tools.py", "Wireshark analysis"]),
    }
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.results: List[dict] = []
    
    def log(self, step: str, status: str, detail: str = ""):
        self.results.append({"step": step, "status": status, "detail": detail})
    
    def analyze(self) -> dict:
        """分析文件类型并提供解题提示."""
        try:
            with open(self.filepath, 'rb') as f:
                header = f.read(16)
        except Exception as e:
            self.log("Load", "fail", str(e)[:100])
            return self._result(False)
        
        # Detect type
        detected = False
        for magic, (ftype, hints) in self.FILE_TYPE_HINTS.items():
            magic_bytes = magic.encode() if isinstance(magic, str) else magic
            if header.startswith(magic_bytes):
                detected = True
                self.log("File Type", "found", ftype)
                for hint in hints:
                    self.log("Hint", "info", hint)
                break
        
        if not detected:
            # General hints
            self.log("File Type", "unknown", f"Header: {header[:8].hex()}")
            self.log("Hint", "info", "Try file_analyzer.py for hex dump")
            self.log("Hint", "info", "Check for embedded files with binwalk")
        
        return self._result(detected)
    
    def _result(self, success: bool) -> dict:
        return {
            "success": success,
            "results": self.results,
            "category": "misc",
            "filepath": self.filepath,
        }
