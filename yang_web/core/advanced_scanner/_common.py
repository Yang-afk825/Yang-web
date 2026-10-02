"""yang_web.core.advanced_scanner 子模块 _common（自 advanced_scanner.py 拆分，请勿手工重排）。"""

from __future__ import annotations
import re
import ssl
import socket
import time
import threading
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, List, Optional, Tuple, Callable, Set
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from collections import defaultdict



def http_request(url: str, method: str = "GET", data: bytes = None,
                 headers: dict = None, timeout: int = 5) -> dict:
    """Unified HTTP request with structured response."""
    result = {"ok": False, "status": 0, "headers": {}, "body": "",
              "body_bytes": b"", "body_len": 0, "elapsed_ms": 0, "error": None}
    try:
        h = {"User-Agent": DEFAULT_UA, "Accept": "*/*"}
        if headers:
            h.update(headers)
        if data and method == "POST":
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        req = urllib.request.Request(url, data=data, headers=h, method=method)
        start = time.time()
        resp = urllib.request.urlopen(req, timeout=timeout, context=_SSL_CTX)
        elapsed = int((time.time() - start) * 1000)
        body = resp.read()
        result.update({
            "ok": True, "status": resp.status,
            "headers": dict(resp.headers),
            "body": body.decode("utf-8", errors="replace"),
            "body_bytes": body, "body_len": len(body),
            "elapsed_ms": elapsed,
        })
    except urllib.error.HTTPError as e:
        result["status"] = e.code
        result["headers"] = dict(e.headers)
        try:
            body = e.read()
            result["body"] = body.decode("utf-8", errors="replace")
            result["body_bytes"] = body
            result["body_len"] = len(body)
        except Exception:
            pass
        result["ok"] = True
        result["error"] = f"HTTP {e.code}"
    except Exception as e:
        result["error"] = str(e)
    return result


def find_flag(text: str) -> Optional[str]:
    m = FLAG_RE.search(text) if text else None
    return m.group(0) if m else None



# ═══════════════════════════════════════════════════════════
#  Common Utilities
# ═══════════════════════════════════════════════════════════

FLAG_RE = re.compile(
    r'(?:flag|ctf|iscc|hctf|ddctf|realworld|n1ctf|suctf|wmctf|geesec|dasctf|sigpwny|'
    r'cyber|hack|pico|tjctf|angstrom|dctf|ractf|zh3r0|inctf|darkctf|csictf|ritsec|'
    r'nactf|b01lers|kksctf|0xgame|0xctf|nssctf|moectf|gactf|actf|starctf|ructf|'
    r'plaidctf|defenit|hitcon|balsn|asis|codegate|0ctf|tctf|wctf|hxp|hackthebox|csaw)'
    r'\{[^}]+\}', re.IGNORECASE
)

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

DEFAULT_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Yang-Web/3.5'
