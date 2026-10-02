"""yang_web.core.multi_stage 子模块 _http（自 multi_stage.py 拆分，请勿手工重排）。"""

from __future__ import annotations
import re
import ssl
import time
import json
import base64
import urllib.request
import urllib.error
import urllib.parse
from urllib.parse import urljoin
import http.cookiejar
from typing import Dict, List, Optional, Tuple, Set, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError

from ._common import (DEFAULT_UA, _SSL_CTX)



class SessionHTTP:
    """带 Cookie Session 的 HTTP 客户端."""

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.cj = http.cookiejar.CookieJar()
        # Create opener with custom SSL context for cookie handling
        https_handler = urllib.request.HTTPSHandler(context=_SSL_CTX)
        http_handler = urllib.request.HTTPHandler()
        cookie_handler = urllib.request.HTTPCookieProcessor(self.cj)
        self._opener = urllib.request.build_opener(https_handler, http_handler, cookie_handler)

    def request(self, url: str, method: str = "GET", data: bytes = None,
                headers: dict = None, timeout: int = None) -> dict:
        """发送 HTTP 请求，返回 {status, headers, body, body_bytes, body_len, ok, error}."""
        result = {"ok": False, "status": 0, "headers": {}, "body": "",
                  "body_bytes": b"", "body_len": 0, "error": None}
        h = {"User-Agent": DEFAULT_UA, "Accept": "*/*"}
        if headers:
            h.update(headers)
        if data and method == "POST" and "Content-Type" not in h:
            h["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            req = urllib.request.Request(url, data=data, headers=h, method=method)
            start = time.time()
            resp = self._opener.open(req, timeout=timeout or self.timeout)
            body = resp.read()
            result.update({
                "ok": True, "status": resp.status,
                "headers": dict(resp.headers),
                "body": body.decode("utf-8", errors="replace"),
                "body_bytes": body, "body_len": len(body),
                "elapsed_ms": int((time.time() - start) * 1000),
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
        except Exception as e:
            result["error"] = str(e)
        return result

    @property
    def cookies(self) -> List[str]:
        return [f"{c.name}={c.value}" for c in self.cj]

    def cookie_str(self) -> str:
        return "; ".join(self.cookies)
