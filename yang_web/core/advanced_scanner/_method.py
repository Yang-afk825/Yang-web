"""yang_web.core.advanced_scanner 子模块 _method（自 advanced_scanner.py 拆分，请勿手工重排）。"""

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

from ._common import (http_request)



# ═══════════════════════════════════════════════════════════
#  4. HTTP Method Auto-Switch Engine
# ═══════════════════════════════════════════════════════════

class MethodAutoSwitch:
    """HTTP方法自适应引擎 — 当GET失败时自动尝试POST等.

    策略:
    1. 先用分析得到的方法发送
    2. 如果response异常(404/400/500)，自动切换方法
    3. 对比结果，选择最佳响应
    """

    METHODS = ["GET", "POST"]

    def __init__(self, url: str, timeout: int = 5):
        self.url = url
        self.timeout = timeout
        self.results: Dict[str, dict] = {}

    def try_all_methods(self, param: str, payload: str,
                        post_params: dict = None) -> dict:
        """Try the same payload with different HTTP methods.

        Returns:
            {"best_method": str, "best_response": dict, "all_results": {...},
             "recommendation": str}
        """
        results = {}
        best_method = None
        best_score = -1

        for method in self.METHODS:
            if method == "GET":
                # Build GET URL with payload
                parsed = urllib.parse.urlparse(self.url)
                params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                params[param] = [payload]
                new_query = urllib.parse.urlencode(params, doseq=True)
                test_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                resp = http_request(test_url, method="GET", timeout=self.timeout)
            else:  # POST
                if post_params is None:
                    post_params = {param: payload}
                data = urllib.parse.urlencode(post_params).encode()
                resp = http_request(self.url, method="POST", data=data, timeout=self.timeout)

            results[method] = resp

            # Score: prefer 200, then 3xx, then 4xx (non-404), then others
            status = resp.get("status", 0)
            body_len = resp.get("body_len", 0)
            score = 0
            if 200 <= status < 300:
                score = 100 + body_len
            elif 300 <= status < 400:
                score = 50
            elif status == 403 or status == 401:
                score = 30
            elif 400 <= status < 500 and status != 404:
                score = 20
            elif status == 404:
                score = 0

            if score > best_score:
                best_score = score
                best_method = method

        recommendation = f"Best method: {best_method} (score: {best_score})"

        return {
            "best_method": best_method,
            "best_response": results.get(best_method, {}),
            "all_results": results,
            "recommendation": recommendation,
        }
