"""yang_web.core.advanced_scanner 子模块 _differ（自 advanced_scanner.py 拆分，请勿手工重排）。"""

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

from ._common import (find_flag, http_request)



# ═══════════════════════════════════════════════════════════
#  2. Response Diffing Engine — 盲注精准检测
# ═══════════════════════════════════════════════════════════

class ResponseDiffer:
    """响应对比引擎 — 通过对比注入前后响应差异来检测盲注.

    用法:
        differ = ResponseDiffer(baseline_url)
        differ.set_baseline()       # 获取基线
        result = differ.test("param", "'", baseline_val="1")   # 对比单次
        results = differ.batch_test("param", payloads)          # 批量对比
    """

    def __init__(self, url: str, timeout: int = 5):
        self.url = url
        self.timeout = timeout
        self.baseline: dict = None
        self.history: List[dict] = []

    def set_baseline(self, method: str = "GET", data: bytes = None) -> dict:
        """Set baseline response for comparison."""
        self.baseline = http_request(self.url, method=method, data=data, timeout=self.timeout)
        return self.baseline

    def test(self, param: str, payload: str, baseline_value: str = "",
             method: str = "GET") -> dict:
        """Test a single payload and compare with baseline.

        Returns:
            {"payload": str, "status_diff": int, "len_diff": int,
             "time_diff_ms": int, "content_similarity": float,
             "new_content": set of new strings, "missing_content": set,
             "flagged": bool, "flags": [str of found flags],
             "analysis": {"suspicious": bool, "reasons": [str]}}
        """
        if self.baseline is None:
            self.set_baseline(method=method)

        # Build test URL
        parsed = urllib.parse.urlparse(self.url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        if param in params:
            orig_val = params[param][0] if params[param] else baseline_value
            new_val = orig_val + payload
            params[param] = [new_val]
        else:
            params[param] = [payload]

        new_query = urllib.parse.urlencode(params, doseq=True)
        test_url = urllib.parse.urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))

        test_resp = http_request(test_url, method=method, timeout=self.timeout)

        # --- Diff Analysis ---
        status_diff = test_resp.get("status", 0) - self.baseline.get("status", 0)
        len_diff = test_resp.get("body_len", 0) - self.baseline.get("body_len", 0)
        time_diff = test_resp.get("elapsed_ms", 0) - self.baseline.get("elapsed_ms", 0)

        test_body = test_resp.get("body", "")
        base_body = self.baseline.get("body", "")

        # Check for flags
        flags = []
        f = find_flag(test_body)
        if f:
            flags.append(f)

        # Content comparison — extract "interesting" tokens
        def _tokens(text, min_len=4):
            return set(re.findall(r'[A-Za-z0-9_/.:-]{' + str(min_len) + r',}', text))

        base_tokens = _tokens(base_body)
        test_tokens = _tokens(test_body)
        new_content = test_tokens - base_tokens
        missing_content = base_tokens - test_tokens
        total = max(len(base_tokens), 1)
        similarity = 1.0 - len(test_tokens.symmetric_difference(base_tokens)) / max(total, 1)

        # Suspicion analysis
        reasons = []
        suspicious = False

        # Status code changes are very suspicious
        if status_diff != 0:
            suspicious = True
            reasons.append(f"Status changed: {self.baseline.get('status')} → {test_resp.get('status')}")

        # Large body length change
        if abs(len_diff) > 100:
            suspicious = True
            reasons.append(f"Body length changed by {len_diff}B")

        # Significant time difference (>500ms) suggests time-based injection
        if time_diff > 500:
            suspicious = True
            reasons.append(f"Response delayed by {time_diff}ms — possible time-based injection")

        # Content similarity drops significantly
        if similarity < 0.7:
            suspicious = True
            reasons.append(f"Content similarity dropped to {similarity:.1%}")

        # SQL error detection in new/missing content
        sql_errors = {"error", "sql", "syntax", "warning", "mysql", "mysqli",
                      "postgresql", "sqlite", "oracle", "odbc", "jdbc",
                      "unknown column", "column not found", "doesn't exist",
                      "no such table", "division by zero"}
        for token in new_content | missing_content:
            token_lower = token.lower()
            for err in sql_errors:
                if err in token_lower:
                    suspicious = True
                    reasons.append(f"SQL error hint: {token}")
                    break

        result = {
            "payload": payload,
            "param": param,
            "test_url": test_url,
            "status_diff": status_diff,
            "len_diff": len_diff,
            "time_diff_ms": time_diff,
            "content_similarity": round(similarity, 3),
            "new_tokens": len(new_content),
            "missing_tokens": len(missing_content),
            "flagged": bool(flags) or suspicious,
            "flags": flags,
            "analysis": {
                "suspicious": suspicious,
                "reasons": reasons,
                "highlight_tokens": list(new_content)[:20],
            },
        }
        self.history.append(result)
        return result

    def batch_test(self, param: str, payloads: List[str],
                   baseline_value: str = "", method: str = "GET",
                   on_progress=None, on_flag=None) -> List[dict]:
        """Batch test multiple payloads."""
        results = []
        for pld in payloads:
            r = self.test(param, pld, baseline_value, method)
            results.append(r)
            if r["flagged"]:
                if on_progress:
                    try:
                        on_progress("diff", pld, f"⚠️ {r['analysis']['reasons']}")
                    except Exception:
                        pass
                if r["flags"] and on_flag:
                    try:
                        on_flag(r["flags"][0])
                    except Exception:
                        pass
        return results
