"""yang_web.core.advanced_scanner 子模块 _rate（自 advanced_scanner.py 拆分，请勿手工重排）。"""

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




# ═══════════════════════════════════════════════════════════
#  7. Smart Rate Limiter
# ═══════════════════════════════════════════════════════════

class SmartRateLimiter:
    """自适应限速器 — 检测目标响应速度并调整并发度.

    根据目标响应时间动态调整:
    - 快响应 (<100ms) → 高并发 (max 30)
    - 正常 (100-500ms) → 中并发 (max 15)
    - 慢响应 (500ms-1s) → 低并发 (max 5)
    - 超慢 (>1s) → 单线程
    - 检测到 429/503 → 退避等待
    """

    def __init__(self, initial_concurrency: int = 10):
        self.concurrency = initial_concurrency
        self.min_concurrency = 1
        self.max_concurrency = 30
        self.response_times: List[float] = []
        self.error_count = 0
        self.backoff_until = 0.0
        self.consecutive_429 = 0

    def adjust(self, response: dict):
        """Adjust concurrency based on response."""
        elapsed = response.get("elapsed_ms", 0) / 1000.0
        status = response.get("status", 0)
        self.response_times.append(elapsed)

        # Handle rate limiting
        if status == 429:
            self.consecutive_429 += 1
            self.backoff_until = time.time() + min(30, 2 ** self.consecutive_429)
            self.concurrency = max(self.min_concurrency, self.concurrency // 2)
            return
        elif status == 503:
            self.consecutive_429 += 1
            self.backoff_until = time.time() + 10
            return
        else:
            self.consecutive_429 = 0

        # Adaptive speed adjustment based on last 20 responses
        if len(self.response_times) >= 5:
            avg_time = sum(self.response_times[-20:]) / min(20, len(self.response_times))
            if avg_time < 0.1:
                self.concurrency = min(self.max_concurrency, self.concurrency + 2)
            elif avg_time < 0.5:
                self.concurrency = min(self.max_concurrency, self.concurrency + 1)
            elif avg_time > 2.0:
                self.concurrency = max(self.min_concurrency, self.concurrency - 2)
            elif avg_time > 1.0:
                self.concurrency = max(self.min_concurrency, self.concurrency - 1)

    def should_wait(self) -> float:
        """Check if we should wait before next request. Returns seconds to wait or 0."""
        if time.time() < self.backoff_until:
            return self.backoff_until - time.time()
        return 0.0

    @property
    def current_stats(self) -> dict:
        avg = sum(self.response_times[-20:]) / max(1, len(self.response_times[-20:]))
        return {
            "concurrency": self.concurrency,
            "avg_response_time": round(avg, 3),
            "error_count": self.error_count,
            "backoff": self.backoff_until > time.time(),
        }
