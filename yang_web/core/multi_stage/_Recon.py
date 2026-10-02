"""yang_web.core.multi_stage._engine 混入 _Recon —— 目标侦察（URL 发现与 API 端点提取）。"""

from __future__ import annotations
import re
from urllib.parse import urljoin
from typing import Dict, List, Optional, Tuple, Set, Callable

class _Recon:
    """目标侦察（URL 发现与 API 端点提取）。"""


    # ── URL Discovery ──

    def _discover_urls(self, url: str, _emit) -> List[str]:
        """当基URL返回404时，自动探测常见入口路径."""
        common_paths = [
            '/login.php', '/login', '/index.php', '/admin',
            '/admin.php', '/register.php', '/register',
            '/api', '/api/v1', '/api/login', '/auth', '/auth/login',
            '/home', '/home.php', '/main', '/dashboard',
            '/flag.php', '/flag', '/secret', '/user',
            '/upload', '/upload.php', '/shell.php',
        ]
        found = []
        from urllib.parse import urlparse
        parsed = urlparse(url)

        for path in common_paths:
            if self._cancelled:
                break
            test_url = f"{parsed.scheme}://{parsed.netloc}{path}"
            resp = self.http.request(test_url)
            if resp["status"] in (200, 302, 301, 403):
                found.append(test_url)
                _emit("discover", path, f"status={resp['status']}")

        return found

    # ── JS API Endpoint Detection ──

    def _extract_api_endpoints(self, html: str, base_url: str = "") -> List[str]:
        """Extract fetch()/XMLHttpRequest API paths from JS in HTML."""
        endpoints = set()
        # First: find referenced JS files
        js_urls = []
        for m in re.findall(r'<script\s+src\s*=\s*["\']([^"\']+)["\']', html, re.I):
            if not m.startswith('http'):
                from urllib.parse import urljoin
                m = urljoin(base_url, m)
            js_urls.append(m)

        # Extract endpoints from inline JS + external JS
        for js_url in [None] + js_urls[:5]:  # None = inline HTML
            if self._cancelled:
                break
            source = html
            if js_url:
                resp = self.http.request(js_url)
                if resp.get("error") or resp.get("status", 0) != 200:
                    continue
                source = resp.get("body", "")
            for m in re.findall(r"fetch\s*\(\s*['\"]([^'\"]+)['\"]", source):
                endpoints.add(m)
            for m in re.findall(r"\.open\s*\(\s*['\"]\w+['\"]\s*,\s*['\"]([^'\"]+)['\"]", source):
                endpoints.add(m)
            for m in re.findall(r"axios\.(?:get|post|put|patch)\s*\(\s*['\"]([^'\"]+)['\"]", source):
                endpoints.add(m)
        return list(endpoints)
