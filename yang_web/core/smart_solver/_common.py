"""yang_web.core.smart_solver 子模块 _common（自 smart_solver.py 拆分，请勿手工重排）。"""

from __future__ import annotations
import re
import json
import ssl
import socket
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, List, Optional, Tuple, Callable, Any





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
