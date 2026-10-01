# -*- coding: utf-8 -*-
"""url_analyzer._http -- HTTP transport primitives, HTML parsing and FLAG detection constants.

从 yang_web/core/url_analyzer.py 机械拆分而来, 逐行搬运, 行为等价。
"""

from urllib.parse import urlparse, parse_qs, unquote, urlencode, urlunparse, quote
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from typing import List, Dict, Tuple, Optional, Callable
import re
import ssl
import socket
import time


# ============================================================================
#  HTTP Engine
# ============================================================================

_SSL_CONTEXT = ssl.create_default_context()

_SSL_CONTEXT.check_hostname = False
_SSL_CONTEXT.verify_mode = ssl.CERT_NONE

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 Yang-Web/2.1 CTF-Toolkit",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
}


DEFAULT_TIMEOUT = 5  # 短超时，auto_exploit 会跑很多请求

USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'



def send_request(url: str, timeout: int = DEFAULT_TIMEOUT, method: str = "GET",
                 post_data: bytes = None) -> Dict:
    """Send HTTP request and return structured response.

    Args:
        url: Target URL
        timeout: Request timeout in seconds
        method: HTTP method (GET or POST)
        post_data: POST body bytes (Content-Type: application/x-www-form-urlencoded)

    Returns:
        {"ok": bool, "url": str, "status": int, "headers": dict,
         "body": str (first 5000 chars), "body_len": int,
         "elapsed_ms": int, "error": str or None}
    """
    result = {
        "ok": False, "url": url, "status": 0, "headers": {},
        "body": "", "body_len": 0, "elapsed_ms": 0, "error": None,
    }
    try:
        headers = dict(DEFAULT_HEADERS)
        if post_data:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = Request(url, data=post_data, headers=headers, method=method)
        start = time.time()
        resp = urlopen(req, timeout=timeout, context=_SSL_CONTEXT)
        elapsed = int((time.time() - start) * 1000)
        body = resp.read()
        charset = "utf-8"
        ct = resp.headers.get("Content-Type", "")
        if "charset=" in ct:
            try:
                charset = ct.split("charset=")[-1].split(";")[0].strip()
            except Exception:
                pass
        try:
            body_str = body.decode(charset, errors="replace")
        except Exception:
            body_str = body.decode("utf-8", errors="replace")
        result.update({
            "ok": True, "status": resp.status,
            "headers": dict(resp.headers),
            "body": body_str[:5000], "body_len": len(body),
            "elapsed_ms": elapsed,
        })
    except HTTPError as e:
        result["status"] = e.code
        result["headers"] = dict(e.headers)
        try:
            body = e.read()
            result["body"] = body.decode("utf-8", errors="replace")[:5000]
            result["body_len"] = len(body)
        except Exception:
            pass
        result["ok"] = True
        result["error"] = f"HTTP {e.code}"
    except URLError as e:
        result["error"] = f"Connection error: {e.reason}"
    except socket.timeout:
        result["error"] = "Request timed out"
    except Exception as e:
        result["error"] = str(e)
    return result



def inject_payload(url: str, param: str, payload: str,
                   method: str = "append") -> str:
    """Inject a payload into a URL query parameter.

    Args:
        url: Base URL
        param: Target parameter name
        payload: Payload value to inject
        method: "append" (add to existing value) or "replace" (overwrite)

    Returns:
        Modified URL with injected payload
    """
    from urllib.parse import quote
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    payload_enc = quote(payload, safe='')
    if param not in params:
        new_query = parsed.query
        if new_query:
            new_query += "&"
        new_query += f"{param}={payload_enc}"
    else:
        new_params = {}
        for pname, pvalues in params.items():
            if pname == param:
                if method == "append":
                    new_params[pname] = [pvalues[0] + payload]
                else:
                    new_params[pname] = [payload]
            else:
                new_params[pname] = pvalues
        new_query = urlencode(new_params, doseq=True)
    return urlunparse((
        parsed.scheme, parsed.netloc, parsed.path,
        parsed.params, new_query, parsed.fragment
    ))



def analyze_response(body: str, detect_rule: Dict) -> Dict:
    """Analyze HTTP response body according to detection rules.

    detect_rule fields:
        "detect": "error" | "success" | "content" | "timeout" | "normal"
        "match": list of keyword strings to search for

    Returns:
        {"success": bool, "confidence": str, "detail": str}
    """
    rule_type = detect_rule.get("detect", "normal")
    match_words = detect_rule.get("match", [])
    result = {"success": False, "confidence": "", "detail": ""}

    SQL_ERRORS = [
        "You have an error in your SQL syntax",
        "Warning: mysql",
        "Unclosed quotation mark",
        "Microsoft OLE DB",
        "ODBC Driver",
        "SQLite3::",
        "PostgreSQL",
        "pg_query",
        "ORA-",
        "PLS-",
        "JDBC",
        "Unknown column",
        "Column not found",
        "doesn\u0027t exist",
        "no such table",
        "Division by zero",
        "supplied argument",
        "Call to a member function",
        "on a non-object",
        "Undefined index",
        "Undefined variable",
        "Fatal error",
        "Parse error",
        "syntax error",
        "Stack trace:",
        "Traceback (most recent call last)",
        "Warning:",
        "Notice:",
        "Error:",
        "XPATH syntax error",
        "updatexml",
        "near \"",
        "SqlException",
        "SqlCommand",
        "mysql_fetch",
        "mysql_num_rows",
        "mysql_error",
        "mysqli_error",
        "pg_exec",
        "odbc_exec",
        "mssql_query",
        "Incorrect syntax near",
    ]

    if rule_type == "error":
        for kw in SQL_ERRORS:
            if kw in body:
                result["success"] = True
                result["confidence"] = "High"
                result["detail"] = (
                    f"Error keyword detected: {kw[:60]} "
                    "- Possible SQL or application error leak"
                )
                return result
        result["detail"] = (
            "No known SQL error patterns found "
            "(vuln may still exist, try other methods)"
        )
    elif rule_type == "success":
        if body.strip():
            result["success"] = True
            result["confidence"] = "Medium"
            result["detail"] = "Response body non-empty, attack may have succeeded"
        else:
            result["detail"] = "Response body empty"
    elif rule_type == "content":
        if not match_words:
            result["detail"] = "No match keywords, assuming neutral"
            result["success"] = True
        else:
            found = [w for w in match_words if w in body]
            if found:
                result["success"] = True
                result["confidence"] = "Very High"
                result["detail"] = (
                    f"Match found: {found[:3]} - Payload reflected in response"
                )
            else:
                result["detail"] = f"No match for: {match_words[:3]}"
    elif rule_type == "timeout":
        result["detail"] = "Timeout detection (judged externally)"
        result["success"] = True
    elif rule_type == "normal":
        result["detail"] = "Neutral detection, return raw response"
        result["success"] = True
    return result



# ============================================================================
#  Page Crawler
# ============================================================================

def crawl_page(url: str, timeout: int = 8) -> Dict:
    """Fetch and crawl a page, extracting forms, links, and input parameters.

    Returns:
        {"ok": bool, "url": str, "status": int, "page_title": str,
         "forms": [{"action": str, "method": str,
                    "inputs": [{"name": str, "type": str, "value": str}]}],
         "links": [{"url": str, "text": str}],
         "discovered_params": [str],
         "stats": {"forms_count": int, "links_count": int, "params_count": int},
         "error": str or None}
    """
    result = {
        "ok": False, "url": url, "status": 0, "page_title": "",
        "forms": [], "links": [], "discovered_params": [],
        "stats": {"forms_count": 0, "links_count": 0, "params_count": 0},
        "error": None,
    }
    try:
        resp = send_request(url, timeout=timeout)
        if not resp["ok"]:
            result["error"] = resp.get("error", "Request failed")
            return result
        body = resp["body"]
        result["ok"] = True
        result["url"] = resp["url"]
        result["status"] = resp["status"]
        result["page_title"] = _extract_title(body)
        result["forms"] = _extract_forms(body, url)
        result["links"] = _extract_links_with_params(body, url)[:20]
        all_params = set()
        for form in result["forms"]:
            for inp in form.get("inputs", []):
                name = inp.get("name", "").strip()
                if name:
                    all_params.add(name)
        for link in result["links"]:
            p = urlparse(link["url"])
            if p.query:
                for pn in parse_qs(p.query, keep_blank_values=True):
                    all_params.add(pn)
        result["discovered_params"] = sorted(all_params)

        # ★ 扫描PHP源码中的 $_GET / $_POST / $_REQUEST 参数
        # 先去掉HTML标签（因为highlight_file会把源码加span）
        clean_body = re.sub(r'<[^>]+>', '', body)
        php_params = set()
        for pattern in [r'\$_GET\[["\'](\w+)["\']',
                        r'\$_POST\[["\'](\w+)["\']',
                        r'\$_REQUEST\[["\'](\w+)["\']',
                        r'\$_GET\[(\$\w+)\]']:
            for m in re.finditer(pattern, clean_body):
                php_params.add(m.group(1))
        if php_params:
            all_params.update(php_params)
            result["discovered_params"] = sorted(all_params)
        result["stats"] = {
            "forms_count": len(result["forms"]),
            "links_count": len(result["links"]),
            "params_count": len(result["discovered_params"]),
        }
    except Exception as e:
        result["error"] = str(e)
    return result



def _extract_title(html: str) -> str:
    """Extract page title from HTML."""
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip() if m else ""



def _extract_forms(html: str, base_url: str) -> List[Dict]:
    """Extract all forms from HTML page."""
    forms = []
    fm_pat = re.compile(r"<form\b([^>]*?)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
    for fm in fm_pat.finditer(html):
        attrs = fm.group(1)
        body = fm.group(2)
        action = _get_attr(attrs, "action") or base_url
        method = (_get_attr(attrs, "method") or "GET").upper()
        if not action.startswith(("http://", "https://")):
            pb = urlparse(base_url)
            if action.startswith("/"):
                action = f"{pb.scheme}://{pb.netloc}{action}"
            else:
                bp = pb.path.rsplit("/", 1)[0] if "/" in pb.path else ""
                action = f"{pb.scheme}://{pb.netloc}{bp}/{action}"
        inputs = []
        ip = re.compile(r"<(?:input|textarea|select|button)\b([^>]*?)(?:/?>)", re.IGNORECASE)
        for im in ip.finditer(body):
            ia = im.group(1)
            name = _get_attr(ia, "name")
            itype = _get_attr(ia, "type") or "text"
            val = _get_attr(ia, "value") or ""
            if name and itype.lower() not in ("submit", "button", "reset", "image"):
                inputs.append({"name": name, "type": itype.lower(), "value": val})
        hp = re.compile(r"<input\b([^>]*?type\s*=\s*[\"\u0027]hidden[\"\u0027][^>]*?)(?:/?>)", re.IGNORECASE)
        for hm in hp.finditer(body):
            ha = hm.group(1)
            name = _get_attr(ha, "name")
            val = _get_attr(ha, "value") or ""
            if name and not any(i["name"] == name for i in inputs):
                inputs.append({"name": name, "type": "hidden", "value": val})
        if inputs:
            forms.append({"action": action, "method": method, "inputs": inputs})
    return forms



def _extract_links_with_params(html: str, base_url: str) -> List[Dict]:
    """Extract links that contain query parameters from HTML."""
    links = []
    lp = re.compile(r"<a\b[^>]*?href=[\"\u0027](.*?)[\"\u0027]", re.IGNORECASE)
    seen = set()
    for m in lp.finditer(html):
        href = m.group(1)
        if "?" not in href:
            continue
        tm = re.search(r"<a\b[^>]*?>(.*?)</a>", html[m.start():m.start() + 500],
                       re.IGNORECASE | re.DOTALL)
        lt = re.sub(r"<[^>]+>", "", tm.group(1)).strip() if tm else ""
        if not href.startswith(("http://", "https://")):
            pb = urlparse(base_url)
            if href.startswith("/"):
                href = f"{pb.scheme}://{pb.netloc}{href}"
            else:
                bp = pb.path.rsplit("/", 1)[0] if "/" in pb.path else ""
                href = f"{pb.scheme}://{pb.netloc}{bp}/{href}"
        if href not in seen:
            seen.add(href)
            links.append({"url": href, "text": lt[:60]})
    return links[:20]



def _get_attr(attrs_str: str, name: str) -> str:
    """Extract attribute value from HTML attribute string."""
    m = re.search(rf"{name}\s*=\s*[\"\u0027]([^\"\u0027]*?)[\"\u0027]",
                  attrs_str, re.IGNORECASE)
    return m.group(1) if m else ""



# ============================================================================
#  Auto-Exploit Engine — 自动解题引擎
# ============================================================================

FLAG_PATHS = [
    "/flag", "/flag.txt", "/flag.php", "/flag.html",
    "/tmp/flag", "/tmp/flag.txt",
    "/var/www/html/flag", "/var/www/html/flag.php",
    "/home/ctf/flag", "/home/flag",
    "/etc/flag", "/root/flag",
    "flag.txt", "flag.php", "flag",
]


FLAG_RE = re.compile(
    r'(?:flag|ctf|iscc|hctf|ddctf|realworld|n1ctf|suctf|wmctf|geesec|dasctf|sigpwny|cyber|hack|pico|tjctf|angstrom|dctf|ractf|zh3r0|inctf|darkctf|csictf|ritsec|nactf|b01lers|kksctf|'
    r'0xgame|0xctf|nssctf|moectf|gactf|actf|starctf|ructf|plaidctf|defenit|hitcon|balsn|asis|codegate|0ctf|tctf|wctf|ractf|hxp|hackthebox|csaw)'
    r'\{([^{};:#\n]{4,})\}', re.IGNORECASE
)
