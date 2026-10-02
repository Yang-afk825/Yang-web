"""yang_web.core.multi_stage 子模块 _analyzer（自 multi_stage.py 拆分，请勿手工重排）。"""

from __future__ import annotations
import re
import ssl
import time
import json
import base64
import urllib.request
import urllib.error
import urllib.parse
from urllib.parse import urljoin
import http.cookiejar
from typing import Dict, List, Optional, Tuple, Set, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError

from ._common import (FLAG_RE, JS_REDIRECT_RE, PAGE_FINGERPRINTS)



# ═══════════════════════════════════════════════════════════
#  Page Analyzer — 自动识别页面类型
# ═══════════════════════════════════════════════════════════

class PageAnalyzer:
    """分析 HTTP 响应，识别页面类型、提取关键信息."""

    def __init__(self):
        pass

    def analyze(self, html: str, url: str = "", headers: dict = None) -> dict:
        """分析页面返回: {type, forms, inputs, redirects, flags, hints, is_terminal}."""
        result = {
            "type": "unknown",
            "forms": [],
            "inputs": [],
            "redirects": [],
            "flags": [],
            "hints": [],
            "is_terminal": False,
            "title": "",
        }

        if not html:
            return result

        # Flag 检测
        flags = FLAG_RE.findall(html)
        if flags:
            result["flags"] = flags
            result["hints"].append(f"Flag found in response: {flags[0]}")

        # 标题
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
        if m:
            result["title"] = m.group(1).strip()[:80]

        # JS 重定向提取
        for pattern in JS_REDIRECT_RE:
            for match in re.findall(pattern, html, re.I):
                if match and match not in result["redirects"]:
                    result["redirects"].append(match)
                    result["hints"].append(f"JS redirect target: {match}")

        # HTML meta refresh 重定向
        for match in re.findall(r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+url=([^\s"\'>]+)', html, re.I):
            if match and match not in result["redirects"]:
                result["redirects"].append(match)

        # 表单分析
        forms = re.findall(r'<form[^>]*>(.*?)</form>', html, re.I | re.S)
        for f_html in forms:
            form_info = {"action": "", "method": "POST", "inputs": [], "textarea": []}

            # action
            am = re.search(r'action\s*=\s*["\']([^"\']*)', f_html, re.I)
            if am:
                form_info["action"] = am.group(1)

            # method
            mm = re.search(r'method\s*=\s*["\'](\w+)', f_html, re.I)
            if mm:
                form_info["method"] = mm.group(1).upper()

            # inputs
            for nm in re.findall(r'<input[^>]*name\s*=\s*["\']([^"\']+)', f_html, re.I):
                form_info["inputs"].append(nm)

            # textareas
            for nm in re.findall(r'<textarea[^>]*name\s*=\s*["\']([^"\']+)', f_html, re.I):
                form_info["textarea"].append(nm)

            all_inputs = form_info["inputs"] + form_info["textarea"]
            if all_inputs:
                result["forms"].append(form_info)
                result["inputs"].extend(all_inputs)

        # 页面类型指纹匹配
        scores = {}
        html_lower = html.lower()
        for ptype, fingerprint in PAGE_FINGERPRINTS.items():
            score = 0
            # 关键词匹配
            for kw in fingerprint.get("keywords", []):
                if kw in html_lower:
                    score += 10
            # 表单匹配
            fdefs = fingerprint.get("forms", []) or fingerprint.get("inputs", [])
            if fdefs and result["forms"]:
                for form_data in result["forms"]:
                    form_inputs = form_data["inputs"] + form_data["textarea"]
                    for fdef in fdefs:
                        if isinstance(fdef, dict):
                            expected = fdef.get("inputs", [])
                            if expected and all(ei in form_inputs for ei in expected):
                                score += 25
                        elif isinstance(fdef, str) and fdef in form_inputs:
                            score += 15
            # content_types
            if "content_types" in fingerprint:
                ct = headers.get("Content-Type", "") if headers else ""
                for t in fingerprint["content_types"]:
                    if t in ct:
                        score += 10
            if score > 0:
                scores[ptype] = score

        if scores:
            result["type"] = max(scores, key=scores.get)
            if scores[result["type"]] < 20:
                result["type"] = "unknown"

        # 终端页面检测
        if result["type"] in PAGE_FINGERPRINTS and PAGE_FINGERPRINTS[result["type"]].get("is_terminal"):
            result["is_terminal"] = True

        # 错误/提示信息提取
        # PHP warnings
        for w in re.findall(r'<b>(Warning|Notice|Fatal error)</b>.*?<br', html, re.I):
            result["hints"].append(f"PHP: {w[:100]}")
        # alert messages
        for a in re.findall(r"alert\(['\"]([^'\"]+)['\"]", html, re.I):
            result["hints"].append(f"Alert: {a}")

        return result
