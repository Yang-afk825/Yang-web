"""yang_web.core.smart_solver._web 混入 _WebBase —— 主流程与基础设施（初始化/日志/solve 编排/初步探测/目录扫描/结果封装）。"""

from __future__ import annotations
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, List, Optional, Tuple, Callable, Any
from ._common import (_detect_php_source, _http_headers, _make_ssl_ctx, decode_body, find_flag, http_get)

class _WebBase:
    """主流程与基础设施（初始化/日志/solve 编排/初步探测/目录扫描/结果封装）。"""
    
    def __init__(self, url: str):
        self.url = url.rstrip("/") if url else ""
        self.results: List[dict] = []
        self.flag: Optional[str] = None
    
    def log(self, step: str, status: str, detail: str = ""):
        self.results.append({"step": step, "status": status, "detail": detail})
    
    def solve(self) -> dict:
        """执行完整的 Web 求解流程."""
        if not self.url:
            return {"success": False, "flag": None, "results": self.results,
                    "category": "web", "error": "No URL provided"}
        
        # 1. 基础探测
        self._probe_initial()
        if self.flag:
            return self._final_result(True)
        
        # 1.5 PHP 反序列化自动检测与利用
        self._try_php_unserialize()
        if self.flag:
            return self._final_result(True)
        
        # 1.6 PHP eval RCE（MD5碰撞+WAF绕过）
        self._try_php_eval_rce()
        if self.flag:
            return self._final_result(True)
        
        # 2. 目录扫描
        self._scan_directories()
        if self.flag:
            return self._final_result(True)
        
        # 3. SQL 注入探测
        self._try_sqli_basic()
        if self.flag:
            return self._final_result(True)
        
        # 3.5 JWT 令牌攻击 (若检测到 JWT Cookie/Header)
        self._try_jwt_attack()
        if self.flag:
            return self._final_result(True)
        
        # 4. SSTI 探测 (增强: 支持 Cookie 认证的 POST 表单)
        self._try_ssti_detection()
        if self.flag:
            return self._final_result(True)
        
        # 4.5 SSTI WAF 绕过 (用于已检测到 SSTI 但被 WAF 拦截的情况)
        self._try_ssti_waf_bypass()
        if self.flag:
            return self._final_result(True)
        
        # 4.6 WSGI environ 迭代 (enterpris WAF — 用 {% for %} 绕过 bracket 禁用) NEW
        self._try_env_iterate()
        if self.flag:
            return self._final_result(True)
        
        # 5. PHP 文件包含自动检测与利用 (HelloCTF/PHPinclude-labs 等)
        self._try_php_file_inclusion()
        if self.flag:
            return self._final_result(True)
        
        # 5.5 LFI / 路径遍历 (通用)
        self._try_lfi()
        if self.flag:
            return self._final_result(True)
        
        # 6. 信息泄露路径
        self._try_leak_paths()
        if self.flag:
            return self._final_result(True)
        
        # 7. SSRF 探测
        self._try_ssrf()
        if self.flag:
            return self._final_result(True)
        
        # 7.5 SSRF DNS Rebinding → RCE
        self._try_ssrf_rebind()
        if self.flag:
            return self._final_result(True)
        
        # 8. RCE 简单探测
        self._try_rce()
        if self.flag:
            return self._final_result(True)
        
        # 8.5 长度限制 RCE (7字符限制 / 数字参数名)
        self._try_length_limit_rce()
        if self.flag:
            return self._final_result(True)
        
        # 9. bashFuck 无字母RCE (检测 WAF 并生成二进制替换payload)
        self._try_bashfuck_rce()
        if self.flag:
            return self._final_result(True)
        
        return self._final_result(False)
    
    def _probe_initial(self):
        """初始探测：获取页面基本信息."""
        self.log("Probe", "running", self.url)
        code, body, _ = http_get(self.url)
        if code is None:
            self.log("Probe", "fail", "Connection failed")
            return
        
        text = decode_body(body)
        self.log("Probe", "ok", f"HTTP {code}, {len(body)} bytes")
        
        # 检查页面是否直接包含 flag
        f = find_flag(text)
        if f:
            self.flag = f
            self.log("Flag found in page", "flag!", f)
        
        # 识别技术栈
        tech_hints = []
        if "php" in text.lower() or ".php" in self.url:
            tech_hints.append("PHP")
        if "jsp" in text.lower() or ".jsp" in self.url:
            tech_hints.append("Java/JSP")
        if "asp" in text.lower() or ".asp" in self.url:
            tech_hints.append("ASP.NET")
        if "node" in text.lower() or "express" in text.lower():
            tech_hints.append("Node.js")
        if "python" in text.lower() or "django" in text.lower() or "flask" in text.lower():
            tech_hints.append("Python")
        if tech_hints:
            self.log("Tech Stack", "info", ", ".join(tech_hints))
    
    def _scan_directories(self):
        """目录扫描."""
        self.log("Dir Scan", "running", f"{len(self.DIR_LIST)} paths")
        found = []
        for path in self.DIR_LIST:
            test_url = f"{self.url}/{path.lstrip('/')}"
            code, body, _ = http_get(test_url)
            if code and code != 404:
                text = decode_body(body)
                f = find_flag(text)
                detail = f"HTTP {code}"
                if f:
                    detail += f" [FLAG: {f}]"
                    self.flag = f
                found.append({"path": path, "code": code, "size": len(body)})
                if f:
                    break
        
        self.log("Dir Scan", f"found {len(found)}", 
                 ", ".join(p["path"] for p in found[:10]))
    
    def _get_render_urls(self):
        """获取可能的 render endpoint URLs."""
        urls = []
        base = self.url.rstrip("/")
        for path in ["/render", "/dashboard", "/template", "/test", "/preview"]:
            urls.append(urllib.parse.urljoin(base + "/", path.lstrip("/")))
        return urls
    
    def _try_payload_get(self, url, payload, label):
        """尝试用 GET 参数 tpl= 发送 payload."""
        try:
            encoded = urllib.parse.quote(payload)
            if '?' in url:
                test_url = f"{url}&tpl={encoded}"
            else:
                test_url = f"{url}?tpl={encoded}"
            headers = dict(_http_headers())
            if hasattr(self, '_jwt_bypass_cookie'):
                headers["Cookie"] = self._jwt_bypass_cookie
            req = urllib.request.Request(test_url, headers=headers)
            ctx = _make_ssl_ctx()
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                rbody = resp.read()
                rtext = decode_body(rbody)
                if "WAF detected" in rtext or not rtext.strip():
                    return None
                return rtext
        except Exception:
            return None

    def _final_result(self, success: bool) -> dict:
        return {
            "success": success,
            "flag": self.flag,
            "results": self.results,
            "category": "web",
            "url": self.url,
        }
