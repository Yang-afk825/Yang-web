"""yang_web.core.smart_solver._web 混入 _WebPhp —— PHP 专项（反序列化 / eval RCE / 文件包含）。"""

from __future__ import annotations

class _WebPhp:
    """PHP 专项（反序列化 / eval RCE / 文件包含）。"""

    def _try_php_unserialize(self):
        """PHP 反序列化漏洞自动检测与利用 — 委托给 php_unserialize 通用引擎.

        php_unserialize.py 统一处理所有变体:
            - 基础属性验证 | __wakeup 绕过 (CVE-2016-7124)
            - == 弱类型绕过 (bool/int) | private/protected 编码
            - 简单 POP 链 (__destruct → 危险函数)
        """
        self.log("PHP-Unserialize", "running", "php_unserialize 通用求解器 v1.0")
        from yang_web.core.php_unserialize import auto_solve

        def _progress(stage, item, status):
            self.log(stage, item, status)

        result = auto_solve(self.url, on_progress=_progress)
        if result:
            self.flag = result.get('flag')
            if self.flag:
                self.log("PHP-Unserialize", "flag!",
                         f"class={result.get('class')}, strategy={result.get('strategy')}: {self.flag}")
            else:
                self.log("PHP-Unserialize", "none", "All classes & strategies tried, no flag")

    def _try_php_eval_rce(self):
        """PHP MD5 碰撞 + eval() RCE — 委托给 php_eval_rce 通用引擎。

        php_eval_rce.py 覆盖的题型：
            - md5($r1)===md5($r2) && $r1!==$r2 碰撞检查
            - eval($r3) + WAF 关键字黑名单（只挡完整 keyword）
            - 字符串拼接绕过关键字（'fl'.'ag' → /flag）
            - GET/POST/COOKIE 多入口自动探测
        """
        self.log("PHP-EvalRCE", "running", "php_eval_rce 通用求解器 v1.0")
        from yang_web.core.php_eval_rce import auto_solve as eval_auto_solve

        def _progress(msg):
            self.log("PHP-EvalRCE", msg, "")

        result = eval_auto_solve(self.url, on_progress=_progress)
        if result:
            self.flag = result.get('flag')
            if self.flag:
                self.log("PHP-EvalRCE", "flag!",
                         f"strategy={result.get('strategy')}: {self.flag}")
            else:
                self.log("PHP-EvalRCE", "none", result.get('status', 'No flag'))

    def _try_php_file_inclusion(self):
        """PHP 文件包含漏洞自动检测与利用 — 委托给 php_lfi 通用引擎.

        php_lfi.py 覆盖的题型:
            - HelloCTF PHPinclude-labs 全系列 (file://, php://filter 等)
            - include/require(_once) + 用户可控参数
            - 协议约束识别 (allow_url_fopen/allow_url_include)
            - 路径遍历 + 常见 flag 位置自动探测
            - php://filter base64 编码绕过 PHP 执行
        """
        self.log("PHP-LFI", "running", "php_lfi 通用求解器 v1.0")
        from yang_web.core.php_lfi import auto_solve as lfi_auto_solve

        def _progress(stage, item, status):
            self.log(stage, item, status)

        result = lfi_auto_solve(self.url, on_progress=_progress)
        if result:
            self.flag = result.get('flag')
            if self.flag:
                self.log("PHP-LFI", "flag!",
                         f"param={result.get('param')}, path={result.get('path')}, strategy={result.get('strategy')}: {self.flag}")
            else:
                self.log("PHP-LFI", "none", result.get('status', 'No flag found'))
