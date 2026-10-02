"""yang_web.core.advanced_scanner 子模块 _solver（自 advanced_scanner.py 拆分，请勿手工重排）。"""

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

from ._chain import (AttackChainEngine)
from ._dict import (DictScanner)
from ._differ import (ResponseDiffer)
from ._method import (MethodAutoSwitch)
from ._port import (QuickPortScanner)
from ._rate import (SmartRateLimiter)



# ═══════════════════════════════════════════════════════════
#  Unified Advanced Solver — 整合所有新引擎
# ═══════════════════════════════════════════════════════════

class AdvancedSolver:
    """统一高级求解器 — 整合所有新引擎.

    与现有SmartSolver互补:
    - SmartSolver: 多类型分类+路由 (Web/Crypto/Binary/Blockchain)
    - AdvancedSolver: Web深度扫描+升级利用 (本模块)
    """

    def __init__(self):
        self.rate_limiter = SmartRateLimiter()

    def deep_scan(self, url: str, analysis_result: dict = None,
                  on_progress=None, on_flag=None) -> dict:
        """对单个URL执行深度扫描.

        Pipeline:
        1. 端口发现 → 了解攻击面
        2. 字典扫描 → 发现隐藏路径/源码
        3. 方法自适应 → 最佳HTTP方法
        4. 响应对比 → 盲注精准检测
        5. 攻击链升级 → 二阶段利用
        6. 自动利用 → 提取Flag
        """
        t0 = time.time()
        flag = None
        stages_executed: List[str] = []

        def _emit(stage, item, status):
            stages_executed.append(f"[{stage}] {item}: {status}")
            if on_progress:
                try:
                    on_progress(stage, item, status)
                except Exception:
                    pass

        def _found(f):
            nonlocal flag
            if not flag:
                flag = f
                if on_flag:
                    try:
                        on_flag(f)
                    except Exception:
                        pass

        # Phase 1: Quick port scan
        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname or "127.0.0.1"
            if host in ("127.0.0.1", "localhost", "::1"):
                _emit("ports", "skip", "本地回环地址，跳过端口扫描")
            else:
                port_scanner = QuickPortScanner(host, timeout=0.5)
                port_result = port_scanner.scan(on_progress=_emit)
                _emit("ports", f"{host}", f"开放 {port_result['open']}/{port_result['total']} 端口")
        except Exception as e:
            _emit("ports", "skip", f"端口扫描异常: {str(e)[:40]}")

        # Phase 2: Dictionary scan (L1+L2)
        scanner = DictScanner(url, max_workers=20, timeout=2, levels=[1, 2])
        scan_result = scanner.scan(on_progress=_emit, on_flag=_found)
        if scan_result.get("flag"):
            return {"success": True, "flag": flag, "source": "dict_scan",
                    "stages": stages_executed, "timing_ms": int((time.time()-t0)*1000)}
        _emit("dict_scan", "完成", f"发现 {scan_result['count']} 路径")

        # Phase 3: Method auto-switch check
        vuln_results = []  # Ensure always defined
        fingerprint = {}
        if analysis_result and isinstance(analysis_result, dict):
            vuln_results = analysis_result.get("results", []) or []
            fingerprint = analysis_result.get("fingerprint", {})
            if vuln_results:
                params = vuln_results[0].get("params", [])
                if params:
                    auto_switch = MethodAutoSwitch(url)
                    sw_result = auto_switch.try_all_methods(params[0], "test")
                    _emit("method", sw_result["best_method"], sw_result["recommendation"])

            # Phase 4: Response diffing for top vulnerability
            if vuln_results:
                top_vuln = max(vuln_results, key=lambda r: r.get("confidence", 0))
                vtype = top_vuln.get("type", "")
                params = top_vuln.get("params", [])

                if vtype == "SQLi" and params:
                    differ = ResponseDiffer(url)
                    differ.set_baseline()
                    sql_probes = ["'", '"', "' OR '1'='1", "1' AND 1=1--",
                                 "1' AND sleep(3)--", "' UNION SELECT 1--"]
                    differ.batch_test(params[0], sql_probes,
                        on_progress=_emit, on_flag=_found)

        # Phase 5: Attack chains
        if vuln_results:
            chain_engine = AttackChainEngine(url)
            chain_result = chain_engine.chain(vuln_results,
                on_progress=_emit, on_flag=_found)
            if chain_result.get("flag"):
                return {"success": True, "flag": flag, "source": "attack_chain",
                        "stages": stages_executed,
                        "timing_ms": int((time.time()-t0)*1000)}

        # Phase 6: Run existing auto_exploit as fallback
        try:
            from yang_web.core.url_analyzer import auto_exploit
            exploit_result = auto_exploit(url, vuln_results, fingerprint=fingerprint,
                on_progress=_emit, on_found=_found)
            if exploit_result.get("flag"):
                return {"success": True, "flag": flag, "source": "auto_exploit",
                        "stages": stages_executed,
                        "timing_ms": int((time.time()-t0)*1000)}
        except Exception:
            pass

        return {
            "success": bool(flag),
            "flag": flag,
            "stages": stages_executed,
            "scan_result": scan_result,
            "timing_ms": int((time.time() - t0) * 1000),
        }
