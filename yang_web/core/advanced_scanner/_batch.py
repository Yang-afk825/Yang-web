"""yang_web.core.advanced_scanner 子模块 _batch（自 advanced_scanner.py 拆分，请勿手工重排）。"""

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



# ═══════════════════════════════════════════════════════════
#  6. Batch Target Runner
# ═══════════════════════════════════════════════════════════

class BatchRunner:
    """多目标批量处理器.

    支持:
    - 从IP段生成目标
    - 从文件读取URL列表
    - 批量分析+扫描+利用
    """

    def __init__(self, max_workers: int = 5):
        self.max_workers = max_workers
        self.results: List[dict] = []

    def run(self, urls: List[str], on_progress=None, on_target_done=None) -> List[dict]:
        """批量处理多个URL.

        Args:
            urls: Target URL list
            on_progress: Callable(url, stage, detail)
            on_target_done: Callable(url, result_dict)

        Returns:
            [{"url": str, "flag": str or None, "analysis": {...}, ...}]
        """
        all_results = []

        def _emit(url, stage, detail):
            if on_progress:
                try:
                    on_progress(url, stage, detail)
                except Exception:
                    pass

        def _process_one(url: str) -> dict:
            """Process a single target end-to-end."""
            result = {"url": url, "flag": None, "analysis": {}, "error": None}

            _emit(url, "init", "开始处理...")

            # Phase 1: URL analysis (lazy import to avoid circular deps)
            try:
                from yang_web.core.url_analyzer import analyze_url
                analysis = analyze_url(url)
                result["analysis"] = analysis
                _emit(url, "analyzed", f"发现 {len(analysis.get('results', []))} 种漏洞")
            except Exception as e:
                result["error"] = f"Analysis failed: {e}"
                _emit(url, "error", str(e))
                return result

            # Phase 2: Quick directory scan
            try:
                scanner = DictScanner(url, max_workers=10, timeout=2)
                scan_result = scanner.scan()
                result["scan"] = scan_result
                if scan_result.get("flag"):
                    result["flag"] = scan_result["flag"]
                    _emit(url, "flag", scan_result["flag"])
                    return result
                _emit(url, "scanned", f"发现 {scan_result.get('count', 0)} 路径")
            except Exception as e:
                _emit(url, "scan_error", str(e)[:60])

            # Phase 3: Attack chains
            try:
                vuln_results = analysis.get("results", [])
                if vuln_results:
                    chain_engine = AttackChainEngine(url)
                    chain_result = chain_engine.chain(vuln_results, on_progress=None)
                    result["chain"] = chain_result
                    if chain_result.get("flag"):
                        result["flag"] = chain_result["flag"]
                        _emit(url, "chain_flag", chain_result["flag"])
                        return result
            except Exception as e:
                _emit(url, "chain_error", str(e)[:60])

            # Phase 4: Auto exploit
            try:
                from yang_web.core.url_analyzer import auto_exploit
                fingerprint = analysis.get("fingerprint", {})
                exploit_result = auto_exploit(url, vuln_results,
                    fingerprint=fingerprint)
                result["exploit"] = exploit_result
                if exploit_result.get("flag"):
                    result["flag"] = exploit_result["flag"]
            except Exception as e:
                _emit(url, "exploit_error", str(e)[:60])

            return result

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(_process_one, url): url for url in urls}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    r = future.result(timeout=120)
                    all_results.append(r)
                    if on_target_done:
                        try:
                            on_target_done(url, r)
                        except Exception:
                            pass
                except Exception:
                    all_results.append({"url": url, "error": "Timeout or exception"})

        self.results = all_results
        return all_results
