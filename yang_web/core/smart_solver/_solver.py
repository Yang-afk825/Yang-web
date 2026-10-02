"""yang_web.core.smart_solver 子模块 _solver（自 smart_solver.py 拆分，请勿手工重排）。"""

from __future__ import annotations
import re
import json
import ssl
import socket
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, List, Optional, Tuple, Callable, Any

from ._binary import (BinaryAnalyzer)
from ._blockchain import (BlockchainAnalyzer)
from ._common import (classify_problem)
from ._crypto import (CryptoSmartSolver)
from ._misc import (MiscAnalyzer)
from ._web import (WebSmartSolver)



# ═══════════════════════════════════════════════════════════
#  智能求解编排器
# ═══════════════════════════════════════════════════════════

class SmartSolver:
    """顶层智能求解编排器 — 自动分类 + 路由求解.
    
    Usage:
        solver = SmartSolver()
        result = solver.solve(metadata={
            "name": "SCTF 2026 phpStilAlive",
            "tags": [{"name": "Web"}, {"name": "PHP"}],
            "problemType": 1,
            "desc": "SCTF 2026 Web / PHP dynamic",
        }, url="http://container-url:port/")
    """
    
    def __init__(self):
        self.results_history: List[dict] = []
        self.categories_stats: Dict[str, int] = {}
    
    def solve(self, metadata: dict, url: str = "", filepath: str = "",
              ciphertext: str = "", source: str = "", bytecode: str = "") -> dict:
        """智能求解入口.
        
        Args:
            metadata: 题目元数据 (name, tags, desc, etc.)
            url: Web 题目 URL
            filepath: 附件文件路径
            ciphertext: 密码题目密文
            source: 区块链题目源码
            bytecode: 区块链题目字节码
        
        Returns:
            {"success": bool, "flag": str|None, "category": str, "results": [...], ...}
        """
        # Step 1: 分类
        category = classify_problem(metadata)
        self.log(category, f"Classified as: {category}")
        self.categories_stats[category] = self.categories_stats.get(category, 0) + 1
        
        result = {"success": False, "flag": None, "category": category, "results": []}
        
        # Step 2: 路由求解
        if category == "web" and url:
            result = self._solve_web(url)
        elif category == "web" and not url:
            result = {"success": False, "flag": None, "category": "web",
                      "error": "No URL provided for Web problem",
                      "results": [{"step": "Pre", "status": "fail",
                                   "detail": "Need container URL to attack"}]}
        elif category == "crypto" and ciphertext:
            result = self._solve_crypto(ciphertext)
        elif category == "crypto" and not ciphertext:
            result = {"success": False, "flag": None, "category": "crypto",
                      "error": "Need ciphertext", "results": []}
        elif category in ("pwn", "reverse") and filepath:
            result = self._solve_binary(filepath)
        elif category in ("pwn", "reverse") and not filepath:
            result = {"success": False, "flag": None, "category": category,
                      "error": "Need binary file (ELF/PE)",
                      "results": []}
        elif category == "blockchain":
            result = self._solve_blockchain(source, bytecode)
        elif category == "misc":
            result = self._solve_misc(filepath) if filepath else {
                "success": False, "flag": None, "category": "misc",
                "error": "Need file for analysis",
                "results": [{"step": "Pre", "status": "info",
                             "detail": "Misc problems need file analysis"}]}
        else:
            result = {
                "success": False, "flag": None, "category": "unknown",
                "results": [{"step": "Classification", "status": "fail",
                             "detail": f"Cannot classify: {metadata.get('name', '?')}"}]}
        
        self.results_history.append(result)
        return result
    
    def log(self, category: str, detail: str):
        """记录分类日志."""
        pass  # Internal logging
    
    def _solve_web(self, url: str) -> dict:
        solver = WebSmartSolver(url)
        return solver.solve()
    
    def _solve_crypto(self, ciphertext: str) -> dict:
        solver = CryptoSmartSolver(ciphertext)
        return solver.solve()
    
    def _solve_binary(self, filepath: str) -> dict:
        analyzer = BinaryAnalyzer(filepath)
        return analyzer.analyze()
    
    def _solve_blockchain(self, source: str = "", bytecode: str = "") -> dict:
        analyzer = BlockchainAnalyzer(source, bytecode)
        return analyzer.analyze()
    
    def _solve_misc(self, filepath: str) -> dict:
        analyzer = MiscAnalyzer(filepath)
        return analyzer.analyze()
    
    def batch_solve(self, problems: List[dict], 
                    containers: Dict[str, str] = None,
                    attachments: Dict[str, str] = None) -> List[dict]:
        """批量求解多道题.
        
        Args:
            problems: 题目列表
            containers: {problem_id: url} 容器URL映射
            attachments: {problem_id: filepath} 附件文件映射
        
        Returns:
            [{...}, ...] 每道题的求解结果
        """
        if containers is None:
            containers = {}
        if attachments is None:
            attachments = {}
        
        all_results = []
        for p in problems:
            pid = p.get("id", "")
            name = p.get("name", "Unknown")
            url = containers.get(pid, "")
            filepath = attachments.get(pid, "")
            
            print(f"\n{'='*60}")
            print(f"Solving: {name} (ID: {pid})")
            print(f"URL: {url or 'N/A'}, File: {filepath or 'N/A'}")
            
            result = self.solve(metadata=p, url=url, filepath=filepath)
            status = "✅ SOLVED" if result.get("success") else "❌ UNSOLVED"
            flag = result.get("flag", "")
            
            print(f"Result: {status}")
            if flag:
                print(f"Flag: {flag}")
            else:
                print(f"Results: {len(result.get('results', []))} steps attempted")
            
            all_results.append({"problem": name, "id": pid, **result})
        
        return all_results
    
    def print_summary(self, results: List[dict]):
        """打印批量求解摘要."""
        solved = [r for r in results if r.get("success")]
        unsolved = [r for r in results if not r.get("success")]
        
        print(f"\n{'='*60}")
        print(f"BATCH SOLVE SUMMARY")
        print(f"{'='*60}")
        print(f"Total: {len(results)} | Solved: {len(solved)} | Unsolved: {len(unsolved)}")
        
        if solved:
            print(f"\n✅ Solved ({len(solved)}):")
            for r in solved:
                print(f"   {r['problem']}: {r.get('flag', 'N/A')}")
        
        if unsolved:
            print(f"\n❌ Unsolved ({len(unsolved)}):")
            for r in unsolved:
                err = r.get("error", "No specific error")
                cat = r.get("category", "?")
                print(f"   [{cat}] {r['problem']}: {err}")
