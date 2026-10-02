"""yang_web.core.smart_solver 子模块 _blockchain（自 smart_solver.py 拆分，请勿手工重排）。"""

from __future__ import annotations
import re
import json
import ssl
import socket
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, List, Optional, Tuple, Callable, Any

from ._common import (find_flag)



# ═══════════════════════════════════════════════════════════
#  Blockchain 分析引擎
# ═══════════════════════════════════════════════════════════

class BlockchainAnalyzer:
    """区块链/智能合约题目分析器."""
    
    SOLIDITY_PATTERNS = [
        (r'msg\.sender', "msg.sender usage - possible auth bypass"),
        (r'require\s*\(', "require() check"),
        (r'assert\s*\(', "assert() check"),
        (r'call\s*\{.*value', "Low-level call with value"),
        (r'delegatecall', "DELEGATECALL - potential proxy attack"),
        (r'selfdestruct', "selfdestruct - destruction capability"),
        (r'tx\.origin', "tx.origin - phishing vulnerability"),
        (r'block\.timestamp', "block.timestamp dependency"),
        (r'block\.number', "block.number dependency"),
        (r'\.transfer\(', ".transfer() usage"),
        (r'\.send\(', ".send() usage"),
        (r'payable', "payable function"),
        (r'onlyOwner', "onlyOwner modifier - access control"),
        (r'constructor\s*\(', "Constructor"),
        (r'fallback\s*\(', "Fallback function"),
        (r'receive\s*\(', "Receive function"),
        (r'ERC20', "ERC20 token"),
        (r'ERC721', "ERC721 NFT"),
        (r'mapping\s*\(', "Storage mapping"),
    ]
    
    def __init__(self, source: str = "", bytecode: str = ""):
        self.source = source
        self.bytecode = bytecode
        self.results: List[dict] = []
        self.findings: List[str] = []
    
    def log(self, step: str, status: str, detail: str = ""):
        self.results.append({"step": step, "status": status, "detail": detail})
    
    def analyze(self) -> dict:
        """分析合约源码或字节码."""
        if self.source:
            self._analyze_solidity()
        
        if self.bytecode:
            self._analyze_bytecode()
        
        if not self.source and not self.bytecode:
            # Provide hints for common blockchain CTF scenarios
            self._general_hints()
        
        return self._result()
    
    def _analyze_solidity(self):
        """分析 Solidity 源码."""
        self.log("Solidity", "running", f"{len(self.source)} chars")
        
        for pattern, description in self.SOLIDITY_PATTERNS:
            matches = re.findall(pattern, self.source, re.IGNORECASE)
            if matches:
                self.findings.append(description)
                self.log("Pattern", "found", description)
        
        # Flag search
        f = find_flag(self.source)
        if f:
            self.log("Flag in source", "flag!", f)
    
    def _analyze_bytecode(self):
        """分析 EVM 字节码（简易版）."""
        self.log("Bytecode", "info", f"{len(self.bytecode)} chars")
        
        # Common opcode patterns
        if '54' in self.bytecode:  # SLOAD
            self.findings.append("Storage read (SLOAD) detected")
            self.log("Opcode", "info", "SLOAD - reads from storage")
        if 'f3' in self.bytecode:  # RETURN
            self.log("Opcode", "info", "RETURN - contract returns data")
    
    def _general_hints(self):
        """区块链 CTF 通用提示."""
        hints = [
            "Check for reentrancy (CALL before state update)",
            "Check for integer overflow/underflow",
            "Check for flash loan manipulation",
            "Check access control (tx.origin vs msg.sender)",
            "Check price oracle manipulation",
            "Use Foundry/Hardhat for local testing",
            "Use cast call for read-only interactions",
        ]
        for hint in hints:
            self.log("Hint", "info", hint)
    
    def _result(self) -> dict:
        return {
            "success": len(self.findings) > 0,
            "results": self.results,
            "findings": self.findings,
            "category": "blockchain",
        }
