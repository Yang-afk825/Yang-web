# -*- coding: utf-8 -*-
"""
Yang-Web Smart Auto-Solver — 智能多类型 CTF 一键解题引擎

功能：
    1. 问题分类器 — 自动识别题目类型 (Web/PWN/Reverse/Crypto/Misc/Blockchain)
    2. 策略路由 — 根据分类选择合适的攻击引擎
    3. 多引擎编排 — Web攻击、密码破解、二进制分析、区块链分析
    4. 结果聚合 — 汇总所有引擎输出，提取 flag

基于 CTF+ 平台 20 道题的实际需求设计。
"""

from __future__ import annotations
import re
import json
import ssl
import socket
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, List, Optional, Tuple, Callable, Any

# 重导出全部原子符号，保持 `from yang_web.core.smart_solver import X` 契约不变
from ._common import (_detect_php_source, FLAG_PATTERNS, find_flag, PROBLEM_TYPE_MAP, TAG_TO_CATEGORY, classify_problem, classify_by_tags_only, _make_ssl_ctx, _http_headers, http_get, http_post, decode_body)
from ._web import (WebSmartSolver)
from ._crypto import (CryptoSmartSolver)
from ._binary import (BinaryAnalyzer)
from ._blockchain import (BlockchainAnalyzer)
from ._misc import (MiscAnalyzer)
from ._solver import (SmartSolver)
from ._entry import (main)
