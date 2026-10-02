# -*- coding: utf-8 -*-
"""
Yang-Web Multi-Stage Attack Engine
==================================
通用多阶段解题引擎 — 自动发现+利用攻击链，覆盖多种题型

架构:
  阶段检测 → 攻击 → 响应分析 → 跳转追踪 → 下一阶段 → ... → Flag

支持场景:
  1. 弱口令登录 → 后台利用 (SQLi/XXE/LFI/...)
  2. JS重定向追踪 → 自动跟随
  3. 多页面爬虫 → 表单识别 → 自动分类攻击
  4. Cookie/Session 保持 → 跨阶段上下文传递
  5. 响应模式识别 → 自动识别下一阶段漏洞类型
"""

from __future__ import annotations
import re
import ssl
import time
import json
import base64
import urllib.request
import urllib.error
import urllib.parse
from urllib.parse import urljoin
import http.cookiejar
from typing import Dict, List, Optional, Tuple, Set, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError

# 重导出全部原子符号，保持 `from yang_web.core.multi_stage import X` 契约不变
from ._common import (COMMON_CREDENTIALS, JS_REDIRECT_RE, XXE_PAYLOADS, LFI_PAYLOADS, PAGE_FINGERPRINTS, _SSL_CTX, DEFAULT_UA, FLAG_RE)
from ._http import (SessionHTTP)
from ._analyzer import (PageAnalyzer)
from ._engine import (MultiStageEngine)
