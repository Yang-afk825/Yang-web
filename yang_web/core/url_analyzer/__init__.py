# -*- coding: utf-8 -*-
"""
URL Vulnerability Analyzer -- CTF attack engine for Yang-Web.

Pipeline:
    1. Parse URL - Extract parameters and path features
    2. Match features - Score vulnerability types
    3. Generate payloads - Ready for attack testing
    4. Execute attacks - Analyze responses for confirmation

All docstrings and comments in plain ASCII English.
"""

# 原 header 导入原样保留: 保证 `from yang_web.core.url_analyzer import *`
# 与拆分前的可见面完全一致（历史上即已导出 re / ssl / Dict 等名字）。
from urllib.parse import urlparse, parse_qs, unquote, urlencode, urlunparse, quote
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from typing import List, Dict, Tuple, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
import re
import ssl
import socket
import time
import json as _json
import threading
import base64
import html as _html
from yang_web.core.php_logic import analyze_and_solve as _php_logic_solve

# 各分层子模块的顶层名统一重导出（含下划线私有名, 保证调用点无需改动）。
from ._http import (_SSL_CONTEXT, DEFAULT_HEADERS, DEFAULT_TIMEOUT, USER_AGENT, send_request, inject_payload, analyze_response, crawl_page, _extract_title, _extract_forms, _extract_links_with_params, _get_attr, FLAG_RE, FLAG_PATHS)
from ._signatures import (PARAM_SIGNATURES, PATH_PATTERNS, ATTACK_PAYLOADS)
from ._engines import (SmartFingerprinter, ConcurrentEngine, AdaptiveScheduler, execute_attack)
from ._attacks import (_PHP_FUNC_MAP, _gen_octal, _try_php_dynamic_func, _try_php_logic_bypass, _scan_static_flag, _execute_php_bypass, auto_exploit, _try_bashfuck_exploit, _try_length_limit_rce_exploit, _try_flag_paths, _try_sqli_extract, _try_lfi_flag, _try_php_unserialize_exploit, _try_php_lfi_exploit, _try_php_eval_rce_exploit)
from ._analyze import (analyze_url, _add_ev, get_attack_guide)
