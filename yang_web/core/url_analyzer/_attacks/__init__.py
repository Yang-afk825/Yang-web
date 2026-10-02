# -*- coding: utf-8 -*-
"""url_analyzer._attacks -- Concrete exploit attempts: PHP bypass, LFI/SQLi extraction, bashFuck, auto_exploit.

从 yang_web/core/url_analyzer.py 机械拆分而来, 逐行搬运, 行为等价。
"""

from urllib.parse import urlparse, parse_qs, unquote, urlencode, urlunparse, quote
from urllib.request import Request, urlopen
from typing import List, Dict, Tuple, Optional, Callable
import re
import time
import html as _html
from .._engines import (AdaptiveScheduler, ConcurrentEngine, execute_attack)
from .._http import (FLAG_RE, USER_AGENT, send_request)

# 重导出全部原子符号，保持 `from yang_web.core.url_analyzer._attacks import X` 契约不变
from ._php_funcs import (_PHP_FUNC_MAP, _gen_octal, _try_php_dynamic_func, _try_php_logic_bypass)
from ._php_rce import (_execute_php_bypass, _try_php_unserialize_exploit, _try_php_lfi_exploit, _try_php_eval_rce_exploit)
from ._extract import (_scan_static_flag, _try_flag_paths, _try_sqli_extract, _try_lfi_flag)
from ._generic_rce import (_try_bashfuck_exploit, _try_length_limit_rce_exploit)
from ._orchestrator import (auto_exploit)
