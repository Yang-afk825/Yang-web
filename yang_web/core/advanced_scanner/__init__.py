# -*- coding: utf-8 -*-
"""
Yang-Web v3.5 Advanced Scanner Engine
基于随波逐流Web扫描工具的设计理念优化

新增能力:
1. Dictionary-based 目录/文件爆破 (多层字典)
2. Response Diffing Engine — 盲注精准检测
3. Attack Chain Engine — 自动二阶段利用 (LFI→Log Poisoning→RCE)
4. HTTP Method Auto-Switch — POST/GET 自适应
5. Quick Port Scanner — 快速端口发现
6. Batch Target Runner — 多目标批量处理
7. Smart Rate Limiter — 自适应限速+退避
"""

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

# 重导出全部原子符号，保持 `from yang_web.core.advanced_scanner import X` 契约不变
from ._common import (http_request, find_flag, FLAG_RE, _SSL_CTX, DEFAULT_UA)
from ._dict import (DictScanner)
from ._differ import (ResponseDiffer)
from ._chain import (AttackChainEngine)
from ._method import (MethodAutoSwitch)
from ._port import (QuickPortScanner)
from ._batch import (BatchRunner)
from ._rate import (SmartRateLimiter)
from ._solver import (AdvancedSolver)
