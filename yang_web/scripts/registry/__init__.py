# -*- coding: utf-8 -*-
"""CTF 脚本注册表 — 元数据、分类、依赖信息."""

from __future__ import annotations
from typing import Dict, List, TypedDict, Optional
import os

# 重导出全部原子符号，保持 `from yang_web.scripts.registry import X` 契约不变
from ._meta import (SCRIPT_DIR, ScriptMeta)
from ._data import (SCRIPTS)
from ._api import (CATEGORIES, list_scripts, search_scripts, get_script, get_script_path)
