"""yang_web.scripts.registry 子模块 _api（自 registry.py 拆分，请勿手工重排）。"""

from __future__ import annotations
from typing import Dict, List, TypedDict, Optional
import os

from ._data import (SCRIPTS)
from ._meta import (SCRIPT_DIR, ScriptMeta)

# ── 分类映射 ──
CATEGORIES: Dict[str, str] = {
    "web": "🌐 Web",
    "pwn": "💣 PWN / 二进制漏洞",
    "reverse": "🔧 逆向工程",
    "crypto": "🔐 密码 / 编码",
    "misc": "📦 杂项 / Misc",
    "forensics": "🔍 取证 / 隐写",
    "blockchain": "⛓️ 区块链 / 智能合约",
}
def list_scripts(category: Optional[str] = None) -> List[tuple]:
    """列出脚本（可按分类筛选），返回 (key, meta) 列表."""
    results = []
    for key, meta in SCRIPTS.items():
        if category and meta["category"] != category:
            continue
        results.append((key, meta))
    return sorted(results, key=lambda x: x[0])
def search_scripts(query: str) -> List[tuple]:
    """按关键词搜索脚本."""
    q = query.lower()
    results = []
    for key, meta in SCRIPTS.items():
        if (q in key.lower() or q in meta["title"].lower()
                or q in meta["description"].lower()
                or q in meta["category"].lower()):
            results.append((key, meta))
    return sorted(results, key=lambda x: x[0])
def get_script(key: str) -> Optional[ScriptMeta]:
    """获取单个脚本元数据."""
    return SCRIPTS.get(key)
def get_script_path(key: str) -> Optional[str]:
    """获取脚本的绝对路径."""
    meta = SCRIPTS.get(key)
    if not meta:
        return None
    path = os.path.join(SCRIPT_DIR, meta["name"])
    if os.path.isfile(path):
        return path
    return None
