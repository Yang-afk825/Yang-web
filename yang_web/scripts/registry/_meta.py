"""yang_web.scripts.registry 子模块 _meta（自 registry.py 拆分，请勿手工重排）。"""

from __future__ import annotations
from typing import Dict, List, TypedDict, Optional
import os










SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))



class ScriptMeta(TypedDict):

    name: str           # 脚本文件名
    title: str          # 中文名
    category: str       # 分类: crypto / web / reverse / misc / forensics
    description: str    # 功能简述
    usage: str          # 使用示例
    deps: List[str]     # 依赖库 (非标准库)
    input_type: str     # 输入类型: text / file / apk / pcap / url
    output_type: str    # 输出类型: text / flag / decode
