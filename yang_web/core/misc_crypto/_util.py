"""yang_web.core.misc_crypto 子模块 _util（自 misc_crypto.py 拆分，请勿手工重排）。"""

import os
import re
import base64 as b64
import binascii
import html as html_mod
import codecs
import urllib.parse
from pathlib import Path



# ═══════════════════════════════════════════
# 编码/解码函数
# ═══════════════════════════════════════════

def _clean_text(text: str) -> str:
    return text.upper().replace(' ', '').replace('\n', '').replace('\r', '')


def _pad_ext(info: dict) -> dict:
    """为扩展密码补上 GUI 需要的默认字段。"""
    d = dict(info)
    d.setdefault("description", d["name"] + " 编码/解码")
    d.setdefault("features", [])
    d.setdefault("encode", True)
    return d
