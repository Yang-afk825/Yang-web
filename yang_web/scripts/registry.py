"""CTF 脚本注册表 — 元数据、分类、依赖信息."""

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


# ── 脚本注册表 ──

SCRIPTS: Dict[str, ScriptMeta] = {
    # ═══ Crypto / 编码 ═══
    "Base家族加解密": {
        "name": "Base家族加解密.py",
        "title": "Base家族加解密",
        "category": "crypto",
        "description": "一站式 base16/32/36/58/62/64/85/91/92 编解码，支持批量操作",
        "usage": 'python scripts/Base家族加解密.py',
        "deps": ["base36", "base58", "base62", "base91", "py3base92"],
        "input_type": "text",
        "output_type": "text",
    },
    "base64批量加解密": {
        "name": "base64批量加解密.py",
        "title": "Base64 批量加解密",
        "category": "crypto",
        "description": "批量 base64 编解码，彩色 ASCII 艺术输出",
        "usage": 'echo "sometext" | python scripts/base64批量加解密.py',
        "deps": [],
        "input_type": "text",
        "output_type": "text",
    },
    "base64异或": {
        "name": "base64异或.py",
        "title": "Base64 + XOR 爆破",
        "category": "crypto",
        "description": "base64 解码后逐字节异或爆破 (0-199) 找出明文",
        "usage": 'python scripts/base64异或.py',
        "deps": [],
        "input_type": "text",
        "output_type": "decode",
    },
    "base64隐写": {
        "name": "base64隐写.py",
        "title": "Base64 隐写提取",
        "category": "crypto",
        "description": "从 base64 编码的 '=' 填充位中提取隐写数据",
        "usage": 'python scripts/base64隐写.py',
        "deps": [],
        "input_type": "text",
        "output_type": "text",
    },
    "base64爬虫": {
        "name": "base64爬虫.py",
        "title": "Base64 爬虫爆破",
        "category": "web",
        "description": "base64 编码参数遍历请求 URL（适合 CTF 爬虫题）",
        "usage": 'python scripts/base64爬虫.py',
        "deps": ["requests"],
        "input_type": "url",
        "output_type": "text",
    },
    "base自动连续解密脚本": {
        "name": "base自动连续解密脚本.py",
        "title": "Base 自动连续解密",
        "category": "crypto",
        "description": "自动检测 base16/32/64 格式并连续解码至明文",
        "usage": 'python scripts/base自动连续解密脚本.py',
        "deps": [],
        "input_type": "text",
        "output_type": "decode",
    },
    "2进制文本转换ascii": {
        "name": "2进制文本转换ascii.py",
        "title": "二进制转 ASCII",
        "category": "crypto",
        "description": "二进制字符串转 ASCII，支持 7/8bit、位翻转、字节倒序",
        "usage": 'python scripts/2进制文本转换ascii.py',
        "deps": [],
        "input_type": "text",
        "output_type": "decode",
    },
    "4字节16进制转浮点": {
        "name": "4字节16进制转浮点.py",
        "title": "Hex 转浮点数",
        "category": "crypto",
        "description": "4 字节 hex ↔ float 互转（大端/小端）",
        "usage": 'python scripts/4字节16进制转浮点.py',
        "deps": [],
        "input_type": "text",
        "output_type": "decode",
    },
    "TLL隐写": {
        "name": "TLL隐写.py",
        "title": "TLL 像素隐写",
        "category": "misc",
        "description": "像素值(63→00,127→01,191→10,255→11)映射提取隐写数据",
        "usage": 'python scripts/TLL隐写.py',
        "deps": [],
        "input_type": "file",
        "output_type": "text",
    },
    "字符串统计": {
        "name": "字符串统计.py",
        "title": "字符串统计对比",
        "category": "crypto",
        "description": "两字符串逐字节统计/对比差异",
        "usage": 'python scripts/字符串统计.py',
        "deps": [],
        "input_type": "text",
        "output_type": "text",
    },
    "字频统计": {
        "name": "字频统计.py",
        "title": "字母频率统计",
        "category": "crypto",
        "description": "字母频率统计排序，按频次降序拼接输出",
        "usage": 'python scripts/字频统计.py',
        "deps": [],
        "input_type": "text",
        "output_type": "text",
    },

    # ═══ Hash / 爆破 ═══
    "md5": {
        "name": "md5.py",
        "title": "MD5 爆破",
        "category": "crypto",
        "description": "5 层嵌套循环爆破 MD5（模板字符串匹配部分 hash）",
        "usage": 'python scripts/md5.py',
        "deps": [],
        "input_type": "text",
        "output_type": "decode",
    },
    "md5爆破": {
        "name": "md5爆破.py",
        "title": "MD5 爆破 (v2)",
        "category": "crypto",
        "description": "与 md5.py 逻辑一致，针对不同格式模板",
        "usage": 'python scripts/md5爆破.py',
        "deps": [],
        "input_type": "text",
        "output_type": "decode",
    },
    "crc32": {
        "name": "crc32.py",
        "title": "CRC32 碰撞",
        "category": "crypto",
        "description": "给定 CRC32 集合爆破 4 字节可打印字符明文",
        "usage": 'python scripts/crc32.py',
        "deps": [],
        "input_type": "text",
        "output_type": "decode",
    },
    "crc爆破": {
        "name": "crc爆破.py",
        "title": "PNG CRC 修复",
        "category": "misc",
        "description": "PNG 宽高 CRC 爆破：给定 CRC32 恢复正确图片宽高",
        "usage": 'python scripts/crc爆破.py',
        "deps": [],
        "input_type": "file",
        "output_type": "text",
    },
    "sm2": {
        "name": "sm2.py",
        "title": "国密 SM2",
        "category": "crypto",
        "description": "国密 SM2 加密/解密模板（需 gmssl）",
        "usage": 'python scripts/sm2.py',
        "deps": ["gmssl"],
        "input_type": "text",
        "output_type": "text",
    },

    # ═══ Web ═══
    "正常盲注": {
        "name": "正常盲注.py",
        "title": "SQL 盲注模板",
        "category": "web",
        "description": "SQL 盲注 Payload 模板，二分法逐字符注入（库名/表名/列名/数据）",
        "usage": 'python scripts/正常盲注.py',
        "deps": ["requests"],
        "input_type": "url",
        "output_type": "text",
    },
    "IIS文件上传": {
        "name": "IIS文件上传.py",
        "title": "IIS PUT 上传利用",
        "category": "web",
        "description": "IIS PUT 文件上传漏洞利用（httplib 实现）",
        "usage": 'python scripts/IIS文件上传.py',
        "deps": [],
        "input_type": "url",
        "output_type": "text",
    },
    "ssh弱口令加提取flag": {
        "name": "ssh弱口令加提取flag.py",
        "title": "SSH 弱口令 + 提取 Flag",
        "category": "web",
        "description": "SSH 弱口令扫描 + 远程执行 cat flag（paramiko）",
        "usage": 'python scripts/ssh弱口令加提取flag.py',
        "deps": ["paramiko"],
        "input_type": "url",
        "output_type": "flag",
    },
    "自动提交flag": {
        "name": "自动提交flag.py",
        "title": "自动提交 Flag",
        "category": "web",
        "description": "CTF 比赛自动获取 flag 并提交到计分平台（requests session）",
        "usage": 'python scripts/自动提交flag.py',
        "deps": ["requests"],
        "input_type": "url",
        "output_type": "text",
    },

    # ═══ Reverse ═══
    "APK逆向Solver": {
        "name": "APK 逆向 Solver.py",
        "title": "APK 逆向 Solver",
        "category": "reverse",
        "description": "通用 SCM time-capsule APK 求解器：4段6字节可打印key → SHA256 → RC4 解密 flag.enc",
        "usage": 'python "scripts/APK 逆向 Solver.py" attachment.apk',
        "deps": [],
        "input_type": "apk",
        "output_type": "flag",
    },

    # ═══ Misc / 流量 ═══
    "ICMP": {
        "name": "ICMP.py",
        "title": "ICMP Ping 扫描",
        "category": "misc",
        "description": "ICMP Ping 扫描（scapy, 多线程, 支持 IP 段和文件输入）",
        "usage": 'python scripts/ICMP.py',
        "deps": ["scapy"],
        "input_type": "url",
        "output_type": "text",
    },
    "ICMP数据包data长度提取": {
        "name": "ICMP数据包data长度提取.py",
        "title": "ICMP Data 提取",
        "category": "misc",
        "description": "从 PDML 提取 ICMP data.len → base64 解码隐写信息",
        "usage": 'python scripts/ICMP数据包data长度提取.py',
        "deps": [],
        "input_type": "file",
        "output_type": "decode",
    },
    "一元二次方程": {
        "name": "一元二次方程.py",
        "title": "一元二次方程求解",
        "category": "misc",
        "description": "解一元二次方程（CTF 自动化流程辅助）",
        "usage": 'python scripts/一元二次方程.py',
        "deps": [],
        "input_type": "text",
        "output_type": "text",
    },
    "键鼠控制": {
        "name": "键鼠控制.py",
        "title": "pyautogui 参考大全",
        "category": "misc",
        "description": "pyautogui 操作参考：鼠标/键盘/截图/图像定位等完整 API",
        "usage": 'python scripts/键鼠控制.py',
        "deps": ["pyautogui"],
        "input_type": "text",
        "output_type": "text",
    },
    "竞赛脚本": {
        "name": "竞赛脚本.zip",
        "title": "竞赛脚本合集",
        "category": "misc",
        "description": "额外的未分类 CTF 竞赛脚本打包（需解压使用）",
        "usage": "解压 scripts/竞赛脚本.zip 后查看",
        "deps": [],
        "input_type": "file",
        "output_type": "text",
    },
}


# ── 分类映射 ──
CATEGORIES: Dict[str, str] = {
    "crypto": "🔐 密码 / 编码",
    "web": "🌐 Web",
    "reverse": "🔧 逆向",
    "misc": "📦 杂项 / Misc",
    "forensics": "🔍 取证 / 隐写",
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
