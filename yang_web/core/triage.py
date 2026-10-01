# -*- coding: utf-8 -*-
"""题型识别（triage）—— 先判类型，再给路径。

自动解题的正确顺序是"先识别、后行动"。此前 ``solve`` 把输入直接丢给脚本库
盲目试跑，命中与否全凭运气；本模块补上缺失的识别环节：从输入的字面特征判断
它像哪一类 CTF 题目，并给出**可以直接复制执行的下一步**。

本模块只做判断与路由，**不执行攻击**。

覆盖的识别类型：

- ``rsa``        多个大整数 —— RSA 公钥参数
- ``hash``       32/40/64 位十六进制 —— MD5 / SHA1 / SHA256
- ``encoded``    可识别的编码（复用 ``decoder.detect_encoding``）
- ``ciphertext`` 高熵但无编码特征 —— 需要密钥的分组/流密码
- ``plaintext``  已是明文或 flag
- ``url``        目标地址 —— 走 Web 攻击链
- ``archive``    压缩包 / 图片 / 抓包 / 可执行文件等（按魔数）
"""

from __future__ import annotations

import os
import re

from .decoder import detect_encoding

__all__ = ["triage", "identify_bytes", "parse_rsa_params", "MAGIC_TABLE"]

#: 文件魔数 → (类型, 说明, 建议动作)
MAGIC_TABLE = [
    (b"PK\x03\x04", "zip", "ZIP 压缩包（也可能是 APK / docx / jar）", "scripts zip_tools"),
    (b"\x89PNG\r\n\x1a\n", "png", "PNG 图片", "scripts img_stego"),
    (b"\xff\xd8\xff", "jpeg", "JPEG 图片", "scripts img_stego"),
    (b"GIF8", "gif", "GIF 图片", "scripts img_stego"),
    (b"\xd4\xc3\xb2\xa1", "pcap", "PCAP 抓包（小端）", "scripts pcap_tools"),
    (b"\xa1\xb2\xc3\xd4", "pcap", "PCAP 抓包（大端）", "scripts pcap_tools"),
    (b"\x0a\x0d\x0d\x0a", "pcapng", "PCAPNG 抓包", "scripts pcap_tools"),
    (b"\x7fELF", "elf", "Linux 可执行文件", "reverse"),
    (b"MZ", "pe", "Windows 可执行文件", "reverse"),
    (b"%PDF", "pdf", "PDF 文档", "scripts file_analyzer"),
    (b"Rar!\x1a\x07", "rar", "RAR 压缩包", "scripts zip_tools"),
    (b"7z\xbc\xaf\x27\x1c", "7z", "7-Zip 压缩包", "scripts zip_tools"),
    (b"\x1f\x8b", "gzip", "GZIP 压缩流", "scripts zlib_tools"),
    (b"BZh", "bzip2", "BZIP2 压缩流", "scripts zlib_tools"),
    (b"OggS", "ogg", "Ogg 音频", "scripts img_stego"),
    (b"ID3", "mp3", "MP3 音频", "scripts img_stego"),
    (b"RIFF", "riff", "RIFF 容器（WAV / AVI）", "scripts img_stego"),
]

#: 十六进制串长度 → 对应散列算法
_HASH_LENGTHS = {32: "MD5", 40: "SHA1", 56: "SHA224", 64: "SHA256", 96: "SHA384", 128: "SHA512"}

_URL_RE = re.compile(r"^https?://[^\s]+$", re.IGNORECASE)
_FLAG_RE = re.compile(r"[A-Za-z0-9_]{2,16}\{[^}\n]{4,}\}")
_BIGINT_RE = re.compile(r"\b\d{20,}\b")
_HEX_RE = re.compile(r"^[0-9a-fA-F\s]+$")
_RADIX36_RE = re.compile(r"^[0-9A-Za-z+/=\s]{12,}$")

#: RSA 参数标签 → 正则。要求 "标签 + 冒号/等号 + 数字"，避免把散文里的
#: 单个字母误当参数。更长的键（e1/e2/c1/c2）单独列出，不会与 e/c 冲突。
_RSA_LABEL_RES = {
    "n": r"\bn\s*[:=]\s*(\d+)",
    "e": r"\be\s*[:=]\s*(\d+)",
    "c": r"\bc\s*[:=]\s*(\d+)",
    "p": r"\bp\s*[:=]\s*(\d+)",
    "q": r"\bq\s*[:=]\s*(\d+)",
    "d": r"\bd\s*[:=]\s*(\d+)",
    "e1": r"\be1\s*[:=]\s*(\d+)",
    "e2": r"\be2\s*[:=]\s*(\d+)",
    "c1": r"\bc1\s*[:=]\s*(\d+)",
    "c2": r"\bc2\s*[:=]\s*(\d+)",
}

#: n / p 低于该阈值时不认为是 RSA 模数（防止散文中 "n = 1" 之类误判）
_MIN_RSA = 10 ** 10

#: 判定为"编码题"所需的最低检测置信度。
#: 编码检测器对任意字母文本都会给出 `rot13 ≈ 50`、`rot47 ≈ 15` 这类兜底分数
#: （本质只是"都是字母"），并不构成编码证据。真实编码串实测最低 75 分，
#: 因此以 60 为界即可滤掉这层噪声，避免把普通英文判成编码题。
_MIN_ENCODING_CONFIDENCE = 60


def parse_rsa_params(text: str) -> dict:
    """从文本中解析 RSA 参数，返回 ``{键: 整数}``（缺省键不出现）。

    两条路径：

    1. **带标签**：``n = 123`` / ``e: 65537`` / ``c=456`` 这类题面最常见的形式，
       直接按标签取值 —— 这样即使 ``e`` 只有个位数也能正确归位；
    2. **无标签兜底**：全部是裸数字串时，用 20 位以上的大整数按 ``n、e、c``
       顺序代入（大整数里不可能出现小的 ``e``，所以这种兜底对 e=3 会退化，
       但至少能拿到 ``n``、``c``，交给调用方枚举常见指数）。

    标签解析不成立的返回值会被判为"不像 RSA"，由调用方决定是否继续兜底。
    """
    if not text:
        return {}

    labeled = {}
    for key, pattern in _RSA_LABEL_RES.items():
        hit = re.search(pattern, text, re.IGNORECASE)
        if hit:
            labeled[key] = int(hit.group(1))

    if _looks_like_rsa(labeled):
        # 共模题面常写成 c1/c2，统一补一个 c，方便统一入口直接吃下
        if "c" not in labeled and labeled.get("c1"):
            labeled["c"] = labeled["c1"]
        return labeled

    # 无标签兜底
    bigints = [int(x) for x in _BIGINT_RE.findall(text)]
    fallback = {}
    if len(bigints) >= 3:
        fallback = {"n": bigints[0], "e": bigints[1], "c": bigints[2]}
    elif len(bigints) == 2:
        fallback = {"n": bigints[0], "c": bigints[1]}
    return fallback if _looks_like_rsa(fallback) else {}


def _looks_like_rsa(params: dict) -> bool:
    """参数是否构成一个像样的 RSA 题面。"""
    n = params.get("n", 0)
    p = params.get("p", 0)
    if params.get("e1") and params.get("e2"):
        return bool(n >= _MIN_RSA or (params.get("c1") and params.get("c2")))
    if n >= _MIN_RSA and (params.get("e") or params.get("c")):
        return True
    if p >= _MIN_RSA and params.get("q"):
        return True
    return False


def _rsa_cmd(params: dict) -> str:
    """把参数字典拼成可直接执行的 crypto 子命令。"""
    flags = [
        f"--{key} {params[key]}"
        for key in ("n", "e", "c", "p", "q", "e1", "e2", "c1", "c2")
        if params.get(key)
    ]
    return "yang-web crypto " + " ".join(flags) if flags else "yang-web crypto --list"


def identify_bytes(data: bytes) -> dict | None:
    """按文件魔数识别二进制内容。识别不了返回 None。"""
    if not data:
        return None
    for magic, kind, desc, action in MAGIC_TABLE:
        if data.startswith(magic):
            return {"kind": kind, "evidence": desc, "action": action}
    # TAR 的魔数在偏移 257 处
    if len(data) > 262 and data[257:262] == b"ustar":
        return {"kind": "tar", "evidence": "TAR 归档", "action": "scripts zip_tools"}
    return None


def _entropy_ratio(text: str) -> float:
    """粗略的"乱码度"：不在常见明文符号集内的字符占比。"""
    if not text:
        return 0.0
    common = set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        "{}_-.,:;!?/+=@#$%^&*()[]<>|~ \n\r\t'\""
    )
    return sum(1 for ch in text if ch not in common) / len(text)


def _path(tool: str, hint: str, cmd: str) -> dict:
    return {"tool": tool, "hint": hint, "cmd": cmd}


def triage(text: str = "", file_path: str = None) -> dict:
    """识别题型并给出推荐路径。

    参数二选一：``text`` 直接给内容，或 ``file_path`` 给文件路径（会读前 4KB 判魔数）。

    返回::

        {
          "kind": "rsa",               # 主判断
          "confidence": 90,            # 0-100
          "evidence": "检测到 3 个 20 位以上整数",
          "paths": [                   # 按推荐度排序，cmd 可直接复制执行
              {"tool": "crypto", "hint": "尝试 Fermat / Wiener / 低指数", "cmd": "..."},
          ],
          "alternatives": [...]        # 其他可能，结构同上
        }
    """
    alternatives = []

    # ── 文件输入：先看魔数 ──
    if file_path:
        if not os.path.isfile(file_path):
            return {"kind": "error", "confidence": 0,
                    "evidence": f"文件不存在: {file_path}", "paths": [], "alternatives": []}
        with open(file_path, "rb") as fh:
            head = fh.read(4096)
        hit = identify_bytes(head)
        size = os.path.getsize(file_path)
        if hit:
            return {
                "kind": hit["kind"],
                "confidence": 95,
                "evidence": f"{hit['evidence']}，{size} 字节",
                "paths": [
                    _path(hit["action"], "按文件类型处理",
                          f"yang-web scripts --run {hit['action'].split()[-1]} --file \"{file_path}\""),
                    _path("scripts", "浏览脚本库中同类型工具", "yang-web scripts --list"),
                ],
                "alternatives": alternatives,
            }
        # 不是已知魔数：尝试当文本处理
        try:
            text = head.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            text = ""

    text = (text or "").strip()
    if not text:
        return {"kind": "unknown", "confidence": 0, "evidence": "输入为空",
                "paths": [], "alternatives": []}

    preview = text if len(text) <= 60 else text[:60] + "..."

    # ── 已是明文 / flag ──
    if _FLAG_RE.search(text):
        found = _FLAG_RE.search(text).group(0)
        return {
            "kind": "plaintext",
            "confidence": 98,
            "evidence": f"输入已是明文，含 flag 形态字符串: {found}",
            "paths": [_path("none", "直接取用，无需解题", "")],
            "alternatives": alternatives,
        }

    # ── URL ──
    if _URL_RE.match(text):
        return {
            "kind": "url",
            "confidence": 95,
            "evidence": "HTTP(S) 目标地址",
            "paths": [
                _path("solve", "走 Web 攻击链（指纹→并发攻击→读 flag）",
                      f"yang-web solve \"{text}\""),
                _path("scan", "目录扫描", f"yang-web scan dir --url \"{text}\""),
            ],
            "alternatives": alternatives,
        }

    # ── RSA 参数（支持 "n = ..." 标签，也支持裸大整数串）──
    params = parse_rsa_params(text)
    if params:
        present = "、".join(
            k for k in ("n", "e", "c", "p", "q", "e1", "e2", "c1", "c2") if params.get(k)
        )
        alternatives.append({
            "kind": "decimal",
            "confidence": 40,
            "evidence": "也可能只是十进制 ASCII 编码串",
            "paths": [_path("decode", "按十进制 ASCII 解码", f'yang-web decode "{preview}"')],
        })
        if not params.get("e") and params.get("n") and params.get("c"):
            evidence = f"解析到 RSA 参数（{present}）—— e 缺失，将由引擎枚举常见指数"
        else:
            evidence = f"解析到 RSA 参数（{present}）"
        return {
            "kind": "rsa",
            "confidence": 90,
            "evidence": evidence,
            "paths": [
                _path("crypto", "自动尝试 Fermat / Wiener / 低指数 / 共模", _rsa_cmd(params)),
                _path("scripts", "RSA 攻击工具箱（兼容入口）", "yang-web scripts --run rsa_toolkit"),
            ],
            "alternatives": alternatives,
        }

    # ── 散列 ──
    compact = re.sub(r"\s+", "", text)
    if _HEX_RE.match(compact) and len(compact) in _HASH_LENGTHS:
        algo = _HASH_LENGTHS[len(compact)]
        alternatives.append({
            "kind": "hex",
            "confidence": 70,
            "evidence": f"同为 {len(compact)} 位十六进制，也可能是 hex 编码的 {len(compact)//2} 字节数据",
            "paths": [_path("decode", "按 hex 解码", f'yang-web decode "{compact}"')],
        })
        return {
            "kind": "hash",
            "confidence": 80,
            "evidence": f"{len(compact)} 位十六进制 — 形态匹配 {algo}",
            "paths": [
                _path("hashid", "确认散列类型", f'yang-web hashid "{compact}"'),
                _path("scripts", "字典爆破（需自备字典）", "yang-web scripts --list"),
            ],
            "alternatives": alternatives,
        }

    # ── 编码（复用 decoder 的检测器）──
    detections = detect_encoding(text)
    if detections and detections[0][2] >= _MIN_ENCODING_CONFIDENCE:
        top = detections[0]
        for enc_id, desc, conf in detections[:5]:
            alternatives.append({
                "kind": enc_id, "confidence": conf,
                "evidence": f"编码检测命中 {desc}",
                "paths": [_path("decode", f"按 {desc} 解码", f'yang-web decode "{preview}"')],
            })
        return {
            "kind": "encoded",
            "confidence": min(95, top[2]),
            "evidence": f"编码检测首选 {top[1]}（置信度 {top[2]}）；输入预览: {preview}",
            "paths": [
                _path("decode", "智能链式解码（可多层）", f'yang-web decode "{preview}"'),
                _path("decode", "暴力尝试所有解码器", f'yang-web decode --brute "{preview}"'),
            ],
            "alternatives": alternatives,
        }

    # ── 无法识别：给通用路径而不是沉默 ──
    entropy = _entropy_ratio(text)
    if entropy > 0.05:
        return {
            "kind": "ciphertext",
            "confidence": 45,
            "evidence": f"未匹配已知编码，但含 {entropy:.0%} 非常见字符 —— 疑似需要密钥的密文",
            "paths": [
                _path("decode", "先试一轮全解码器", f'yang-web decode --brute "{preview}"'),
                _path("misc", "古典密码知识库（维吉尼亚 / 希尔 / 仿射…）", "yang-web misc --list"),
                _path("scripts", "浏览脚本库", "yang-web scripts --list"),
            ],
            "alternatives": alternatives,
        }

    return {
        "kind": "text",
        "confidence": 30,
        "evidence": f"未匹配任何已知特征；输入预览: {preview}",
        "paths": [
            _path("decode", "碰运气试一轮链式解码", f'yang-web decode "{preview}"'),
            _path("misc", "看古典密码知识库", "yang-web misc --list"),
        ],
        "alternatives": alternatives,
    }
