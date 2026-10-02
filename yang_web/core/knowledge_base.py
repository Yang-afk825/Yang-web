# -*- coding: utf-8 -*-
"""Des-CTF-Knowledge 知识库检索引擎（接入 Yang-Web）。

把 Dest1ny-Sec/Des-CTF-Knowledge（中文实战 CTF 知识库）接入工具箱：
- list_articles(): 列出 12 篇深度文章清单
- search(query, kind): 按类型检索
    kind=payload  → 检索 PAYLOAD-CHEATSHEET.md 高频 Payload 速查
    kind=wp       → 检索 1150+ 篇历年大赛 WriteUp
    kind=script   → 检索 46 类 / 110+ 现成脚本
    kind=article  → 检索 12 篇深度文章（含 .idx.md 章节导航）
    kind=all      → 全部
纯 Python 标准库实现，零外部依赖。
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List

# 知识库根目录探测（优先级：环境变量 CTF_KB_DIR > 仓库内 submodule > 常见位置）
def _find_kb_root() -> Path:
    """探测 Des-CTF-Knowledge 根目录，返回 Path（可能不存在）。"""
    # 1. 环境变量 CTF_KB_DIR
    env = os.environ.get("CTF_KB_DIR")
    if env:
        p = Path(env)
        if (p / "PAYLOAD-CHEATSHEET.md").exists():
            return p
    # 2. 仓库内 submodule / 同级目录（Yang-web/knowledge/Des-CTF-Knowledge）
    here = Path(__file__).resolve()
    repo_root = here.parent.parent.parent  # yang_web/core → yang_web → repo_root
    for cand in (
        repo_root / "knowledge" / "Des-CTF-Knowledge",
        repo_root / "Des-CTF-Knowledge",
    ):
        if (cand / "PAYLOAD-CHEATSHEET.md").exists():
            return cand
    # 3. 常见位置（向后兼容旧路径 / 手动 clone）
    for cand in (
        Path.home() / "Des-CTF-Knowledge",
        repo_root.parent / "Des-CTF-Knowledge",
    ):
        if (cand / "PAYLOAD-CHEATSHEET.md").exists():
            return cand
    # 4. 默认返回仓库内 submodule 位置（可能不存在，available() 会判 false）
    return repo_root / "knowledge" / "Des-CTF-Knowledge"


_KB_ROOT: Path = _find_kb_root()

# 12 篇深度文章（文件名 → 一句话描述）
ARTICLES: List[tuple] = [
    ("SQL.md", "SQL 注入（联合/报错/堆叠/盲注/WAF绕过/宽字节/二次注入）"),
    ("命令执行.md", "命令执行 RCE（拼接符/空格绕过/无回显/反弹shell/无字母/disable_functions）"),
    ("文件上传漏洞.md", "文件上传（一句话/图片马/.htaccess/.user.ini/解析漏洞/条件竞争）"),
    ("文件包含.md", "文件包含 LFI（php伪协议/死亡exit绕过/日志session包含/pearcmd）"),
    ("SSRF漏洞.md", "SSRF（gopher打Redis/FastCGI/DNS-rebinding/dict协议/绕过）"),
    ("PHP反序列化漏洞总结.md", "PHP 反序列化（POP链/phar/session/SoapClient/字符逃逸/原生类）"),
    ("php代码审计.md", "PHP 代码审计（弱类型/变量覆盖/preg_match绕过/md5碰撞/intval）"),
    ("SSTI.md", "SSTI 模板注入（Jinja2/Flask/__subclasses__/catch_warnings）"),
    ("JWT.md", "JWT（None算法/RSA→HMAC/KID注入/JKU）"),
    ("图片隐写.md", "图片隐写（LSB/IHDR宽高/盲水印/文件头）"),
    ("音频隐写.md", "音频隐写（MP3Stego/频谱/DTMF/SilentEye）"),
    ("压缩包总结.md", "压缩包（CRC爆破/明文攻击/伪加密）"),
]


def kb_root() -> Path:
    return Path(_KB_ROOT)


def available() -> bool:
    return kb_root().exists() and (kb_root() / "PAYLOAD-CHEATSHEET.md").exists()


# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------
def _read_text(path: Path, limit: int = 0) -> str | None:
    """读文本文件，自动处理 utf-8/gbk 编码，可选截断。"""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    text = None
    for enc in ("utf-8", "gbk"):
        try:
            text = data.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        text = data.decode("utf-8", errors="replace")
    if limit and len(text) > limit:
        text = text[:limit]
    return text


def _snippet(text: str, query: str, ctx: int = 6, max_hits: int = 3) -> str:
    """提取含 query 的行及其上下文，用于结果摘要。"""
    lines = text.splitlines()
    ql = query.lower()
    hits = [i for i, ln in enumerate(lines) if ql in ln.lower()]
    if not hits:
        return "\n".join(lines[:30])
    out: List[str] = []
    for h in hits[:max_hits]:
        lo = max(0, h - ctx)
        hi = min(len(lines), h + ctx + 1)
        block = "\n".join(lines[lo:hi])
        if block not in out:
            out.append(block)
    return "\n\n……\n\n".join(out)


# ---------------------------------------------------------------------------
# 各类型检索
# ---------------------------------------------------------------------------
def search_payload(query: str, limit: int = 10) -> List[Dict[str, Any]]:
    root = kb_root()
    p = root / "PAYLOAD-CHEATSHEET.md"
    if not p.exists():
        return []
    text = _read_text(p)
    if not text:
        return []
    ql = query.lower()
    # 按 "## " 二级标题分节（标题 + 正文）
    parts = re.split(r"(?m)^(## .+)$", text)
    results: List[Dict[str, Any]] = []
    # parts[0] 是文件头，其后是 标题/正文 交替
    for i in range(1, len(parts), 2):
        title = parts[i]
        body = parts[i + 1] if i + 1 < len(parts) else ""
        if ql in title.lower() or ql in body.lower():
            results.append({
                "type": "payload",
                "title": title.lstrip("# ").strip(),
                "path": "PAYLOAD-CHEATSHEET.md",
                "content": _snippet(body, query),
            })
            if len(results) >= limit:
                break
    return results


def search_wp(query: str, limit: int = 15) -> List[Dict[str, Any]]:
    root = kb_root()
    art_dir = root / "CTF大赛WP集合" / "articles"
    if not art_dir.exists():
        return []
    ql = query.lower()
    results: List[Dict[str, Any]] = []
    files = list(art_dir.glob("*.md"))
    # 1) 文件名命中（快，零成本）
    name_hits = [f for f in files if ql in f.stem.lower()]
    for f in name_hits[:limit]:
        results.append({
            "type": "wp",
            "title": f.name,
            "path": str(f.relative_to(root)),
            "content": "（文件名命中，打开对应文件查看完整 WP）",
        })
    # 2) 内容命中（限制扫描数量，防卡顿）
    if len(results) < limit:
        name_set = set(name_hits)
        scan = [f for f in files if f not in name_set][:200]
        for f in scan:
            text = _read_text(f, 8192)
            if text and ql in text.lower():
                results.append({
                    "type": "wp",
                    "title": f.name,
                    "path": str(f.relative_to(root)),
                    "content": _snippet(text, query, 3, 2),
                })
                if len(results) >= limit:
                    break
    return results


def search_script(query: str, limit: int = 15) -> List[Dict[str, Any]]:
    root = kb_root()
    ql = query.lower()
    results: List[Dict[str, Any]] = []
    tools_dir = root / "CTF常用脚本及工具"
    if not tools_dir.exists():
        return []
    # 1) 脚本索引命中
    idx = tools_dir / "SCRIPTS-INDEX.md"
    if idx.exists():
        text = _read_text(idx)
        if text and ql in text.lower():
            results.append({
                "type": "script",
                "title": "脚本索引命中",
                "path": "CTF常用脚本及工具/SCRIPTS-INDEX.md",
                "content": _snippet(text, query, 4, 2),
            })
    # 2) 脚本目录名命中
    for d in sorted(tools_dir.iterdir()):
        if not d.is_dir():
            continue
        if ql in d.name.lower():
            results.append({
                "type": "script",
                "title": d.name,
                "path": str(d.relative_to(root)),
                "content": "现成脚本目录，按需修改硬编码参数后运行",
            })
            if len(results) >= limit:
                break
    return results


def search_article(query: str, limit: int = 10) -> List[Dict[str, Any]]:
    root = kb_root()
    ql = query.lower()
    results: List[Dict[str, Any]] = []
    # 1) 文件名/描述命中
    for name, desc in ARTICLES:
        if ql in name.lower() or ql in desc.lower():
            results.append({
                "type": "article",
                "title": name,
                "path": name,
                "content": desc,
            })
    # 2) 章节导航命中（读 .idx.md）
    for name, _desc in ARTICLES:
        idx_path = root / (name.replace(".md", ".idx.md"))
        if not idx_path.exists():
            continue
        text = _read_text(idx_path)
        if text and ql in text.lower():
            results.append({
                "type": "article",
                "title": f"{name} · 章节导航",
                "path": idx_path.name,
                "content": _snippet(text, query, 2, 2),
            })
    # 去重 + 截断
    seen = set()
    uniq: List[Dict[str, Any]] = []
    for r in results:
        k = (r["type"], r["title"])
        if k not in seen:
            seen.add(k)
            uniq.append(r)
    return uniq[:limit]


# ---------------------------------------------------------------------------
# 统一入口
# ---------------------------------------------------------------------------
_KIND_MAP = {
    "payload": search_payload,
    "wp": search_wp,
    "script": search_script,
    "article": search_article,
}


def list_articles() -> List[Dict[str, str]]:
    root = kb_root()
    out = []
    for name, desc in ARTICLES:
        p = root / name
        lines = 0
        if p.exists():
            try:
                with p.open("rb") as f:
                    lines = sum(1 for _ in f)
            except OSError:
                lines = 0
        out.append({"file": name, "desc": desc, "lines": lines})
    return out


def search(query: str, kind: str = "all", limit: int = 15) -> Dict[str, Any]:
    if not available():
        return {
            "available": False,
            "root": str(kb_root()),
            "count": 0,
            "results": [],
            "message": "知识库未找到：请确认已克隆 Des-CTF-Knowledge，或设置环境变量 CTF_KB_DIR 指向其根目录。",
        }
    kinds = list(_KIND_MAP.keys()) if kind in ("all", "", None) else [kind]
    results: List[Dict[str, Any]] = []
    for k in kinds:
        if k in _KIND_MAP:
            results.extend(_KIND_MAP[k](query, limit))
    return {
        "available": True,
        "root": str(kb_root()),
        "kind": kind,
        "count": len(results),
        "results": results,
        "message": "",
    }


def read_file(path: str, offset: int = 0, limit: int = 200) -> Dict[str, Any]:
    """读取知识库内指定文件的完整内容（支持分页）。

    path: 相对知识库根目录的文件路径（如 "SQL.md" 或
          "CTF大赛WP集合/articles/xxx.md"）；防路径遍历。
    offset: 起始行号（0-based），limit: 读取行数。
    """
    root = kb_root().resolve()
    p = (kb_root() / path).resolve()
    try:
        p.relative_to(root)
    except ValueError:
        return {"ok": False, "error": "非法路径（越出知识库目录）"}
    if not p.is_file():
        return {"ok": False, "error": f"文件不存在: {path}"}
    text = _read_text(p)
    if text is None:
        return {"ok": False, "error": f"文件读取失败: {path}"}
    lines = text.splitlines()
    total = len(lines)
    start = max(0, int(offset))
    end = min(total, start + max(1, int(limit)))
    return {
        "ok": True,
        "path": path,
        "total": total,
        "offset": start,
        "limit": limit,
        "has_more": end < total,
        "content": "\n".join(lines[start:end]),
    }
