# -*- coding: utf-8 -*-
"""
JS / 客户端挑战求解器 — 处理浏览器端 CTF 题目

支持的挑战类型:
    1. 游戏类 (2048/FlappyBird/Snake...) — 提取胜利条件、作弊码、JS 直接调用
    2. JS 加密/解密 — 逆向客户端加密逻辑
    3. 硬编码 Flag — 直接在 JS/HTML 中搜索 flag 模式
    4. WebSocket/API — 分析客户端请求，重放进阶
    5. Canvas/WebGL — 提取隐写数据
    6. WebAssembly — wasm 分析

解题策略:
    - 阶段1: 静态分析 — 提取所有 JS/HTML，正则搜索 flag/密钥/条件
    - 阶段2: 逻辑还原 — 识别游戏规则、加密算法、状态机
    - 阶段3: 暴力/绕过 — 生成浏览器控制台命令、直接调用内部函数

@author Yang-Web Arsenal v2.2
"""
from __future__ import annotations

import re
import json
import ssl
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field


# ═══════════════════════════════════════════════════════════
#  挑战检测模式
# ═══════════════════════════════════════════════════════════

FLAG_PATTERNS = [
    re.compile(r'[A-Za-z]{2,10}\{[^}]{3,80}\}'),      # 通用 CTF flag
    re.compile(r'alert\(["\']([A-Za-z]{2,10}\{[^}]*\})["\']', re.IGNORECASE),
    re.compile(r'(?:flag|secret|token)\s*[:=]\s*["\']([^"\']{5,100})["\']', re.IGNORECASE),
]

GAME_PATTERNS = [
    ("2048", [r'2048', r'checkFlagTile', r'\.value\s*==\s*2048', r'konamiCode']),
    ("Snake", [r'SnakeGame', r'snake', r'foodPosition']),
    ("FlappyBird", [r'FlappyBird', r'birdY', r'pipe', r'gravity']),
    ("Minesweeper", [r'Minesweeper', r'mineField', r'reveal']),
    ("Tetris", [r'@Tetris', r'tetris', r'board.*20.*10']),
    ("TypingGame", [r'typing', r'scramble', r'wordList']),
]

KONAMI_PATTERN = re.compile(
    r'(?:konami|cheat|secret)\s*Code\s*=\s*\[([^\]]+)\]', re.IGNORECASE
)

JS_CHECK_FUNCTIONS = [
    r'function\s+(check\w*[Ff]lag|show\w*[Ff]lag|get\w*[Ff]lag|win|complete|success)',
    r'(?:key|secret|code|password)\s*(?:==|===)\s*["\']([^"\']+)["\']',
    r'localStorage\.(?:set|get)Item\(["\'](.*?)["\']',
    r'fetch\(["\']([^"\']*flag[^"\']*)["\']',
    r'XMLHttpRequest.*?open\(["\']\w+["\'],\s*["\']([^"\']*flag[^"\']*)["\']',
]


# ═══════════════════════════════════════════════════════════
#  数据结构
# ═══════════════════════════════════════════════════════════

@dataclass
class JSChallengeReport:
    """JS 挑战分析报告."""
    url: str = ""
    title: str = ""
    game_type: str = ""
    flags_found: List[str] = field(default_factory=list)
    cheat_codes: List[str] = field(default_factory=list)
    win_conditions: List[str] = field(default_factory=list)
    console_commands: List[str] = field(default_factory=list)
    js_files: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    localStorage_keys: List[str] = field(default_factory=list)
    vulnerable_functions: List[str] = field(default_factory=list)
    summary: str = ""


# ═══════════════════════════════════════════════════════════
#  核心分析引擎
# ═══════════════════════════════════════════════════════════

class JSChallengeSolver:
    """JS / 客户端 CTF 挑战自动求解引擎."""

    def __init__(self, verbose: bool = True):
        self.verbose = verbose
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

    def _log(self, msg: str, level: str = "info"):
        if not self.verbose:
            return
        p = {"info": "  [*]", "ok": "  [+]", "err": "  [-]", "warn": "  [!]",
             "flag": "  [FLAG]", "cmd": "  [→]"}.get(level, "  [*]")
        print(f"{p} {msg}")

    def _fetch(self, url: str) -> Optional[str]:
        """获取页面或资源."""
        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            with urllib.request.urlopen(req, timeout=15, context=self._ssl_ctx) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            self._log(f"获取失败 {url}: {e}", "err")
            return None

    # ── 阶段1: 静态分析 ──

    def _extract_js_urls(self, html: str, base_url: str) -> List[str]:
        """从 HTML 中提取所有 JS 文件 URL."""
        urls = []
        # <script src="...">
        for m in re.finditer(r"""<script[^>]+src=["']([^"']+)["']""", html):
            src = m.group(1)
            if src.startswith("http"):
                urls.append(src)
            elif src.startswith("//"):
                urls.append("https:" + src)
            else:
                urls.append(base_url.rstrip("/") + "/" + src.lstrip("/"))
        return urls

    def _search_flags(self, content: str) -> List[str]:
        """在文本中搜索 flag 模式."""
        flags = []
        # 优先匹配已知 CTF flag 格式
        for pat in FLAG_PATTERNS:
            for m in pat.finditer(content):
                flag = m.group(1) if m.lastindex else m.group(0)
                # 过滤误报：排除包含 JS 关键字的匹配
                if any(kw in flag for kw in ['function', 'keyName', 'keyCode', 'currentItem', 'var ', 'if(']):
                    continue
                if len(flag) < 60 and '\n' not in flag:
                    flags.append(flag)
        # 去重
        seen = set()
        result = []
        for f in flags:
            if f not in seen:
                seen.add(f)
                result.append(f)
        return result

    def _detect_game_type(self, js_content: str) -> str:
        """检测游戏类型."""
        for game_name, patterns in GAME_PATTERNS:
            score = sum(1 for p in patterns if re.search(p, js_content, re.IGNORECASE))
            if score >= 2:
                return game_name
        return "unknown"

    def _find_cheat_codes(self, js_content: str) -> List[str]:
        """查找作弊码/Konami 码."""
        codes = []
        m = KONAMI_PATTERN.search(js_content)
        if m:
            # 解析数组内容
            raw = m.group(1)
            keys = re.findall(r"""['"]([^'"]+)['"]""", raw)
            if keys:
                codes.append(" → ".join(keys))
                self._log(f"发现作弊码: {' + '.join(keys)}", "ok")

        # 也找直接的条件比较
        for m in re.finditer(r'(?:password|code|secret)\s*(?:==|===)\s*["\']([^"\']{2,30})["\']', js_content, re.IGNORECASE):
            codes.append(m.group(1))

        return codes

    def _find_api_endpoints(self, js_content: str) -> List[str]:
        """查找 API 端点."""
        endpoints = set()
        for pat in [
            r'fetch\(["\']([^"\']+)["\']',
            r'\.open\(["\']\w+["\'],\s*["\']([^"\']+)["\']',
            r'\.ajax\(\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
        ]:
            for m in re.finditer(pat, js_content):
                endpoints.add(m.group(1))
        return sorted(endpoints)

    def _find_localstorage(self, js_content: str) -> List[str]:
        """查找 localStorage 键."""
        keys = set()
        for m in re.finditer(r'localStorage\.(?:get|set)Item\(["\']([^"\']+)["\']', js_content):
            keys.add(m.group(1))
        return sorted(keys)

    def _generate_console_commands(self, report: JSChallengeReport, js_content: str) -> List[str]:
        """生成浏览器控制台命令."""
        cmds = []

        # 直接调用 showFlag / getFlag 等函数
        for m in re.finditer(r'function\s+(show\w*[Ff]lag|get\w*[Ff]lag|reveal\w*[Ff]lag)\s*\(', js_content):
            fn = m.group(1)
            cmds.append(f"{fn}();")

        # 如果有 Konami 码，生成按键模拟
        if report.cheat_codes:
            code_keys = report.cheat_codes[0].split(" → ")
            # 生成 dispatchEvent 序列
            key_map = {"up": "ArrowUp", "down": "ArrowDown", "left": "ArrowLeft", "right": "ArrowRight", "b": "b", "a": "a"}
            events = []
            for k in code_keys:
                mapped = key_map.get(k.lower(), k)
                events.append(
                    f"document.dispatchEvent(new KeyboardEvent('keydown',{{key:'{mapped}',keyCode:{ord(mapped[0].upper())}}}));"
                )
            cmds.append("// 自动输入作弊码：")
            # 合并为一行
            cmds.append("setTimeout(function(){" + ";".join(
                f"setTimeout(function(){{{e}}},{i*50})" for i, e in enumerate(events)
            ) + "},500);")

        # localStorage 操作
        for key in report.localStorage_keys:
            if re.search(r'score|high|best|win', key, re.IGNORECASE):
                cmds.append(f"// 修改分数：localStorage.setItem('{key}', '9999999');")

        # 直接调用内部函数放置大数字 (2048 游戏)
        if report.game_type == "2048":
            cmds.append("// 2048 - 直接调用 checkFlagTile 获取 flag:")
            cmds.append("checkFlagTile(2048);")
            cmds.append("// 或输入 Konami 码: ↑↑↓↓←→←→BA")
            cmds.append("// 或直接: showFlag();")

        return cmds

    # ── 主分析流程 ──

    def analyze(self, url: str) -> JSChallengeReport:
        """分析 JS 挑战，返回完整报告."""
        report = JSChallengeReport(url=url)

        # 1. 获取 HTML
        self._log(f"分析: {url}", "info")
        html = self._fetch(url)
        if not html:
            report.summary = "无法获取页面"
            return report

        # 提取标题
        title_m = re.search(r'<title>(.*?)</title>', html)
        report.title = title_m.group(1).strip() if title_m else ""

        # 2. 提取 JS 文件
        js_urls = self._extract_js_urls(html, url)
        report.js_files = js_urls
        self._log(f"发现 {len(js_urls)} 个 JS 文件", "info")

        # 3. 合并所有 JS 内容
        all_js = ""
        # 内联 JS
        for m in re.finditer(r'<script[^>]*>(.*?)</script>', html, re.DOTALL):
            s = m.group(1).strip()
            if s:
                all_js += s + "\n"

        # 外部 JS
        for js_url in js_urls:
            if "jquery" in js_url.lower() or "bootstrap" in js_url.lower():
                continue  # 跳过库文件
            js = self._fetch(js_url)
            if js:
                all_js += f"\n// --- {js_url} ---\n" + js + "\n"
                self._log(f"  JS: {js_url.split('/')[-1]} ({len(js)}B)", "ok")

        # 4. 搜索 flag
        flags = self._search_flags(html + all_js)
        if flags:
            report.flags_found = flags
            for f in flags:
                self._log(f"发现 Flag: {f}", "flag")

        # 5. 检测游戏类型
        report.game_type = self._detect_game_type(all_js)
        if report.game_type != "unknown":
            self._log(f"检测到游戏: {report.game_type}", "ok")

        # 6. 找作弊码
        report.cheat_codes = self._find_cheat_codes(all_js)

        # 7. 找 API 端点
        report.api_endpoints = self._find_api_endpoints(all_js)

        # 8. 找 localStorage
        report.localStorage_keys = self._find_localstorage(all_js)

        # 9. 找 flag 检查函数
        for pat in JS_CHECK_FUNCTIONS:
            for m in re.finditer(pat, all_js):
                detail = m.group(0)[:120]
                report.vulnerable_functions.append(detail)

        # 10. 生成控制台命令
        report.console_commands = self._generate_console_commands(report, all_js)

        # 11. 生成摘要
        parts = []
        if report.title:
            parts.append(f"页面: {report.title}")
        if report.game_type != "unknown":
            parts.append(f"类型: {report.game_type} 游戏")
        if report.flags_found:
            parts.append(f"Flag: {', '.join(report.flags_found)}")
        if report.cheat_codes:
            parts.append(f"作弊码: {', '.join(report.cheat_codes)}")

        report.summary = " | ".join(parts) if parts else "未找到明显解题线索"
        self._log(f"分析完成: {report.summary}", "ok")

        return report


# ═══════════════════════════════════════════════════════════
#  GUI 接口
# ═══════════════════════════════════════════════════════════

def solve_js_challenge(url: str, callback: Callable = None) -> dict:
    """GUI 调用接口."""
    solver = JSChallengeSolver(verbose=False)
    if callback:
        callback("正在获取页面...", 10)

    report = solver.analyze(url)

    if callback:
        callback(f"分析完成: {report.summary}", 100)

    return {
        "success": bool(report.flags_found or report.cheat_codes),
        "title": report.title,
        "game_type": report.game_type,
        "flags": report.flags_found,
        "cheat_codes": report.cheat_codes,
        "console_commands": report.console_commands,
        "js_files": report.js_files,
        "api_endpoints": report.api_endpoints,
        "localstorage_keys": report.localStorage_keys,
        "full_report": report,
    }


# ═══════════════════════════════════════════════════════════
#  独立运行
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = input("URL: ").strip()

    if not url:
        print("用法: python js_challenge_solver.py <URL>")
        sys.exit(1)

    solver = JSChallengeSolver(verbose=True)
    report = solver.analyze(url)

    print("\n" + "=" * 60)
    print("  分析报告")
    print("=" * 60)

    if report.title:
        print(f"  页面: {report.title}")
    print(f"  游戏类型: {report.game_type}")

    if report.flags_found:
        print(f"\n  🏁 Flag:")
        for f in report.flags_found:
            print(f"    {f}")

    if report.cheat_codes:
        print(f"\n  🎮 作弊码:")
        for c in report.cheat_codes:
            print(f"    {c}")

    if report.console_commands:
        print(f"\n  💻 浏览器控制台命令 (F12 → Console):")
        for c in report.console_commands:
            print(f"    > {c}")

    if report.js_files:
        print(f"\n  📜 JS 文件 ({len(report.js_files)}):")
        for f in report.js_files:
            print(f"    {f.split('/')[-1]}")

    if report.api_endpoints:
        print(f"\n  🌐 API 端点:")
        for e in report.api_endpoints:
            print(f"    {e}")

    print(f"\n  📋 摘要: {report.summary}")
    print("=" * 60)
