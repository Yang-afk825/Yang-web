"""yang_web.core.multi_stage._engine 混入 _Base —— 主流程编排与生命周期（初始化 / 取消 / solve 主循环）。"""

from __future__ import annotations
import re
import time
from urllib.parse import urljoin
from typing import Dict, List, Optional, Tuple, Set, Callable
from ._analyzer import (PageAnalyzer)
from ._common import (COMMON_CREDENTIALS, FLAG_RE, LFI_PAYLOADS, XXE_PAYLOADS)
from ._http import (SessionHTTP)

class _Base:
    """主流程编排与生命周期（初始化 / 取消 / solve 主循环）。"""


    def __init__(self, timeout: int = 8, max_stages: int = 5):
        self.timeout = timeout
        self.max_stages = max_stages
        self.http = SessionHTTP(timeout=timeout)
        self.analyzer = PageAnalyzer()
        self.attack_log: List[dict] = []
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def solve(self, url: str, on_progress=None, on_flag=None) -> dict:
        """主入口: 自动多阶段解题.

        Returns:
            {"success": bool, "flag": str|None, "stages": [...],
             "attack_log": [...], "timing_ms": int}
        """
        t0 = time.time()
        self._cancelled = False
        self._base_url = url
        self.attack_log = []
        found_flag = None

        def _emit(stage, item, status):
            if on_progress:
                try:
                    on_progress(stage, item, status)
                except Exception:
                    pass

        def _found(flag):
            nonlocal found_flag
            if not found_flag:
                found_flag = flag
                if on_flag:
                    try:
                        on_flag(flag)
                    except Exception:
                        pass

        _emit("multi", url, "🚀 启动多阶段自动解题...")

        current_url = url
        visited: Set[str] = set()

        for stage_num in range(1, self.max_stages + 1):
            if self._cancelled or found_flag:
                break

            # Step 1: 请求当前页面
            _emit("stage", f"第{stage_num}阶段", f"请求: {current_url[:60]}")
            if current_url in visited:
                _emit("stage", "循环检测", "URL 已访问过，跳过")
                break
            visited.add(current_url)

            resp = self.http.request(current_url)
            if resp["error"]:
                _emit("stage", "请求失败", resp["error"][:60])
                break

            body = resp["body"]
            headers = resp["headers"]

            # Step 1.5: 404/error on base URL → auto-discover common paths
            is_404 = resp["status"] in (404, 403) and stage_num == 1
            if is_404:
                # Quick check: is this a real 404 page?
                not_found_markers = ['404', 'not found', 'Not Found', 'Not Found']
                looks_404 = any(m in body for m in not_found_markers)
                has_forms = re.search(r'<form\b', body, re.I)
                if looks_404 and not has_forms:
                    _emit("stage", "入口404", "自动探测常见路径...")
                    discovered = self._discover_urls(current_url, _emit)
                    if discovered:
                        current_url = discovered[0]
                        resp = self.http.request(current_url)
                        if resp["error"]:
                            _emit("stage", "请求失败", resp["error"][:60])
                            break
                        body = resp["body"]
                        headers = resp["headers"]
                        _emit("redirect", current_url[:60], f"发现入口 ({len(discovered)}个)")
                        visited.add(current_url)  # Mark the discovered URL as visited
                    else:
                        _emit("stage", "路径终止", "404且无可用入口")
                        self.attack_log.append({"stage": 1, "url": current_url,
                            "type": "404", "attack": None, "result": "dead_end"})
                        break

            # Step 2: 分析页面
            analysis = self.analyzer.analyze(body, current_url, headers)
            page_type = analysis["type"]
            _emit("page_type", current_url[:50], f"识别: {page_type} | 标题: {analysis['title'][:30]}")

            # Flask/Werkzeug server → auto-upgrade to SSTI detection
            server = headers.get("Server", "")
            if page_type == "unknown" and ("Werkzeug" in server or "Flask" in server or "Python" in server):
                page_type = "ssti"
                _emit("page_type", "Flask detected", "auto-upgrade: SSTI")

            stage_record = {
                "stage": stage_num,
                "url": current_url,
                "type": page_type,
                "analysis": analysis,
                "attack": None,
                "result": None,
            }

            # Step 3: 检查 Flag
            if analysis["flags"]:
                _found(analysis["flags"][0])
                stage_record["result"] = "flag_found"
                self.attack_log.append(stage_record)
                break

            # Step 4: 终端页面检测
            if analysis["is_terminal"]:
                body_flag = FLAG_RE.search(body)
                if body_flag:
                    _found(body_flag.group(0))
                stage_record["result"] = "terminal"
                self.attack_log.append(stage_record)
                break

            # Step 5: 根据页面类型执行对应攻击
            next_stage_url = None

            if page_type == "login":
                next_stage_url = self._stage_login(current_url, resp, analysis, _emit, _found)

            elif page_type == "xxe":
                next_stage_url = self._stage_xxe(current_url, resp, analysis, _emit, _found)

            elif page_type in ("ssti", "unknown"):
                # SSTI: explicit match or fallback for unknown pages
                next_stage_url = self._stage_ssti(current_url, resp, analysis, _emit, _found)
                if not next_stage_url and page_type == "unknown":
                    next_stage_url = self._stage_generic(current_url, resp, analysis, _emit, _found)

            elif page_type == "command":
                next_stage_url = self._stage_rce(current_url, resp, analysis, _emit, _found)

            elif page_type in ("search",):
                # Search page → SQLi/XSS
                next_stage_url = self._stage_generic(current_url, resp, analysis, _emit, _found)

            else:
                _emit("stage", "未知类型", f"尝试通用攻击")

            # Step 6: 处理 JS 重定向
            if not next_stage_url and analysis["redirects"]:
                redirect = analysis["redirects"][0]
                if not redirect.startswith("http"):
                    redirect = urljoin(current_url, redirect)
                _emit("redirect", redirect[:60], "JS 重定向跟随")
                next_stage_url = redirect

            # Step 7: 页面内链接发现
            if not next_stage_url and not found_flag:
                links = re.findall(r'href\s*=\s*["\']([^"\']+)', body, re.I)
                unvisited = []
                for link in links[:20]:
                    if link.startswith("#") or link.startswith("javascript:"):
                        continue
                    full = urljoin(current_url, link)
                    if full not in visited and ".php" in full.lower():
                        unvisited.append(full)
                if unvisited:
                    next_stage_url = unvisited[0]
                    _emit("link", next_stage_url[:60], f"发现 {len(unvisited)} 个未访问链接")

            if next_stage_url:
                if next_stage_url in visited:
                    # Check if we've already visited, move to next unvisited
                    unvisited_links = [l for l in re.findall(r'href\s*=\s*["\']([^"\']+)', body, re.I) 
                                       if not l.startswith("#") and not l.startswith("javascript:")]
                    for link in unvisited_links:
                        full = urljoin(current_url, link)
                        if full not in visited:
                            next_stage_url = full
                            break
                    else:
                        next_stage_url = None  # All visited

            stage_record["result"] = "next_stage" if next_stage_url else "dead_end"
            self.attack_log.append(stage_record)

            if not next_stage_url:
                _emit("stage", "路径终止", "无更多可攻击阶段")
                break

            current_url = next_stage_url

        timing = int((time.time() - t0) * 1000)
        return {
            "success": bool(found_flag),
            "flag": found_flag,
            "attack_log": self.attack_log,
            "stages_count": len(self.attack_log),
            "timing_ms": timing,
        }
