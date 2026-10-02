"""yang_web.core.advanced_scanner 子模块 _dict（自 advanced_scanner.py 拆分，请勿手工重排）。"""

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

from ._common import (find_flag, http_request)



# ═══════════════════════════════════════════════════════════
#  1. Dictionary-based Directory/File Scanner
# ═══════════════════════════════════════════════════════════

class DictScanner:
    """字典式目录/文件爆破引擎.

    三级字典:
    - L1: 精炼核心路径 (高命中率, ~50条, 先跑)
    - L2: 扩展字典 (~200条, 覆盖面广)
    - L3: 智能派生 (从已知路径动态生成)
    """

    # L1: 精炼核心路径 — 高命中率
    L1_PATHS = [
        # 源码泄露
        ".git/HEAD", ".git/config", ".svn/entries", ".DS_Store",
        "www.zip", "www.tar.gz", "backup.zip", "source.zip", "web.zip",
        "wwwroot.zip", "backup.sql", "dump.sql",
        # 配置文件
        ".env", ".env.local", ".env.production", ".env.backup",
        "config.php", "config.php.bak", "config.php~", "config.php.swp",
        "wp-config.php", "wp-config.php.bak", "wp-config.php~",
        "database.yml", "settings.py", "application.properties",
        "WEB-INF/web.xml", "web.config",
        # 敏感文件
        "robots.txt", ".htaccess", ".htpasswd",
        "phpinfo.php", "info.php", "test.php",
        # Flag直接路径
        "flag", "flag.txt", "flag.php", "/flag", "/flag.txt",
        # 管理入口
        "admin/", "admin.php", "login.php", "manage/",
        "phpmyadmin/", "adminer.php",
        # API/调试
        "api/", "api/v1/", "swagger.json", "api-docs",
        "actuator", "actuator/health", "actuator/env",
        "debug/", "debug/default/view",
        # 备份文件
        "index.php.bak", "index.php~", "index.php.swp",
        ".index.php.swp", ".index.php.swo",
        # Docker/CI
        "Dockerfile", "docker-compose.yml", ".dockerignore",
        ".gitlab-ci.yml", "Jenkinsfile",
        # 包管理
        "composer.json", "package.json", "requirements.txt",
        "Gemfile", "pom.xml", "build.gradle",
        # 其他常见
        "readme.md", "README.md", "CHANGELOG.md",
        "upload/", "uploads/", "images/", "static/",
        "vendor/", "node_modules/", ".vscode/",
        "console", "jmx-console", "web-console",
    ]

    # L2: 扩展字典
    L2_PATHS = [
        # Web框架路径
        "wp-admin/", "wp-content/", "wp-includes/", "wp-login.php",
        "wp-json/", "wp-json/wp/v2/users",
        "administrator/", "user/login", "index.php?route=",
        # 源码管理
        ".git/index", ".git/logs/HEAD", ".git/refs/heads/master",
        ".svn/wc.db", ".hg/store/",
        ".bzr/branch/branch.conf",
        # 配置文件
        ".env.dev", ".env.stage", ".env.example",
        "config/config.php", "config/database.php",
        "inc/config.php", "includes/config.php",
        "conf/config.php", "db.php", "database.php",
        "config.py", "config.json", "config.yml",
        "appsettings.json", "appsettings.Development.json",
        "settings/local.py", "settings/production.py",
        # 日志文件
        "error.log", "debug.log", "access.log", "app.log",
        "storage/logs/laravel.log",
        "var/log/", "logs/",
        # 上传目录
        "upload.php", "uploader.php", "fileupload.php",
        "uploads/files/", "uploads/images/",
        "attachment/", "attachments/",
        "tmp/", "temp/", "cache/", "data/",
        # 备份
        "db_backup.sql", "database.sql", "sql.sql",
        "1.sql", "dump.sql.gz",
        "backup/", "backups/",
        "old/", "bak/",
        # API端点
        "api/v1/users", "api/v1/admin", "api/v1/flag",
        "api/flag", "api/admin",
        "graphql", "graphql?query={__schema{types{name}}}",
        "v1/", "v2/", "api/v2/",
        # Spring Boot Actuators
        "actuator/mappings", "actuator/beans", "actuator/configprops",
        "actuator/env", "actuator/heapdump", "actuator/threaddump",
        "actuator/loggers", "actuator/metrics",
        # 敏感信息
        "server-status", "server-info",
        "status", "stats",
        "crossdomain.xml", "clientaccesspolicy.xml",
        "sitemap.xml", ".well-known/security.txt",
        # 默认页面
        "index.html", "home.html", "main.html",
        "default.aspx", "Default.aspx",
        # 常见CMS
        "wp-content/debug.log",
        "administrator/index.php",
        "sites/default/settings.php",
        "misc/", "modules/", "themes/",
        # PHPMyAdmin
        "pma/", "mysql/", "sql/", "dbadmin/",
        # 开发工具
        "phpinfo.php", "info.php", "i.php",
        "test.php", "test.html", "demo/",
        "shell.php", "cmd.php", "exec.php",
        # 敏感脚本
        "cron.php", "task.php", "queue.php",
        "export.php", "import.php", "download.php",
        # 其他
        "favicon.ico", "screenshot.png",
        "redirect", "redirect.php", "go.php", "link.php",
    ]

    # L3 派生规则: 从已知路径动态生成
    DERIVE_RULES = [
        # 如果发现了 admin.php → 尝试 admin/login.php, admin/index.php
        lambda p: [f"admin/{p}"] if p.endswith('.php') else [],
        # 如果发现了 config.php.bak → 尝试 config.php, config.inc.php
        lambda p: [p.replace('.bak', ''), p.replace('.php.bak', '.php')],
        # 如果是 .git/HEAD → 尝试 .git/index, .git/config
        lambda p: ['.git/' + x for x in ['config', 'index', 'logs/HEAD', 'refs/heads/master']] if '.git/HEAD' in p else [],
    ]

    def __init__(self, base_url: str, max_workers: int = 20, 
                 timeout: int = 3, levels: List[int] = None):
        self.base_url = base_url.rstrip("/")
        self.max_workers = max_workers
        self.timeout = timeout
        self.levels = levels or [1, 2]
        self.results: List[dict] = []
        self.found_paths: Set[str] = set()
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def scan(self, on_progress=None, on_flag=None) -> dict:
        """Run dictionary scan and return results."""
        t0 = time.time()
        tasks = []

        # Build task list by level
        if 1 in self.levels:
            for path in self.L1_PATHS:
                tasks.append(("L1", path))
        if 2 in self.levels:
            for path in self.L2_PATHS:
                tasks.append(("L2", path))

        results = []
        found_flag = [None]

        def _emit(stage, item, status):
            if on_progress:
                try:
                    on_progress(stage, item, status)
                except Exception:
                    pass

        _emit("dict_scan", f"字典扫描启动", f"L1:{len(self.L1_PATHS)} + L2:{len(self.L2_PATHS)} = {len(tasks)} 路径")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {}
            for level, path in tasks:
                if self._cancelled:
                    break
                test_url = f"{self.base_url}/{path.lstrip('/')}"
                futures[executor.submit(self._check_path, test_url, path, level)] = (path, level)

            try:
                for future in as_completed(futures, timeout=self.timeout * len(tasks) // self.max_workers + 10):
                    if self._cancelled or found_flag[0]:
                        break
                    result = future.result()
                    if result:
                        results.append(result)
                        self.found_paths.add(result["path"])
                        # Flag check
                        body = result.get("body", "")
                        if body:
                            f = find_flag(body)
                            if f:
                                found_flag[0] = f
                                if on_flag:
                                    try:
                                        on_flag(f)
                                    except Exception:
                                        pass
                                _emit("flag", result["path"], f)
            except FuturesTimeoutError:
                pass
            finally:
                for f in futures:
                    f.cancel()

        # L3: Dynamic derivation from L1 results
        if 3 in self.levels and self.found_paths and not self._cancelled:
            derived = set()
            for fp in self.found_paths:
                for rule in self.DERIVE_RULES:
                    try:
                        for dp in rule(fp):
                            if dp not in derived and dp not in self.found_paths:
                                derived.add(dp)
                    except Exception:
                        pass
            if derived:
                _emit("dict_scan", "L3派生扫描", f"{len(derived)} 派生路径")
                l3_tasks = {executor.submit(self._check_path,
                    f"{self.base_url}/{p.lstrip('/')}", p, 3): p for p in list(derived)[:50]}
                try:
                    for future in as_completed(l3_tasks, timeout=15):
                        if self._cancelled or found_flag[0]:
                            break
                        result = future.result()
                        if result:
                            results.append(result)
                            if result.get("body"):
                                f = find_flag(result["body"])
                                if f and not found_flag[0]:
                                    found_flag[0] = f
                except FuturesTimeoutError:
                    pass
                finally:
                    for f in l3_tasks:
                        f.cancel()

        # Sort: interesting first (200 OK with content)
        results.sort(key=lambda r: (
            0 if r.get("status") == 200 and r.get("body_len", 0) > 0 else
            1 if r.get("status") in (301, 302, 403) else
            2
        ))

        timing = int((time.time() - t0) * 1000)
        return {
            "success": len(results) > 0,
            "flag": found_flag[0],
            "paths_found": results,
            "count": len(results),
            "timing_ms": timing,
        }

    def _check_path(self, url: str, original_path: str, level: int) -> Optional[dict]:
        """Check a single path."""
        try:
            resp = http_request(url, timeout=self.timeout)
            if resp["ok"] and resp["status"] not in (404,):
                return {
                    "path": original_path,
                    "url": url,
                    "level": level,
                    "status": resp["status"],
                    "body_len": resp["body_len"],
                    "body": resp["body"][:2000],
                    "title": self._extract_title(resp["body"]),
                }
        except Exception:
            pass
        return None

    @staticmethod
    def _extract_title(html: str) -> str:
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip()[:60] if m else ""
