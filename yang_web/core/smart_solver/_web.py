"""yang_web.core.smart_solver 子模块 _web（自 smart_solver.py 拆分，请勿手工重排）。"""

from __future__ import annotations
from ._WebBase import _WebBase
from ._WebInject import _WebInject
from ._WebToken import _WebToken
from ._WebFile import _WebFile
from ._WebRce import _WebRce
from ._WebPhp import _WebPhp

class WebSmartSolver(_WebBase, _WebInject, _WebToken, _WebFile, _WebRce, _WebPhp):
    """增强版 Web 求解器 — 集成所有 payloads 模块."""
    
    # 目录扫描列表（扩展版）
    DIR_LIST = [
        "robots.txt", ".git/HEAD", ".env", ".DS_Store", "backup.zip",
        "admin/", "login.php", "admin.php", "config.php", "db.php",
        "phpinfo.php", "info.php", "test.php", "shell.php", "cmd.php",
        "flag", "flag.txt", "flag.php", "/flag", "/secret", "/api",
        "index.php.bak", "index.php~", "config.php.bak", ".htaccess",
        "www.zip", "www.tar.gz", "source.zip", "backup.sql",
        "swagger.json", "api-docs", "actuator", "actuator/health",
        ".svn/entries", ".hg/requires", ".bzr/branch-format",
        "wp-admin/", "wp-config.php", "wp-content/",
        "WEB-INF/web.xml", "console", "debug/", "debug/default/view",
        "?debug=1", "phpmyadmin/", ".gitignore", "composer.json",
        "package.json", "Dockerfile", "docker-compose.yml",
        "readme.md", "README.md", "CHANGELOG.md",
    ]
