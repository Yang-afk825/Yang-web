# -*- coding: utf-8 -*-
"""版本号一致性守卫。

历史上同一时刻代码里并存过 1.4.0 / 3.6 / 4.0.0 三个版本号：
CLI 包里写着 4.0，(GUI 标题写 3.6)，GUI 状态栏写 1.4.0，
`yang_web.__version__` 是 1.4.0 —— 而 pyproject 是 4.0.0。
所以这里把「单一版本来源」固化成测试：所有展示串与字面量都必须与
`yang_web.__version__` 同源。
"""
from __future__ import annotations

import os
import re
import unittest

import yang_web

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# "Yang-Web v4.1" / "Yang-Web Arsenal v4.1" 这类展示串
DISPLAY_RE = re.compile(r'Yang-Web(?: Arsenal)? v(\d+\.\d+(?:\.\d+)?)')
# 字面量：version = "4.1.0" / "version": "4.1.0"
LITERAL_RE = re.compile(r'version["\']?\s*[:=]\s*["\'](\d+\.\d+\.\d+)["\']')

SCAN_EXT = ('.py', '.spec', '.toml', '.yml', '.yaml')
SKIP_DIRS = {'__pycache__', '.git', 'node_modules', 'build', 'dist',
             '.build-venv', '.venv', 'venv'}


def norm(v):
    """把 4.1 / 4.1.0 归一成同一元组，允许展示串用短写法。"""
    parts = (v.split('.') + ['0', '0'])[:3]
    return tuple(int(x) for x in parts)


class TestVersionConsistency(unittest.TestCase):
    def test_pyproject_matches_dunder(self):
        path = os.path.join(REPO, 'pyproject.toml')
        with open(path, encoding='utf-8') as fh:
            text = fh.read()
        m = re.search(r'^version\s*=\s*["\']([^"\']+)["\']', text, re.M)
        self.assertIsNotNone(m, 'pyproject.toml 里找不到 version 字段')
        self.assertEqual(norm(m.group(1)), norm(yang_web.__version__),
                         'pyproject.toml (%s) 与 yang_web.__version__ (%s) 不一致'
                         % (m.group(1), yang_web.__version__))

    def test_no_hardcoded_version_drift(self):
        want = norm(yang_web.__version__)
        bad = []
        for root, dirs, files in os.walk(REPO):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            if 'Des-CTF-Knowledge' in root:
                continue
            for fname in files:
                if not fname.endswith(SCAN_EXT):
                    continue
                full = os.path.join(root, fname)
                rel = os.path.relpath(full, REPO).replace('\\', '/')
                try:
                    with open(full, encoding='utf-8') as fh:
                        lines = fh.read().splitlines()
                except (OSError, UnicodeDecodeError):
                    continue
                for i, line in enumerate(lines, 1):
                    for rx in (DISPLAY_RE, LITERAL_RE):
                        for m in rx.finditer(line):
                            if norm(m.group(1)) != want:
                                bad.append('%s:%d  写死的 %s（应为 %s）'
                                           % (rel, i, m.group(0), yang_web.__version__))
        self.assertEqual(bad, [], '发现版本号漂移：\n  ' + '\n  '.join(bad))

    def test_display_strings_use_dunder(self):
        """展示串必须走 f-string 插值，而不是自己写死数字。"""
        for rel in ('yang_web/server.py', 'yang_web/gui/_app.py'):
            with open(os.path.join(REPO, rel), encoding='utf-8') as fh:
                text = fh.read()
            self.assertIn('__version__', text, '%s 未引用 __version__' % rel)


if __name__ == '__main__':
    unittest.main()
