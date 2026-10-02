# -*- coding: utf-8 -*-
"""版本号一致性守卫。

历史上同一时刻代码里并存过 1.4.0 / 3.6 / 4.0.0 / 4.1.0 多个版本号：
CLI 包里写着 4.0、（GUI 标题写 3.6）、GUI 状态栏写 1.4.0、
`yang_web.__version__` 是 1.4.0 —— 而 pyproject 是 4.0.0。
更糟的是 Web UI：`web/index.html` 的 <title> 与左上角 logo 各写死一份
`v4.0`，所以 4.1.0 的 exe 启动后眼睛看到的仍是「v4.0」。

所以这里把「单一版本来源」固化成测试：所有展示串、字面量与 UA 串
都必须与 `yang_web.__version__` 同源。

覆盖范围刻意包含 `.html` 与 README —— 上一版只扫 .py/.spec/.toml/.yml，
正是这两个漏点让"页面显示 v4.0"的缺陷一路发到了 Release。
"""
from __future__ import annotations

import os
import re
import unittest

import yang_web

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 本文件自身必须排除：说明文字里必然出现被检查的子串（自我误伤）
SELF = 'tests/test_version.py'

# "Yang-Web v4.1" / "Yang-Web Arsenal v4.1" 这类展示串
DISPLAY_RE = re.compile(r'Yang-Web(?: Arsenal)? v(\d+\.\d+(?:\.\d+)?)')
# 字面量：version = "4.1.1" / "version": "4.1.1"
LITERAL_RE = re.compile(r'version["\']?\s*[:=]\s*["\'](\d+\.\d+\.\d+)["\']')
# UA 串：YangWeb/4.1.1
UA_RE = re.compile(r'YangWeb/(\d+\.\d+(?:\.\d+)?)')
# README 首行标题：# Yang-Web 🛠️ v4.1.1（标题与版本号之间允许有 emoji 等）
README_TITLE_RE = re.compile(r'^#\s+Yang-Web\b[^\n]*?\bv(\d+\.\d+(?:\.\d+)?)')

SCAN_EXT = ('.py', '.spec', '.toml', '.yml', '.yaml', '.html')
SKIP_DIRS = {'__pycache__', '.git', 'node_modules', 'build', 'dist',
             '.build-venv', '.venv', 'venv'}


def norm(v):
    """把 4.1 / 4.1.0 归一成同一元组，允许展示串用短写法。"""
    parts = (v.split('.') + ['0', '0'])[:3]
    return tuple(int(x) for x in parts)


def read(rel):
    with open(os.path.join(REPO, rel), encoding='utf-8') as fh:
        return fh.read()


class TestVersionConsistency(unittest.TestCase):

    def test_pyproject_matches_dunder(self):
        m = re.search(r'^version\s*=\s*["\']([^"\']+)["\']',
                      read('pyproject.toml'), re.M)
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
                if rel == SELF:
                    continue
                try:
                    with open(full, encoding='utf-8') as fh:
                        lines = fh.read().splitlines()
                except (OSError, UnicodeDecodeError):
                    continue
                for i, line in enumerate(lines, 1):
                    for rx in (DISPLAY_RE, LITERAL_RE, UA_RE):
                        for m in rx.finditer(line):
                            if norm(m.group(1)) != want:
                                bad.append('%s:%d  写死的 %s（应为 %s）'
                                           % (rel, i, m.group(0),
                                              yang_web.__version__))
        self.assertEqual(bad, [], '发现版本号漂移：\n  ' + '\n  '.join(bad))

    def test_display_strings_use_dunder(self):
        """运行时展示串必须走 f-string 插值，而不是自己写死数字。"""
        for rel in ('yang_web/server.py', 'yang_web/gui/_app.py'):
            self.assertIn('__version__', read(rel), '%s 未引用 __version__' % rel)

    def test_web_ui_version_is_injected(self):
        """Web UI 不得写死版本号，必须用 __VERSION__ 占位符由服务端注入。

        这是上一版漏掉的那处：4.1.0 的 exe 启动后页面仍显示 v4.0，
        因为 index.html 的 <title> 和 logo 各写死了一份。
        """
        html = read('yang_web/web/index.html')
        self.assertIn('__VERSION__', html,
                      'web/index.html 未使用 __VERSION__ 占位符')
        stray = DISPLAY_RE.findall(html)
        self.assertEqual(stray, [],
                         'web/index.html 里仍有写死的版本号：%s' % (stray,))
        # 服务端必须真的做了替换，否则占位符会原样漏到页面上
        self.assertIn('__VERSION__', read('yang_web/server.py'),
                      'server.py 未注入 __VERSION__')

    def test_readme_title_matches_dunder(self):
        """README 首行是仓库首页最大的字，必须与 __version__ 一致。"""
        with open(os.path.join(REPO, 'README.md'), encoding='utf-8') as fh:
            first = fh.readline().strip()
        m = README_TITLE_RE.search(first)
        self.assertIsNotNone(m, 'README 首行找不到版本号：%r' % first)
        self.assertEqual(norm(m.group(1)), norm(yang_web.__version__),
                         'README 首行 (%s) 与 __version__ (%s) 不一致'
                         % (first, yang_web.__version__))


if __name__ == '__main__':
    unittest.main()
