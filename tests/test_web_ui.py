# -*- coding: utf-8 -*-
"""Web UI 端到端守卫：页面实际渲染出的版本号必须等于 `__version__`。

背景：`web/index.html` 的 <title> 与左上角 logo 曾各写死一份 `v4.0`，
导致 4.1.0 的 exe 启动后眼睛看到的仍是「v4.0」。
单纯断言"占位符存在"不够——必须真的请求一次 `/`、确认替换发生了
且没有旧版本号残留。

依赖 fastapi + httpx，缺失时 skip：CI 的纯标准库 job 会跳过，
而 release.yml 装了打包依赖，所以**发布前一定会真的跑到**。
"""
from __future__ import annotations

import re
import unittest

import yang_web

try:
    from fastapi.testclient import TestClient
    from yang_web import server
    _SKIP_REASON = None
except Exception as _e:  # pragma: no cover - 环境相关
    _SKIP_REASON = 'fastapi / httpx 不可用: %s' % _e

DISPLAY_RE = re.compile(r'Yang-Web v(\d+\.\d+(?:\.\d+)?)')


def _norm(v):
    parts = (v.split('.') + ['0', '0'])[:3]
    return tuple(int(x) for x in parts)


@unittest.skipIf(_SKIP_REASON, _SKIP_REASON or '')
class TestWebUiVersion(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(server.app)

    def test_index_renders_current_version(self):
        r = self.client.get('/')
        self.assertEqual(r.status_code, 200)
        html = r.text
        self.assertNotIn('__VERSION__', html,
                         'index.html 的占位符未被替换，原样漏到了页面上')

        found = DISPLAY_RE.findall(html)
        self.assertTrue(found, '页面里没有渲染出任何版本号')
        for v in found:
            self.assertEqual(_norm(v), _norm(yang_web.__version__),
                             '页面渲染出的版本 %s != __version__ %s'
                             % (v, yang_web.__version__))
    def test_health_endpoint_version(self):
        d = self.client.get('/api/health').json()
        self.assertEqual(d.get('version'), yang_web.__version__)

    def test_openapi_version(self):
        self.assertEqual(server.app.version, yang_web.__version__)


if __name__ == '__main__':
    unittest.main()
