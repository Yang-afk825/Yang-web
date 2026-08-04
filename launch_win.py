# -*- coding: utf-8 -*-
"""Yang-Web v4.0 exe 启动入口 (无控制台版)。

启动 FastAPI 服务 + pywebview 独立窗口。
"""
import os
import sys

# 打包后资源路径修正
if getattr(sys, 'frozen', False):
    _BASE = sys._MEIPASS
else:
    _BASE = os.path.dirname(os.path.abspath(__file__))

if _BASE not in sys.path:
    sys.path.insert(0, _BASE)


def main():
    try:
        from yang_web.server import main as server_main
        server_main()
    except Exception as e:
        import traceback
        # 写错误日志便于排查
        try:
            log_path = os.path.join(os.path.dirname(sys.executable), 'yangweb_error.log')
            with open(log_path, 'w', encoding='utf-8') as f:
                traceback.print_exc(file=f)
        except Exception:
            pass


if __name__ == '__main__':
    main()
