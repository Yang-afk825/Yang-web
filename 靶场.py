# -*- coding: utf-8 -*-
"""Yang-Web 脚本库靶场 — 4 关 Web 挑战 (全部可用脚本库 URL 型脚本解)

用法:  python 靶场.py [port]
默认端口 9999, 浏览器打开 http://127.0.0.1:9999/

关卡 (均可被 Yang-Web 脚本库/自动攻击解开):
  Level 1  时间盲注  → 脚本库 time_sqli.py (填 URL)
  Level 2  布尔盲注  → 脚本库 bool_inject.py (填 URL)
  Level 3  JS 硬编码 flag → 脚本库 js_challenge_solver.py (填 URL)
  Level 4  命令执行  → 自动攻击页 simple_cmd_rce

依赖: 仅 Python 标准库 (http.server + sqlite3), 零外部依赖
"""
import base64
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9999
FLAG = "Geesec{web_range_4in1_flag_2026}"

# ── SQLite 内存数据库 (Level 1/2) ──
# 注意: ThreadingHTTPServer 多线程下 sqlite :memory: 每个线程独立,
# 必须用文件数据库或加锁。这里用文件库 + 每次请求新连接。
import tempfile
_DB_PATH = os.path.join(tempfile.gettempdir(), "yangweb_range.db")
if os.path.exists(_DB_PATH):
    os.remove(_DB_PATH)
DB = sqlite3.connect(_DB_PATH)
DB.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, secret TEXT)")
DB.execute("INSERT INTO users VALUES (1, 'admin', 'admin123', ?)", (FLAG,))
DB.execute("INSERT INTO users VALUES (2, 'guest', 'guest', 'not_the_flag')")
DB.commit()
DB.close()


def db_query(sql: str):
    """每次请求新建连接查询 (文件库, 多线程安全)"""
    conn = sqlite3.connect(_DB_PATH)
    try:
        cur = conn.execute(sql)
        return cur.fetchone()
    finally:
        conn.close()

TEMPLATE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{title} - Yang-Web 靶场</title>
<style>
body{{font-family:'Cascadia Code',Consolas,monospace;background:#1e1e2e;color:#cdd6f4;max-width:900px;margin:30px auto;padding:0 20px}}
h1{{color:#89b4fa}} h2{{color:#a6e3a1}} a{{color:#89b4fa}}
.card{{background:#313244;border-radius:10px;padding:16px;margin:14px 0;border-left:4px solid #89b4fa}}
.card.l1{{border-left-color:#f38ba8}} .card.l2{{border-left-color:#fab387}}
.card.l3{{border-left-color:#f9e2af}} .card.l4{{border-left-color:#a6e3a1}}
input,button{{background:#45475a;color:#cdd6f4;border:1px solid #585b70;border-radius:6px;padding:7px 10px;font-size:14px;margin:3px}}
button{{cursor:pointer;background:#89b4fa;color:#11111b;font-weight:bold}}
.flag{{background:#1d1d29;border:2px dashed #f9e2af;border-radius:8px;padding:10px;margin-top:10px;color:#f9e2af;font-size:16px}}
.warn{{color:#f38ba8}}
code{{background:#45475a;padding:2px 6px;border-radius:4px}}
</style></head><body>
<h1>🔐 Yang-Web 脚本库靶场</h1>
<p>4 个关卡 · 用 Yang-Web 脚本库的脚本依次解出 <code>Geesec{{...}}</code> flag</p>
{body}
<hr><p style="color:#6c7086">Yang-Web 靶场 · 仅本地测试 · 端口 {PORT}</p>
</body></html>"""


def page(title, body):
    return TEMPLATE.format(title=title, body=body, PORT=PORT)


def flag_div(flag):
    return f'<div class="flag">🏁 Flag: <b>{flag}</b></div>'


class Handler(BaseHTTPRequestHandler):
    server_version = "YangWeb-Range/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), fmt % args))

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        routes = {
            "/": self.home,
            "/level1": self.level1,
            "/level2": self.level2,
            "/level3": self.level3,
            "/level4": self.level4,
        }
        if path in routes:
            routes[path]()
        elif path.startswith("/level3/js"):
            self.level3_js()
        elif path == "/l1/check":
            self.l1_check()
        elif path == "/l2/check":
            self.l2_check()
        else:
            self.html("404 Not Found", 404)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/l1/check":
            self.l1_check()
        elif path == "/l2/check":
            self.l2_check()
        elif path in ("/l4/exec", "/level4"):
            self.l4_exec()
        else:
            self.html("404 Not Found", 404)

    # ── 首页 ──
    def home(self):
        self.html(page("首页", """
<div class="card l1"><h2>Level 1 · 时间盲注</h2>
<p>GET <code>/l1/check?username=xxx</code>, 参数 <code>username</code>, 拼进 SQL。<br>
条件为真时延时 2 秒 (SLEEP)。</p>
<p class="warn">提示: 脚本库 <b>time_sqli.py</b> — URL 填 <code>http://127.0.0.1:9999/l1/check</code>, QUERY 填注入表达式</p></div>
<div class="card l2"><h2>Level 2 · 布尔盲注</h2>
<p>GET <code>/l2/check?id=xxx</code>, 参数 <code>id</code>, 条件真返回 <code>OK</code> 假返回 <code>NO</code>。</p>
<p class="warn">提示: 脚本库 <b>bool_inject.py</b></p></div>
<div class="card l3"><h2>Level 3 · JS 硬编码 Flag</h2>
<p>页面 <code>/level3</code> 的 JS 里藏着 flag。</p>
<p class="warn">提示: 脚本库 <b>js_challenge_solver.py</b> — URL 填 <code>http://127.0.0.1:9999/level3</code></p></div>
<div class="card l4"><h2>Level 4 · 命令执行</h2>
<p>POST <code>/l4/exec</code>, 参数 <code>cmd</code> 直接进 <code>system()</code>。</p>
<p class="warn">提示: 自动攻击页填 URL <code>http://127.0.0.1:9999/level4</code></p></div>
<p style="margin-top:24px"><a href="/level1">→ 进入 Level 1</a></p>
"""))

    # ── Level 1: 时间盲注 ──
    def level1(self):
        self.html(page("Level 1 · 时间盲注", """
<div class="card l1"><h2>Level 1 · 时间盲注</h2>
<p>POST <code>/l1/check</code>, 参数 <code>username</code>。<br>
正常: <code>username=admin</code> → 立即返回。注入条件为真 → 延时 2s。</p>
<p>库: <code>users</code> 表, 找 <code>admin</code> 的 <code>secret</code> 字段。</p>
<p class="warn">提示: time_sqli.py 用法 — URL <code>http://127.0.0.1:9999/l1/check</code> QUERY <code>1' AND SLEEP(2)-- -</code></p>
<form method="GET" action="/l1/check"><input name="username" value="admin"><button>登录</button></form>
</div>"""))

    def _get_param(self, name: str) -> str:
        """手动解析 GET 参数: 不按 = 分割值 (盲注 payload 含 = 会被 parse_qs 破坏)"""
        qs = urllib.parse.urlparse(self.path).query
        for part in qs.split('&'):
            if part.startswith(name + '='):
                return urllib.parse.unquote_plus(part[len(name) + 1:])
        return ''

    def l1_check(self):
        username = self._get_param('username')
        # 模拟 MySQL SLEEP 时间盲注: 解析 IF(条件,SLEEP(n),0), 条件为真才延时
        import re as _re
        # 匹配 IF( ... ,SLEEP(n),0) 或 IF( ... ,SLEEP(n),1), n 支持小数 (2.0)
        m = _re.search(r"IF\s*\((.*?)\s*,\s*SLEEP\s*\(\s*(\d+(?:\.\d+)?)\s*\)\s*,\s*0\s*\)", username, _re.I | _re.S)
        if m:
            cond = m.group(1).strip()
            delay = min(float(m.group(2)), 5.0)
            # 把条件里的 SUBSTRING((SELECT..),p,1)='C' 转成 sqlite 可执行
            # SQLite 支持 SUBSTR, 把 SUBSTRING 替换为 SUBSTR
            cond_sql = cond.replace('SUBSTRING', 'SUBSTR')
            try:
                row = db_query("SELECT 1 WHERE " + cond_sql)
                if row:
                    time.sleep(delay)
            except Exception:
                pass
        # 登录检查: 只验证用户存在, 不泄露 secret (flag 只能靠盲注提取)
        try:
            row = db_query("SELECT 1 FROM users WHERE username='" + username + "'")
        except Exception:
            row = None
        if row:
            self.html("✅ 登录成功")
        else:
            self.html("❌ 用户不存在")

    def l1_check_get(self):
        self.html("请用 POST 提交 username 参数")

    # ── Level 2: 布尔盲注 ──
    def level2(self):
        self.html(page("Level 2 · 布尔盲注", """
<div class="card l2"><h2>Level 2 · 布尔盲注</h2>
<p>POST <code>/l2/check</code>, 参数 <code>id</code>。<br>
条件为真返回 <code>OK</code>, 假返回 <code>NO</code>。</p>
<p>库: <code>users</code> 表 id=1 的 <code>secret</code>。</p>
<p class="warn">提示: bool_inject.py — URL <code>http://127.0.0.1:9999/l2/check</code> QUERY <code>1 AND SUBSTR((SELECT secret FROM users WHERE id=1),1,1)='G'</code></p>
<form method="GET" action="/l2/check"><input name="id" value="1"><button>查询</button></form>
</div>"""))

    def l2_check(self):
        idv = self._get_param('id')
        # 模拟 MySQL 布尔盲注: 支持 ' OR IF(SUBSTR((query),p,1)='C',1,0)# 风格
        import re as _re
        m = _re.search(r"IF\s*\((.*?)\s*,\s*1\s*,\s*0\s*\)", idv, _re.I | _re.S)
        if m:
            cond = m.group(1).strip().replace('SUBSTR', 'SUBSTR')
            # 条件形如 SUBSTR((SELECT secret FROM users WHERE id=1),1,1)='G'
            try:
                row = db_query("SELECT 1 WHERE " + cond)
                self.html("OK" if row else "NO")
                return
            except Exception:
                pass
        # 常规: id 数字直接查
        try:
            row = db_query("SELECT secret FROM users WHERE id=" + idv)
        except Exception:
            row = None
        self.html("OK" if row else "NO")

    def l2_check_get(self):
        self.html("请用 POST 提交 id 参数")

    # ── Level 3: JS 硬编码 flag ──
    def level3(self):
        self.html(page("Level 3 · JS 硬编码 Flag", """
<div class="card l3"><h2>Level 3 · JS 硬编码 Flag</h2>
<p>本页 JS 中藏着一个 flag。查看源码或让求解器帮你找。</p>
<p class="warn">提示: js_challenge_solver.py — URL <code>http://127.0.0.1:9999/level3</code></p>
</div>
<script>
// 隐藏的凭证
var _creds = {
  "user": "level3",
  "token": "not_the_flag",
  "hint": "flag 在下面这个变量里"
};
// 真正的 flag 在这里 — 仔细找
var _hidden = "Geesec{web_range_4in1_flag_2026}";
console.log("loaded");
</script>
"""))

    def level3_js(self):
        # 提供 JS 文件 (求解器会抓取)
        js = """
var _creds = {"user":"level3","token":"not_the_flag"};
// secret stash
var _hidden = "Geesec{web_range_4in1_flag_2026}";
"""
        data = js.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'application/javascript; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # ── Level 4: 命令执行 ──
    def level4(self):
        self.html(page("Level 4 · 命令执行", """
<div class="card l4"><h2>Level 4 · 命令执行</h2>
<p>POST <code>/l4/exec</code>, 参数 <code>cmd</code> 直接进 <code>system()</code>。</p>
<p>flag 在服务器文件 <code>flag.txt</code> 中。页面下方展示了服务端源码。</p>
<p class="warn">提示: 自动攻击页填 URL <code>http://127.0.0.1:9999/level4</code> 点自动攻击; 或直接 <code>cmd=cat flag.txt</code></p>
<form method="POST" action="/l4/exec"><input name="cmd" value="cat flag.txt"><button>执行</button></form>
</div>
<pre style="background:#1d1d29;padding:12px;border-radius:8px;overflow:auto;font-size:12px">&lt;?php
// 靶场 Level 4 源码
system($_POST['cmd']);
highlight_file(__FILE__);
?&gt;</pre>
"""))

    def l4_exec(self):
        p = self._params()
        cmd = (p.get('cmd') or [''])[0]
        if not cmd:
            self.html("cmd 参数为空")
            return
        base_dir = os.path.dirname(os.path.abspath(__file__))
        # 确保 flag 文件存在 (同时写 flag.txt 和模拟 /flag)
        if not os.path.exists(os.path.join(base_dir, 'flag.txt')):
            with open(os.path.join(base_dir, 'flag.txt'), 'w') as f:
                f.write(FLAG)
        if not os.path.exists(os.path.join(base_dir, '_flag')):
            with open(os.path.join(base_dir, '_flag'), 'w') as f:
                f.write(FLAG)
        # 模拟 Linux 根路径: cat /flag → 读 flag.txt
        cmd_linux = cmd.replace('/flag', os.path.join(base_dir, 'flag.txt'))
        cmd_linux = cmd_linux.replace('/etc/passwd', os.path.join(base_dir, '_flag'))
        try:
            r = subprocess.run(cmd_linux, shell=True, capture_output=True, text=True, timeout=10,
                               cwd=base_dir)
            out = r.stdout + r.stderr
            self.html(f"<pre>{out}</pre>")
        except Exception as e:
            self.html(f"<pre>执行出错: {e}</pre>")

    # ── 辅助 ──
    def _params(self):
        length = int(self.headers.get('Content-Length', 0) or 0)
        body = self.rfile.read(length).decode('utf-8', 'replace')
        return urllib.parse.parse_qs(body)

    def _flag_or(self, secret):
        if 'Geesec' in secret or 'flag' in secret.lower():
            return f'<span class="flag">🏁 {secret}</span>'
        return secret

    def html(self, body, code=200):
        if not body.startswith("<!DOCTYPE"):
            body = page("结果", body)
        data = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    srv = ThreadingHTTPServer(('0.0.0.0', PORT), Handler)
    print(f"\n=== Yang-Web 靶场已启动: http://127.0.0.1:{PORT}/ ===")
    print("  L1 时间盲注: POST /l1/check  username  → time_sqli.py")
    print("  L2 布尔盲注: POST /l2/check  id        → bool_inject.py")
    print("  L3 JS硬编码: GET  /level3              → js_challenge_solver.py")
    print("  L4 命令执行: POST /l4/exec  cmd        → 自动攻击 simple_cmd_rce")
    print("  按 Ctrl+C 停止\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n靶场已停止")


if __name__ == '__main__':
    main()
