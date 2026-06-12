# Yang-Web 🛠️ v1.4.0

> **CTF 一站式工具箱** — 智能解码 + 23种密码/编码 + JWT攻击 + Payload库 + 靶场分析 + GUI图形界面

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-green.svg)]()
[![GUI](https://img.shields.io/badge/GUI-tkinter-purple.svg)]()
[![Ciphers](https://img.shields.io/badge/ciphers-23-orange.svg)]()
[![Scripts](https://img.shields.io/badge/scripts-41-red.svg)]()
[![Payloads](https://img.shields.io/badge/payloads-8_mods-blue.svg)]()

---

## 📖 简介

Yang-Web 是一把 **CTF 全方向的瑞士军刀**，覆盖编码解码、密码破解、Payload 生成、靶场分析到攻击利用。内置 **图形界面 (GUI)**，支持 CLI ↔ GUI 一键切换。完全离线，零第三方依赖。

**14 个子命令 + 智能解码器(14种编码) + 23种密码(Base全系+古典+键盘+中文) + 41个内嵌CTF脚本 + JWT攻击链 + 8大Payload模块 + 🆕靶场黑名单分析。**

---

## ✨ 核心优势

- 📴 **完全离线** — 零 pip 依赖，Python 标准库一把梭
- 🧠 **智能解码器** — 粘贴即用：自动识别14种编码 + 一键解码 + 暴力全试 + 链式递归
- 🔐 **23种密码** — Base全系 + 古典(凯撒/栅栏/猪圈/培根/Vigenère/ADFGX/摩斯) + 键盘映射 + 中文编码
- 📦 **41个内嵌脚本** — Crypto/Web/Misc/Reverse 全覆盖，一键运行
- 🎯 **靶场分析(`--analyze`)** — 🆕 粘贴黑名单，自动告诉你哪些后缀/绕过能用
- 🖥️ **图形界面** — GUI ↔ CLI 一键切换，密码面板即看即用
- 🎯 **8大Payload模块** — SSTI/SQLi/LFI/SSRF/XSS/RCE/PHP/Upload
- 🛡️ **WAF 绕过** — 30+ SQL WAF + 12类 PHP RCE 绕过
- 🔑 **JWT 攻击链** — 解析→None攻击→弱密钥爆破→伪造令牌

---

## 📦 安装

```bash
pip install yang-web

# 或 GitHub
git clone https://github.com/Yang-afk825/Yang-web.git
cd Yang-web
python -m yang_web
```

---

## 📋 子命令详解

### 1. 智能解码 `decode`

自动检测编码格式并链式解码。支持 **base64/32/16/58/85、URL、HTML实体、ROT13、二进制/八进制/十进制ASCII、Unicode转义、摩斯电码**。

```bash
$ yang-web decode "ZmxhZ3t0ZXN0fQ=="
→ flag{test}

$ yang-web decode --brute "dGVzdA=="      # 暴力全试
```

---

### 2. 编码 `encode`

明文 → 编码。

```bash
$ yang-web encode base64 "hello world"
$ yang-web encode url "admin' OR 1=1--"
```

---

### 3. SSTI 模板注入 `ssti`

8 种引擎（Jinja2/Twig/Smarty/Mako/ERB/FreeMarker/Velocity/Django）。

```bash
$ yang-web ssti --list                    # 列出引擎
$ yang-web ssti --exploit --engine Jinja2  # RCE Payload
$ yang-web ssti --bypass --engine Twig    # 过滤绕过
```

---

### 4. SQL 注入 `sqli`

MySQL/PostgreSQL/MSSQL/Oracle/SQLite + 30种WAF绕过 + 🆕认证绕过。

```bash
$ yang-web sqli --list
$ yang-web sqli --db MySQL                # 全部MySQL Payload
$ yang-web sqli --blind                   # 盲注模板
$ yang-web sqli --waf 空白符绕过           # WAF绕过
$ yang-web sqli --search "绕过登录"        # 🆕认证绕过Payload
```

---

### 5. LFI / 文件包含 `lfi`

```bash
$ yang-web lfi --traversal                # 路径遍历
$ yang-web lfi --linux / --windows        # 敏感文件
$ yang-web lfi --php                      # 伪协议
$ yang-web lfi --filter-chain             # PHP filter chain
```

---

### 6. SSRF `ssrf`

```bash
$ yang-web ssrf --cloud aws               # 云元数据
$ yang-web ssrf --internal                # 内网探测
$ yang-web ssrf --protocol                # 协议利用
$ yang-web ssrf --bypass                  # 绕过技巧
```

---

### 7. XSS `xss`

```bash
$ yang-web xss --detect
$ yang-web xss --steal cookie
$ yang-web xss --bypass
```

---

### 8. RCE `rce`

```bash
$ yang-web rce --inject                   # 命令注入Payload
$ yang-web rce --shell bash --ip 10.0.0.1 --port 4444
```

---

### 9. PHP 技巧 `php`

Magic Hash ×27 + 弱类型 ×14 + WAF绕过 ×12。

```bash
$ yang-web php --magic
$ yang-web php --waf-php
$ yang-web php --rce
```

---

### 10. 🆕 文件上传 `upload`

覆盖文件上传全攻击面 + 🆕靶场分析。

```bash
$ yang-web upload --ext                   # 后缀名绕过
$ yang-web upload --mime                  # Content-Type伪造
$ yang-web upload --content               # 图片马内容绕过
$ yang-web upload --parse apache          # 解析漏洞
$ yang-web upload --htaccess / --userini  # 配置文件利用
$ yang-web upload --advanced              # 高级技巧

# 🆕 靶场黑名单分析
$ yang-web upload --analyze "php,php3,php5,php7,phtml,shtml,cgi"
→ 🎯 靶场黑名单分析
  已拦截: cgi, php, php3, php5, php7, phtml, shtml
  ✅ 可用后缀: phar, php4, php8, phps, pht
    🎯 推荐 .pht — 最常见的绕过后缀
  🔤 大小写混合: Php ✅ / PHP ✅ / pHp5 ✅
  📦 双后缀: shell.php.jpg
  💾 NTFS 数据流: shell.php::$DATA
```

---

### 11. Hash 识别 `hashid`

40+ 种 Hash 算法识别。

```bash
$ yang-web hashid "e10adc3949ba59abbe56e057f20f883e"
🔍 MD5 / NTLM / MD4
```

---

### 12. JWT 攻击 `jwt`

```bash
$ yang-web jwt "eyJ..." --none           # None攻击
$ yang-web jwt "eyJ..." --brute          # 弱密钥爆破
$ yang-web jwt "eyJ..." --forge --secret "key" --claim '{"admin":true}'
```

---

### 13. 离线扫描 `scan`

```bash
$ yang-web scan dir --search flag
$ yang-web scan file --search backup
```

---

### 14. 内嵌脚本库 `scripts`

41 个 CTF 脚本（Crypto/Web/Misc/Reverse）。

```bash
$ yang-web scripts                       # 列出全部
$ yang-web scripts --category crypto     # 按分类
$ yang-web scripts --run rsa_toolkit     # 运行脚本
$ yang-web scripts --check-deps          # 依赖检查
```

---

## 🔗 实战工作流

### SQL 注入 → 登录绕过
```bash
# 1. 靶场返回 "用户名或密码错误"
# 2. Yang-Web 找认证绕过
$ yang-web sqli --db MySQL | grep "万能密码"
# 3. 用 admin' OR '1'='1 登录 ✅
```

### 文件上传 → 后缀绕过
```bash
# 1. 上传 shell.php → BLOCKED: .php not allowed
# 2. 分析黑名单
$ yang-web upload --analyze "php,php3,php5,php7,phtml,shtml,cgi"
# 3. 推荐 .pht → 上传成功 ✅
```

### 编码解码
```bash
$ yang-web decode "NTI2ZjYyNmY3NDIwNjU2MTczNzk="
# Step 1: base64 → Step 2: base16 → "Robot easy" ✅
```

---

## 🔐 GUI Misc Crypto 密码面板

**23 种** CTF 常见密码，支持一键 Encode/Decode。

| 分类 | 密码 |
|------|------|
| 基础编码 | Base64/32/16/58/85, URL, HTML, Unicode, 二进制/八进制/十进制 |
| 古典替换 | 凯撒、埃特巴什、ROT13、维吉尼亚、ADFGX |
| 棋盘/坐标 | 猪圈、培根、波利比奥斯、栅栏、键盘QWE/棋盘/坐标 |
| 中文/特殊 | 当铺、杰斐逊转轮、摩斯、二进制加密、倒序、字母表顺序、数字坐标 |
| 其他 | 标准银河字母、手机键盘、非斯象形文字、蓝孔打卡 |

### GUI 启动
```bash
yang-web gui
# 或双击桌面 Yang-Web 快捷方式
```

---

## 📂 项目结构

```
Yang-web/
├── pyproject.toml
├── README.md
├── yang_web/
│   ├── __init__.py / __main__.py
│   ├── cli.py                      # CLI (14子命令)
│   ├── gui.py                      # GUI (图形界面)
│   ├── core/                       # 核心引擎
│   │   ├── decoder.py              # 智能解码 (14种编码)
│   │   ├── misc_crypto.py          # 密码引擎 (23种)
│   │   ├── hashid.py / jwt.py     # Hash识别 / JWT攻击
│   ├── payloads/                   # 8大Payload模块
│   │   ├── sqli.py (🆕认证绕过)
│   │   ├── upload.py (🆕--analyze)
│   │   ├── ssti.py / lfi.py / ssrf.py
│   │   ├── xss.py / rce.py / php.py
│   ├── scripts/                    # 41个CTF脚本
│   └── wordlists/                  # 字典数据
```

---

## v1.4.0 更新

- 🆕 **Upload 靶场分析** — `--analyze` 粘贴黑名单，自动推荐绕过方案（CLI+GUI双支持）
- 🆕 **SQLi 认证绕过** — 8 条万能密码 Payload（`admin' OR '1'='1`等）
- 🔧 **GUI 分类修复** — 下拉框选中后正确加载数据
- 🔧 **GUI 列表展开** — 不再截断显示，全部 Payload 可见
- 🔧 **密码引擎补全** — Atbash/Caesar/ROT13/Rail Fence/Morse 等补全
- 🔧 **GUI 搜索优化** — 输入框支持回车触发搜索
- 🐛 **bugfix** — AES 解密轮密钥顺序修复、pyproject.toml 构建后端修复

---

## 📮 联系

3303257524@qq.com

## 📄 License

MIT — 详见 [LICENSE](LICENSE)
