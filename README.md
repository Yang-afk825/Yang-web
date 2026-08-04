# Yang-Web 🛠️ v4.0.0

> **CTF 一站式工具箱** — 智能解码 + 50+种密码/编码 + 12+智能攻击引擎 + JWT攻击 + 反弹Shell + 隐写分析 + Payload库 + 靶场分析 + GUI图形界面 + 独立桌面应用

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-green.svg)]()
[![GUI](https://img.shields.io/badge/GUI-pywebview-purple.svg)]()
[![Ciphers](https://img.shields.io/badge/ciphers-50+-orange.svg)]()
[![Scripts](https://img.shields.io/badge/scripts-51-red.svg)]()
[![Payloads](https://img.shields.io/badge/payloads-8_mods-blue.svg)]()
[![Engines](https://img.shields.io/badge/engines-12-brightgreen.svg)]()

---

## 📖 简介

Yang-Web 是一把 **CTF 全方向的瑞士军刀**，覆盖编码解码、密码破解、Payload 生成、靶场分析到攻击利用。内置 **图形界面 (GUI)**，支持 CLI ↔ GUI 一键切换，打包为 **独立 Windows 桌面应用 (exe)**。完全离线，零第三方依赖。

**14 个子命令 + 智能解码器(14种编码) + 12+智能攻击引擎(源码指纹→并发攻击→一键解题→实时攻击流) + 50+种密码/编码 + 纯Python密码引擎(AES/RC4/RSA) + 中文特色密码 + 反弹Shell/WebShell生成 + 隐写分析 + 51个内嵌CTF脚本 + JWT攻击链 + 8大Payload模块 + 靶场黑名单分析 + 内嵌浏览器 + 脚本库靶场。**

---

## 💡 项目初心

做 CTF 的人都知道一个痛点：**工具太多、太散、太贵。**

解码要去一个网站，SQL 注入要翻另一个脚本，JWT 破解还得现找 payload……赛场上时间就是分数，翻来翻去浪费的都是解题窗口。市面上的商业工具动辄几百上千，学生党扛不住。

所以我写了 Yang-Web。

**一个工具，搞定 CTF 全流程**——从拿到题目到读出 Flag，编码解码、漏洞分析、payload 生成、攻击利用一气呵成。

选择 **MIT 开源、零依赖、永久免费**，是因为我相信好的安全工具不该有门槛。不管你是刚入门的新手，还是打了好几年的老选手，打开终端就能用，不需要折腾环境、不需要掏钱。

如果你觉得这个工具有用，顺手点个 ⭐ Star，或者提个 PR 一起完善。让更多人知道：**好用的 CTF 工具，可以免费，也可以开源。**

---

## ✨ 核心优势

- 📴 **完全离线** — 零 pip 依赖，Python 标准库一把梭
- 🧠 **智能解码器** — 粘贴即用：自动识别14种编码 + 一键解码 + 暴力全试 + 链式递归
- 🔐 **50+种密码/编码** — Base全系 + 古典(凯撒/栅栏/猪圈/培根/Vigenère/ADFGX/摩斯) + 键盘映射 + 中文特色密码(与佛论禅/核心价值观/百家姓...) + 高级编码(Brainfuck/Ook!/JSFuck/AAencode...18种)
- 📦 **51个内嵌脚本** — Crypto/Web/Misc/Reverse 全覆盖，一键运行，支持 URL 输入 + 额外参数
- 🎯 **靶场分析(`--analyze`)** — 粘贴黑名单，自动告诉你哪些后缀/绕过能用
- 🧠 **12+ 智能攻击引擎** — 粘贴URL→自动分析→一键解题：源码指纹识别 + 并发攻击 + 自适应调度 + 自动读Flag + **SSE 实时攻击流**
- 🖥️ **独立桌面应用** — pywebview 打包 exe，双击即用，内嵌浏览器（带 Headers 编辑）
- 🎯 **8大Payload模块** — SSTI/SQLi/LFI/SSRF/XSS/RCE/PHP/Upload
- 🛡️ **WAF 绕过** — 30+ SQL WAF + 12类 PHP RCE 绕过
- 🔑 **JWT 攻击链** — 解析→None攻击→弱密钥爆破→伪造令牌
- 🔒 **纯Python密码引擎** — AES(ECB/CBC)/RC4/RSA/MD5/SHA全系/BLAKE2/CRC32/HMAC/XOR爆破/进制转换
- 🐚 **反弹Shell & 隐写** — 10种语言反弹Shell + 6种WebShell + PNG分析 + LSB提取 + EXIF读取 + 密文特征识别
- 🎮 **脚本库靶场** — 内置 4 关 Web 挑战（时间盲注/布尔盲注/JS硬编码/命令执行），可用脚本库脚本一键解出

---

## 📦 安装

```bash
# 源码运行
git clone https://github.com/Yang-afk825/Yang-web.git
cd Yang-web
python -m yang_web.server        # 启动 Web 服务 (默认 8765)

# 或直接使用打包好的桌面应用
dist/Yang-Web.exe                # 独立窗口, 无需 Python
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

MySQL/PostgreSQL/MSSQL/Oracle/SQLite + 30种WAF绕过 + 认证绕过。

```bash
$ yang-web sqli --list
$ yang-web sqli --db MySQL                # 全部MySQL Payload
$ yang-web sqli --blind                   # 盲注模板
$ yang-web sqli --waf 空白符绕过           # WAF绕过
$ yang-web sqli --search "绕过登录"        # 认证绕过Payload
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

```bash
$ yang-web php --weak                     # 弱类型比较
$ yang-web php --serialize                # 反序列化
$ yang-web php --md5-collision            # MD5碰撞
```

---

### 10. 文件上传 `upload`

```bash
$ yang-web upload --list                  # 全部上传Payload
$ yang-web upload --bypass                # 黑名单绕过
$ yang-web upload --analyze               # 🆕 靶场黑名单分析
```

---

### 11. Hash 识别 `hashid`

40+ Hash 算法自动识别。

```bash
$ yang-web hashid "5f4dcc3b5aa765d61d8327deb882cf99"
→ MD5 (92%)
```

---

### 12. JWT 攻击 `jwt`

```bash
$ yang-web jwt --parse <token>            # 解析
$ yang-web jwt --attack none <token>      # None攻击
$ yang-web jwt --crack <token>            # 弱密钥爆破 (37条)
$ yang-web jwt --forge <token> --secret k # 伪造
```

---

### 13. 离线扫描 `scan`

```bash
$ yang-web scan --url http://target       # 目录爆破 + 指纹
$ yang-web scan --sensitive               # 敏感文件检测
```

---

### 14. 内嵌脚本库 `scripts`

51 个 CTF 脚本，Web 界面一键运行，支持 URL 输入 + 额外参数。

```bash
$ yang-web scripts --list                 # 全部脚本
$ yang-web scripts --run time_sqli --url "http://x/?id={PAYLOAD}" --args "SELECT flag FROM t"
```

---

## 🔗 实战工作流

### SQL 注入 → 登录绕过

```bash
# 1. 靶场返回 "用户名或密码错误"
# 2. Yang-Web 找认证绕过
$ yang-web sqli --search "绕过登录"
# 3. 用 admin' OR '1'='1 登录 ✅
```

### 文件上传 → 后缀绕过

```bash
# 1. 上传 shell.php → BLOCKED: .php not allowed
# 2. 分析黑名单
$ yang-web upload --analyze
# 3. 推荐 .pht → 上传成功 ✅
```

### 编码解码

```bash
$ yang-web decode "Um9ib3QgZWFzeQ=="
# Step 1: base64 → Step 2: base16 → "Robot easy" ✅
```

### 自动攻击 → 一键出 Flag

```bash
# 粘贴 URL 到自动攻击页, 点击开始
# 源码指纹 → 引擎路由 → 并发攻击 → 实时 SSE 攻击流 → Flag
```

---

## 🔐 GUI Misc Crypto 密码面板

Web 界面内置完整密码学面板：

- **智能解码** — 14种编码链式/暴力解码
- **高级编码** — 18种 (Brainfuck/Ook!/JSFuck/AAencode...)
- **中文密码** — 与佛论禅/核心价值观/百家姓/古典密码知识库(34种+参考图)
- **密码学引擎** — AES/RC4/RSA/Hash/XOR/进制转换
- **Hash 识别** — 40+ 算法
- **JWT 面板** — 解析/攻击/爆破
- **Payload 面板** — 8大模块
- **Shell 面板** — 反弹Shell/WebShell 生成器
- **隐写面板** — PNG/LSB/EXIF/密文识别
- **脚本库** — 51脚本 + URL输入 + 额外参数 + 结果本页显示
- **自动攻击** — SSE 实时攻击流
- **内嵌浏览器** — Headers 编辑, CORS 代理

---

## 📂 项目结构

```
Yang-Web/
├── Yang-Web.spec          # PyInstaller 打包配置
├── launch.pyw             # 无窗口启动入口
├── yang_web/
│   ├── server.py          # FastAPI 后端 (:8765)
│   ├── web/               # Web UI (index.html)
│   ├── core/              # 核心引擎
│   │   ├── decoder.py         # 智能解码
│   │   ├── hashid.py          # Hash识别
│   │   ├── jwt.py             # JWT攻击
│   │   ├── misc_crypto.py     # 古典密码
│   │   ├── crypto_engine.py   # AES/RC4/RSA
│   │   ├── advanced_engines.py # 18种高级编码
│   │   ├── chinese_ciphers.py  # 中文特色密码
│   │   ├── url_analyzer.py     # 自动攻击调度
│   │   ├── simple_cmd_rce.py   # 简单命令注入探测
│   │   ├── bashfuck_solver.py  # 无字母RCE
│   │   ├── ssrf_rebind.py      # SSRF DNS Rebinding
│   │   ├── php_lfi.py          # PHP文件包含
│   │   ├── php_eval_rce.py     # PHP eval RCE
│   │   ├── multi_stage.py      # 多阶段攻击
│   │   ├── smart_solver.py     # 智能一键解题
│   │   └── ...                 # 12+ 引擎
│   ├── scripts/           # 51个CTF脚本
│   └── wordlists/         # 词库 + 古典密码参考图
├── 靶场.py                # 内置4关Web靶场 (9999)
└── dist/Yang-Web.exe      # 独立桌面应用
```

---

## 🆕 v4.0.0 更新 (2026-08-04)

> 本次聚焦「桌面化 + 自动化」— 从 Web 工具走向独立应用 + 脚本库靶场闭环。

- 🖥️ **独立桌面应用** — pywebview + WebView2 打包 exe（24MB），双击即用，无需 Python 环境
- 🌐 **内嵌浏览器** — 工具箱内置浏览器，支持 Headers 编辑 + CORS 服务端代理
- ⚡ **SSE 实时攻击流** — 自动攻击页实时推送 `{stage,item,status}` 攻击进度
- 🎮 **脚本库靶场** — 内置 4 关 Web 靶场（时间盲注/布尔盲注/JS硬编码/命令执行），脚本库脚本一键解出 Flag
- 🎯 **简单命令注入引擎 (simple_cmd_rce)** — 针对 `system($_POST['x'])` 无 WAF 靶场，源码解析 + 参数提取 + 直连探测，秒出 Flag
- 📥 **脚本库 URL 输入** — 目标 URL + 额外参数输入框，整行参数传入，结果本页显示
- 🐛 **大量修复** — exe 窗口模式崩溃(uvicorn log)、JS await 语法、脚本库表格空白、Python2 脚本迁移、GBK 编码崩溃等

## v3.6.0 更新 (2026-07-15)

> 本次聚焦「自动化解题引擎」全面扩容 — 从单点 Payload 走向多阶段自动攻击链，新增 11 个核心解题引擎，内嵌脚本库 41 → 51。

- 🔗 **多阶段攻击引擎（multi_stage.py）** — 通用多阶段解题框架：阶段检测 → 攻击 → 响应分析 → 跳转追踪 → 下一阶段，自动串联攻击链直至读出 Flag
- 🔍 **高级扫描引擎（advanced_scanner.py）** — 字典目录/文件爆破 + Response Diffing 精准检测 + 自动攻击链 + HTTP 方法自适应
- 🧠 **智能一键解题引擎（smart_solver.py）** — 问题分类器 + 策略路由 + 多引擎自动编排
- 🐘 **PHP 反序列化求解器（php_unserialize.py）** — 基础验证 / `__wakeup` 绕过（CVE-2016-7124）/ 弱类型 == 绕过
- 📂 **PHP 文件包含求解器（php_lfi.py）** — include/require + 协议约束识别 + flag 文件自动发现
- 💥 **PHP eval RCE 求解器（php_eval_rce.py）** — MD5 碰撞检测 + eval() 代码执行 + WAF 关键字黑名单绕过
- 🐚 **bashFuck 无字母 RCE（bashfuck.py + bashfuck_solver.py）** — 过滤字母数字后 `$((2#…))` 二进制 + ANSI-C `$'\ooo'` 构造命令
- 🌐 **SSRF DNS Rebinding→RCE（ssrf_rebind.py）** — Flask/Django url 参数 + DNS 解析检测 + 黑名单绕过（nip.io/sslip.io/十进制/八进制）
- 🗃️ **SQLi-LABS 专项求解器（sqli_labs_solver.py）** — Less-1~75 完整映射 + 自动探测闭合方式/列数/注入类型
- 🎮 **JS/客户端挑战求解器（js_challenge_solver.py）** — 游戏类挑战胜利条件提取 + 硬编码 flag 扫描
- 🏋️ **RSA 综合求解器（rsa_toolkit.py）** — 已知 p/q/e/d 解密 + 低指数攻击 + 模数分解（Fermat/Yafu 联动）
- 📊 **50+ 脚本库元数据** — 41 → 51 脚本，分类/描述/依赖全标注，Web 界面可视化浏览 + 一键运行

## v3.0.0 更新 (2026-06-25)

- 🔐 **纯Python密码引擎** — AES(ECB/CBC, FIPS-197验证) / RC4 / RSA / MD5 / SHA / BLAKE2 / CRC32 / HMAC / XOR爆破
- 🆕 **中文特色密码** — 与佛论禅/核心价值观/百家姓/社会主义核心价值观编码
- 🆕 **高级编码引擎** — Brainfuck/Ook!/JSFuck/AAencode/颜文字/Quoted-Printable 等 18 种
- 🖥️ **GUI v2.0** — Catppuccin 暗色主题, 11 个面板
- 🆕 **靶场黑名单分析** — 上传过滤规则 → 自动推荐可用后缀/绕过

## v2.0.0 更新 (2026-06-16)

- 🖥️ **GUI 图形界面** — tkinter 暗色主题，密码面板即看即用
- 🧠 **智能解码器** — 14 种编码自动识别 + 链式递归解码
- 🎯 **JWT 攻击链** — 解析/None攻击/37条弱密钥爆破
- 📦 **脚本注册表** — 41 个 CTF 脚本分类管理

## v1.4.0 更新

- 📦 **脚本库** — 20+ 内嵌 CTF 脚本
- 🎯 **Payload 生成器** — 初版 8 大模块

---

## 📚 CTF 知识文档

项目附带完整 CTF 知识库（skill 文档），覆盖：

- **Web** — 源码泄露11种路径 / PHP伪协议 / SQL注入大全 / 反序列化 / SSTI / SSRF / JWT
- **Reverse** — IDA Pro 速查 / 脱壳 / 符号执行 / APK逆向
- **Pwn** — 保护机制 / 栈溢出 / 格式化字符串 / 堆利用
- **Crypto** — RSA 10+攻击 / ECC / 格密码 / 古典密码分类表
- **Forensics** — 图片/音频隐写 / 内存取证 / 文件头Magic表
- **Misc** — Python沙箱逃逸 / 多层编码 / 蓝牙RFID

---

## 📮 联系

- GitHub: [Yang-afk825/Yang-web](https://github.com/Yang-afk825/Yang-web)
- 邮箱: 3303257524@qq.com

---

## 📄 License

MIT License © 2026 Yang-afk825
