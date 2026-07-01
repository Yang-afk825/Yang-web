# 🏴 CTF 解题指南 · 全分类深度参考

> Yang-Web 配套知识库 — 覆盖 Web / Crypto / Reverse / Pwn / Forensics / Misc / OSINT / Malware / AI-ML 九大方向

---

## 📚 文档导航

| 文档 | 方向 | 行数 | 核心内容 |
|------|------|------|---------|
| [ctf-web.md](ctf-web.md) | 🔵 Web | 725 | 源码泄露11法、PHP伪协议全系、文件包含6大技巧、SQL注入全类型、SSTI速查表、SSRF绕Firewalling、反序列化gadget链、JWT攻击、Node.js原型链污染、GraphQL |
| [ctf-crypto.md](ctf-crypto.md) | 🟡 Crypto | 487 | RSA攻击13种(小e/Wiener/共模/格)、ECC攻击4种、Lattice/LLL速成、AES模式攻防(ECB/CBC/CTR/GCM)、哈希长度扩展、古典密码全表、编码识别 |
| [ctf-reverse.md](ctf-reverse.md) | 🔴 Reverse | 524 | IDA快捷键大全、脱壳4法、angr/Z3符号执行、加密常量速查、APK逆向(Frida/jadx)、Go/Rust逆向要点、反调试全解 |
| [ctf-forensics.md](ctf-forensics.md) | 🟠 Forensics | 687 | LSB/调色板/DCT隐写、频谱图分析、Wireshark过滤/提取、Volatility内存取证、浏览器取证、NTFS ADS、文件头速查表 |
| [ctf-misc.md](ctf-misc.md) | 🟢 Misc | 563 | Python沙箱逃逸(8种绕过)、多层编码解题、条件竞争、蓝牙/RFID/SDR、零宽字符、Unicode同形异码 |
| [ctf-pwn.md](ctf-pwn.md) | 🟣 Pwn | 420 | 保护机制速查、栈溢出3模式、ret2libc模板、格式化字符串、堆利用(UAF/Double Free)、seccomp ORW、one_gadget |
| [ctf-osint.md](ctf-osint.md) | ⚫ OSINT | 523 | 地理位置反查、Google Dorks大全、图片反查4引擎、Maltego/SpiderFoot、VirusTotal情报、Tor/.onion |
| [ctf-malware.md](ctf-malware.md) | 🔴 Malware | 541 | LOLBAS全表、无文件恶意软件、Cobalt Strike配置提取、BITSAdmin持久化、DLL劫持自动化 |
| [ctf-aiml.md](ctf-aiml.md) | 🤖 AI/ML | 480 | 模型逆向、对抗样本、LangChain/GGUF安全、模型配置隐写、神经网络可解释性攻击 |
| [SKILL.md](SKILL.md) | 📋 入口 | 151 | 题目分类路由、快速启动命令、解题流程、工具安装清单、AWD速查 |

---

## 🚀 快速开始

**拿到题目 → 三步走：**

```
1. file / strings  ← 确认类型，搜 flag 字符串
2. 查上表 → 对应文档
3. 先试文档开头的「Quick Wins」
```

---

## 🎯 邪修速查

👉 最常用的一招鲜技巧都收在 **[CTF-CheatSheet.md](CTF-CheatSheet.md)**

---

## 🔗 与 Yang-Web 工具的配合

| 场景 | 查阅文档 | 使用工具 |
|------|---------|---------|
| 编码解不开 | ctf-crypto.md → 编码识别 | `yang-web decode --brute` |
| SQL注入 | ctf-web.md → SQL注入 | `yang-web sqli --db MySQL` |
| JWT攻击 | ctf-web.md → JWT | `yang-web jwt --none --brute` |
| 上传后缀 | ctf-web.md → 文件上传 | `yang-web upload --analyze` |
| 古典密码 | ctf-crypto.md → 古典密码 | `yang-web misc-crypto` |
| SSTI | ctf-web.md → SSTI | `yang-web ssti --exploit` |
| SSRF | ctf-web.md → SSRF | `yang-web ssrf --protocol` |
| LFI | ctf-web.md → 文件包含 | `yang-web lfi --php` |

---

## ⚠️ 免责声明

本文档仅供 CTF 竞赛及安全研究学习使用。禁止用于未授权测试。

---

*最后更新: 2026-07-01 · Yang-Web v3.0*
