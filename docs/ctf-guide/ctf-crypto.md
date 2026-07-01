# Crypto — 密码学深度参考

## Quick Wins（先试这些）

```bash
# 识别编码类型
echo 'ciphertext' | base64 -d 2>/dev/null && echo "base64"
echo 'ciphertext' | base32 -d 2>/dev/null && echo "base32"
echo 'ciphertext' | xxd -r -p 2>/dev/null && echo "hex"
# 批量尝试
python3 -c "
import base64
c = '...'
for f in [base64.b16decode, base64.b32decode, base64.b64decode, base64.b85decode]:
    try: print(f(c))
    except: pass
"

# RSA 基本信息提取
openssl rsa -pubin -in key.pub -text -noout   # 查看 RSA 公钥参数
openssl rsa -in private.pem -check             # 检查私钥
python3 -c "from Crypto.PublicKey import RSA; k=RSA.importKey(open('key.pub').read()); print(k.n, k.e)"

# 在线识别工具
# https://www.dcode.fr/cipher-identifier  （古典密码识别）
# https://gchq.github.io/CyberChef/        （万能编解码）
```

## 古典密码分类

### 替换密码
| 类型 | 特征 | 破解方法 |
|------|------|---------|
| 凯撒密码 | 字母移位，3位最经典 | 尝试所有25种偏移 |
| Atbash | A↔Z, B↔Y | 对称替换 / `str.translate` |
| 单表替换 | 任意字母映射表 | 频率分析（英文中E最常用） |
| 维吉尼亚 Vigenère | 关键词+多表替换 | Kasiski检验法确定密钥长度 → 频率分析 |
| 栅栏 Rail Fence | Z字形排列 | 尝试不同行数 |
| 培根 Bacon | 5位二进制表示字母 | 两种字体区分A/B |
| 键盘密码 | 键盘布局偏移 | 看键盘映射关系 |

### 常用 Python 工具
```python
# 凯撒爆破
import string
def caesar_brute(cipher):
    for shift in range(26):
        plain = ''.join(chr((ord(c)-65+shift)%26+65) if c.isupper() 
                       else chr((ord(c)-97+shift)%26+97) if c.islower() 
                       else c for c in cipher)
        print(f"[{shift}] {plain}")

# 词频分析
from collections import Counter
freq = Counter(ciphertext.lower())
print(freq.most_common(10))  # e,t,a,o,i,n,s,h,r,d 应为最常见
```

## 现代对称加密

### AES (常见CTF考点)
- 分组长度128位，密钥128/192/256位
- 工作模式:
  - **ECB**: 相同明文块 → 相同密文块（不安全，[像素攻击](https://www.anquanke.com/post/id/103706)）
  - **CBC**: 前一块密文与当前明文 XOR → 加密（IV随机）→ 需要IV
  - **CTR**: 计数器模式，可并行，本质是流密码
  - **GCM**: CTR + GMAC认证标签
- CTF 考点:
  - ECB字节反转攻击
  - CBC padding oracle 攻击
  - CBC IV 可控 → 选择密文攻击
  - **CTR/GCM Nonce重用 → 毁灭性！** (高频考点)
  - 密钥/IV硬编码 → 直接解密

### CTR/GCM Nonce 重用攻击 ★★★
```python
# 核心原理: CTR模式本质是 AES(Key, Nonce||Counter) ⊕ Plaintext
# Nonce+Counter相同时，密钥流相同 → 两条密文异或 = 两条明文异或!

# 攻击: 已知 C1, C2 (同Nonce), 已知P1部分 → 恢复P2
C1 = bytes.fromhex('...')
C2 = bytes.fromhex('...')

# P1 ⊕ P2 = C1 ⊕ C2
xor_result = bytes(a ^ b for a, b in zip(C1, C2))

# 假设我们知道P1中某段是 'flag{' → 恢复P2对应位置
known = b'Dear Bob, the flag is '
xor_result[:len(known)]  # 现在 = known ⊕ P2[:len(known)]

# GCM更危险: nonce重用直接泄露认证密钥H!
# H = AES(Key, 0^128)
# 两条不同长度的密文 → 多项式恢复H → 可伪造任意密文的认证标签
# 工具: https://github.com/nonce-disrespect/nonce-disrespect
```

```python
from Crypto.Cipher import AES
# ECB 模式
cipher = AES.new(key, AES.MODE_ECB)
plain = cipher.decrypt(ciphertext)
```

### RC4 (流密码)
- 密钥调度(KSA) + 伪随机数生成(PRGA)
- 常见 CTF 题: XOR 加密（RC4就是XOR流，已知部分明文可恢复密钥流）

```python
def rc4(data, key):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)
```

## RSA 攻击大全

### 基础参数提取
```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import *
key = RSA.importKey(open('pubkey.pem').read())
n, e = key.n, key.e
print(f"n={n}\nn bits={n.bit_length()}\ne={e}")
```

### 攻击类型速查表
| 攻击 | 适用条件 | 工具 | 核心思路 |
|------|---------|------|---------|
| 小e攻击 | e=3，明文小 | `gmpy2.iroot(c, 3)` | 直接开方或 `c + k*n`开方 |
| 广播攻击 | 同一e加密同一m给>=e人 | CRT + 开方 | 中国剩余定理 |
| 共模攻击 | 同n不同e，e互质 | 扩展欧几里得 | GCD(e1,c1) + GCD(e2,c2) |
| 维纳攻击 Wiener | d < n^0.25 | `RSAwienerHacker.py` | 连分数逼近 |
| Boneh-Durfee | d < n^0.292 | SageMath | 格攻击(LLL) |
| 低位攻击 | d低位泄露 | SageMath Coppersmith | 格 + 部分已知d |
| 已知高位攻击 | p高位已知 | SageMath | Coppersmith 求解f(x) |
| p-1光滑 Pollard | p-1光滑 | `Pollard_pm1` | p-1分解 |
| Fermat分解 | p,q相近 | `fermat_factor` | p-q ≈ 2√n |
| 私钥泄露 | 已知d | 直接解密 | — |
| 铜匠 Coppersmith | 已知部分p | Sage `small_roots` | 由部分信息恢复全部 |

### 通用 SageMath 求解模板
```python
# 小e攻击
from gmpy2 import iroot
m = int(iroot(c, e)[0])
print(bytes.fromhex(hex(m)[2:]))

# 共模攻击
def egcd(a, b):
    if b == 0: return a, 1, 0
    g, x1, y1 = egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

_, s1, s2 = egcd(e1, e2)
m = (pow(c1, s1, n) * pow(c2, s2, n)) % n
print(bytes.fromhex(hex(m)[2:]))

# 维纳攻击（使用 owiener / RSAwienerHacker）
import owiener
d = owiener.attack(e, n)
m = pow(c, d, n)
print(bytes.fromhex(hex(m)[2:]))

# Coppersmith 已知高位p
# p_high 已知部分位，补0到完整长度
# PR.<x> = PolynomialRing(Zmod(n))
# f = p_high + x
# f.small_roots(X=2^(bits), beta=0.4)
```

## 椭圆曲线 ECC

### 核心概念
- 密钥: 私钥d（随机数），公钥Q = dG
- 加密: ECDH 密钥交换, ECIES 混合加密
- 签名: ECDSA (r, s)

### 攻击方法
| 攻击 | 条件 | 方法 |
|------|------|------|
| Pohlig-Hellman | 群的阶是光滑数 | 分解阶为小素数 → CRT |
| Smart攻击 | 奇异曲线 | SSAS攻击 → 提升到Qp |
| 无效曲线攻击 | 点验证不严 | 发送小阶点 |
| 重复随机数 | 两个签名用相同k | 差分恢复私钥 |
| 伪造签名 | k已知 | 直接算d |

```python
# 使用 SageMath 解离散对数（小阶）
from sage.all import *
E = EllipticCurve(GF(p), [a, b])
G = E(gx, gy)
Q = E(qx, qy)  # 公钥
# Pohlig-Hellman: 阶分解后离散对数
d = discrete_log(Q, G, ord=G.order(), operation='+')
```

## 格密码 / Lattice

### 核心概念
- **格 (Lattice)**: 一组基向量 `{b1, ..., bn}` 的整数线性组合
- **SVP**: 找格中最短非零向量
- **CVP**: 找离目标最近的格向量
- **LLL算法**: 格基约化，找近似最短基

### CTF 应用场景
| 场景 | 构造方法 |
|------|---------|
| 背包密码 (Knapsack) | 格子包含公钥向量，LLL恢复明文 |
| 隐藏数问题 (HNP) | 知道部分比特 + 签名，恢复秘密 |
| 低指数RSA | Boneh-Durfee 用格解方程 |
| 近似GCD | 多密文近似共享p，格恢复p |
| 线性同余 (LCG) | 递推参数未知，格恢复 |

### 背包破解模板
```python
# Merkle-Hellman 背包 - LLL破解
# 构造 K = 对角线矩阵
# M = [[I, 0], [pubKey, C]]
# LLL约化后找最短行
from sage.all import *
n = len(pubKey)
M = matrix(ZZ, n+1, n+1)
for i in range(n):
    M[i,i] = 1
    M[i,n] = pubKey[i]
M[n,n] = C
L = M.LLL()
# 寻找0/1模式的行 → 恢复明文
```

## 哈希函数

### 常见哈希长度
| 算法 | 输出长度 | 安全状态 |
|------|---------|---------|
| MD4 | 128位 | ❌ 已碰撞 |
| MD5 | 128位 | ❌ 已碰撞（2004王小云） |
| SHA-1 | 160位 | ❌ 已碰撞（2017Google） |
| SHA-256 | 256位 | ✅ 安全 |
| SHA-512 | 512位 | ✅ 安全 |

### 攻击类型
- **长度扩展攻击**: MD5/SHA-1/SHA-2 都有此缺陷
  - 已知 H(M)，不知 M，可计算 H(M || padding || append)
  - 防御: 用 `H(K || M)` 替代 `H(M)`（但更好用HMAC）
  - Python: `hashpumpy` 库实现

```python
# 长度扩展攻击
import hashpumpy
# original_hash = md5(secret + message)
new_hash, new_message = hashpumpy.hashpumpy(
    original_hash, original_message, append_data, 
    min(10, 20), key_len_guess)
```

### 哈希碰撞 CTF 技巧
- PHP: `md5('240610708') == md5('QNKCDZO')` → 0e开头 → PHP弱类型相等
- Python: MD5/SHA-1数字碰撞绕过
- 快速哈希爆破: `hashcat -m 0 hash.txt wordlist.txt`

## 编码识别速查表
| 特征 | 编码 |
|------|------|
| 只含0-9,A-F，长度偶数 | Hex/Base16 |
| A-Z, 2-7, =填充 | Base32 |
| A-Za-z0-9+/ = | Base64 |
| A-Za-z0-9 无填充 | Base62 |
| A-Za-z0-9+./%~ | Base85 |
| 含 %XX | URL编码 |
| 含 &#NN; 或 &xxx; | HTML实体 |
| 含 U+XXXX 或 \uXXXX | Unicode |

---

## 新增: 密码学综合进阶

### 生日攻击 (Birthday Attack)
```python
# 找哈希碰撞：给定 H1 和 H2，需要 H1(x) == H2(y)
# 期望尝试次数 = 2^(n/2)，n为哈希位长
# 128位MD5 → 约2^64次

# 概率: 在k个值中，至少一次碰撞的概率
# P ≈ 1 - exp(-k²/(2N))
import math

def collision_prob(k, n):
    """k个样本，n位哈希的碰撞概率"""
    N = 2 ** n
    return 1 - math.exp(-k * (k-1) / (2 * N))

print(f"2^64 samples, 128-bit hash: P={collision_prob(2**64, 128):.6f}")
```

### Merkle-Damgård 结构详解
```python
# MD5/SHA-1/SHA-2 都是 Merkle-Damgård 结构
# 特点：迭代压缩，每块处理完后状态更新
# 这导致了长度扩展攻击的可行性

# CTF 中可能遇见：伪造认证token
# token = secret + message 的 MD5/SHA-1/SHA-256
# 可扩展为 secret + message + padding + append 的新token
```

### 分组密码工作模式补全
```python
# ECB: 最不安全，16字节块独立加密
#   识别特征: 相同明文块 → 相同密文块
#   攻击: 字节反转、块重排、已知明文对接

# CBC: 前一块密文 XOR 明文再加密
#   攻击1: Bit Flipping — 修改前一块的密文影响后一块明文
#   攻击2: Padding Oracle — 利用解密padding校验的反馈逐个字节恢复明文
#   攻击3: IV可控 — 可改变解密结果

# CTR: 计数器加密后 XOR 明文（流模式）
#   攻击1: 重用nonce → 密钥流相同 → 两个密文XOR去掉密钥
#   攻击2: 已知明文 → 恢复密钥流 → 解密/伪造任何密文

# GCM: 认证加密 (CTR + GMAC)
#   攻击1: nonce重用 → 认证密钥可恢复 → 伪造任意密文
#   攻击2: 短tag（如4字节）→ 爆破tag
```

### CBC Bit-Flipping 攻击模板
```python
# 场景: 修改cookie/IV中的某些位，改变解密后的明文
# 例如: 将 "user=guest" 改为 "user=admin"

def cbc_bit_flip(ciphertext, original_text, target_text, block_size=16):
    """
    ciphertext: 完整的密文（IV + 数据块）
    original_text: 已知的明文段（在第N块）
    target_text: 想要改成的明文
    """
    iv = ciphertext[:block_size]
    blocks = []
    for i in range(block_size, len(ciphertext), block_size):
        blocks.append(ciphertext[i:i+block_size])
    
    # 假设 original_text 在第一块中
    # 需要修改 IV 中相应位置
    new_iv = bytearray(iv)
    for i in range(len(original_text)):
        # IV 被 XOR 到第一块解密结果上
        # P[i] = Dec(C[i]) ^ IV[i]
        # 要改成 P'[i]，需要 IV'[i] = IV[i] ^ P[i] ^ P'[i]
        new_iv[i] ^= ord(original_text[i]) ^ ord(target_text[i])
    
    return bytes(new_iv) + ciphertext[block_size:]
```

### Padding Oracle 攻击
```python
# 原理: CBC解密时，如果padding不合法，服务器返回错误
# 利用这个oracle可以逐字节恢复出明文

def padding_oracle_attack(encrypt_func, oracle_func, block_size=16):
    """
    encrypt_func(data): 返回 IV + ciphertext
    oracle_func(ciphertext): 如果padding合法返回True，否则False
    """
    def decrypt_block(block, prev_block):
        """使用oracle解密一个密文块"""
        # 中间值 I = Dec(block)
        # 明文 P = I ^ prev_block
        
        fake_prev = bytearray(block_size)
        decrypted = bytearray(block_size)
        
        # 从最后一个字节开始逐字节恢复
        for byte_pos in range(block_size - 1, -1, -1):
            pad_val = block_size - byte_pos
            # 设置已知位置为pad_val
            for k in range(byte_pos + 1, block_size):
                fake_prev[k] = pad_val ^ decrypted[k]
            
            # 爆破当前字节
            for guess in range(256):
                fake_prev[byte_pos] = guess
                if oracle_func(bytes(fake_prev) + block):
                    decrypted[byte_pos] = guess ^ pad_val
                    break
        
        # 最终明文 = decrypted ^ prev_block
        plain = bytes(d ^ p for d, p in zip(decrypted, prev_block))
        # 去掉padding
        pad = plain[-1]
        return plain[:-pad]
```

---

### 流密码重修
```python
# ⚠️ 流密码关键是: 永不重用密钥流(key stream)!

# 场景1: Two-Time Pad（同一key XOR两个密文）
# c1 = m1 XOR ks
# c2 = m2 XOR ks
# c1 XOR c2 = m1 XOR m2 → 可恢复部分明文

def two_time_pad(c1, c2):
    """两个密文用相同密钥流"""
    xor_result = bytes(a ^ b for a, b in zip(c1, c2))
    # 结果是一个XOR后的明文对
    # 用字母频率或空格假设来恢复
    # 如果某个位置的字符XOR后是小写字母 → 该位置可能是空格
    result = bytearray(xor_result)
    for i in range(len(result)):
        c = result[i]
        # 如果某个位置是字母 → 可能是 space ^ letter
        if chr(c).isalpha():
            # 假设c2[i]是空格
            result[i] = ord(' ')
    return bytes(result)

# 场景2: LCG（线性同余生成器）伪随机
# X_{n+1} = (a * X_n + c) mod m
# 如果有足够输出 → 可通过格恢复参数

def lcg_break(outputs):
    """已知LCG输出序列，恢复参数"""
    if len(outputs) < 3:
        return None
    # 假设 m 已知（很多CTF中 m=2^32）
    # 或 m 可推算：相邻差值的GCD
    diffs = [outputs[i+1] - outputs[i] for i in range(len(outputs)-1)]
    # m = GCD of (d[i+1]*d[i-1] - d[i]^2)
    from math import gcd
    m = 0
    for i in range(1, len(diffs)-1):
        m = gcd(m, diffs[i+1]*diffs[i-1] - diffs[i]**2)
    # 恢复 a, c
    a = (diffs[1] * pow(diffs[0], -1, m)) % m
    c = (outputs[1] - a * outputs[0]) % m
    return m, a, c
```

---

### MT19937 (梅森旋转) 预测
```python
# Python random 模块使用 MT19937
# 624个连续32位输出 → 可恢复完整状态

def untwist(state):
    """从624个输出反向恢复内部状态"""
    # MT19937 的 temper 函数:
    # y ^= (y >> 11)
    # y ^= (y << 7) & 0x9D2C5680
    # y ^= (y << 15) & 0xEFC60000
    # y ^= (y >> 18)
    
    def undo_right_shift_xor(y, shift):
        """逆向右移异或"""
        result = y
        for i in range(32 // shift):
            result ^= (result >> shift) << (shift * (i+1))
            result &= 0xFFFFFFFF
        return result
    
    def undo_left_shift_xor_and(y, shift, mask):
        """逆向左移异或并掩码"""
        result = y
        for i in range(32 // shift):
            shifted = (result << shift) & mask
            result ^= shifted
            result &= 0xFFFFFFFF
        return result
    
    state_restored = []
    for y in state:
        y = undo_right_shift_xor(y, 18)
        y = undo_left_shift_xor_and(y, 15, 0xEFC60000)
        y = undo_left_shift_xor_and(y, 7, 0x9D2C5680)
        y = undo_right_shift_xor(y, 11)
        state_restored.append(y)
    return state_restored

# 使用例:
# import random
# outputs = [random.getrandbits(32) for _ in range(624)]
# mt_state = untwist(outputs)
# # mt_state 即为 MT 内部状态，可复制到另一个 random.Random()
```

---

### AES-ECB 字节反转 (字节对接攻击)
```python
# 原理: ECB的16字节分块独立加密
# 场景: 加密格式为: prefix + user_input + secret_suffix
# 通过操纵输入长度，逐字节尝试匹配块

def ecb_byte_at_a_time(oracle_func, block_size=16):
    """逐字节恢复被加密的 suffix"""
    known = b''
    
    # 第一步: 确认 block_size
    # 填充逐渐增加直到长度跳变一个block
    
    for block_num in range(1, 20):
        # 构造 input = 15 - len(known) % 16 字节的填充
        pad_len = (block_size * block_num - len(known)) - 1
        if pad_len < 0:
            pad_len += block_size
        
        prefix = b'A' * pad_len
        baseline = oracle_func(prefix)
        
        for guess in range(256):
            test_input = prefix + known + bytes([guess])
            test_ct = oracle_func(test_input)
            
            if test_ct[:block_size * block_num] == baseline[:block_size * block_num]:
                known += bytes([guess])
                break
        
        if known.endswith(b'}'):
            break
    
    return known.decode()
```

---

## 新增: SMT/SAT 求解器在密码学中的应用

### Z3 解非线性方程组
```python
from z3 import *

# 场景: 自定义加密函数，逆向解析后得到约束
# 例: output[i] = (flag[i] * 7 + 13) % 256 == expected[i]

flag = [BitVec(f'f{i}', 8) for i in range(32)]
s = Solver()

for i in range(32):
    # 将约束转为位向量运算
    s.add((flag[i] * 7 + 13) & 0xFF == expected[i])

# 添加可打印约束
for c in flag:
    s.add(c >= 0x20, c <= 0x7e)
# flag必须以 ISCC{ 开头
s.add(flag[0] == ord('I'))
s.add(flag[1] == ord('S'))
s.add(flag[2] == ord('C'))
s.add(flag[3] == ord('C'))
s.add(flag[4] == ord('{'))

if s.check() == sat:
    m = s.model()
    result = ''.join(chr(m[f].as_long()) for f in flag)
    print(f"Z3 solved: {result}")
```

### 非线性约束的线性化技巧
```python
# 如果加密过程是:
# for i in range(n):
#     x = flag[i] ^ key[i]
#     y = (x * 3 + 7) % 256
#     z = y ^ (y >> 3)

# 可以先写解密脚本逆向
# 如果不可逆 → 用 Z3/BitVec逐位约束
```

---

## 组合加密题型实战

### CTF常见混合加密题
```
1. 古典编码堆叠:
   base64 → rot13 → hex → ascii → 反转 → 得到flag
   → 反向操作 + 用自动解码脚本

2. RSA + AES 混合:
   RSA加密AES密钥 → AES加密flag
   → 解密RSA得AES密钥 → 解密AES得flag

3. XOR + 逆序 + 异或:
   多层嵌套操作
   → 逆向每一步

4. 图像像素加密:
   图片中每个像素的RGB XOR key
   → 将像素矩阵视为2D数组，恢复key后解密

5. 自定义FSM (状态机):
   输入流驱动状态转移 → 输出flag的一部分
   → 逆向FSM逻辑或暴力枚举初始状态
```

### 解密入口思维导图
```
拿到密文/文件
  ↓ 识别编码/形式
  ├── 纯密文(hex/Base64) → 解码 → 识别算法
  │   ├── RSA → 找n,e,c → 攻击
  │   ├── AES → 找key/IV → 解密
  │   ├── 自定义 → Z3/angr求解
  │   └── XOR → 已知明文恢复key
  │
  ├── 图片 → 像素LSB/调色板 → 取RGB通道
  │   └── 像素值可能是密文 → 按特定顺提取
  │
  ├── 程序/脚本 → 逆向加密算法 → 写反向解密
  │
  └── 网络交互 → 分析协议/密钥交换
```

---

## 常用工具安装
```bash
pip install pycryptodome gmpy2 sympy pwntools z3-solver py3base92
pip install owiener  # RSA维纳攻击
pip install hashpumpy  # 哈希长度扩展
pip install pycryptodomex  # 加密算法集合
pip install fastecdsa  # 快速ECC运算
# SageMath: https://www.sagemath.org/ （RSA ECC Lattice 必备）
```

## 参考脚本 (D:\CTF常用脚本\)
- `Base家族加解密.py` — base16~92 一站式编解码
- `base64隐写.py` — 从base64的=中提取隐写数据
- `base自动连续解密脚本.py` — 自动识别base16/32/64循环解
- `md5爆破.py`, `crc32.py`, `crc爆破.py` — 爆破类
- `sm2.py` — 国密SM2加解密模板
- `base64异或.py` — base64解码后逐字节XOR爆破
- `4字节16进制转浮点.py` — hex ↔ float转换

---

## Paillier / Goldwasser-Micali 同态加密（新增V4）

### Paillier 加法同态
```python
# Paillier: E(m) = g^m * r^n mod n^2
# 加法同态: E(m1) * E(m2) = E(m1+m2) mod n^2
# 标量乘: E(m)^k = E(k*m) mod n^2
# 解密: L(c^lambda mod n^2) * L(g^lambda mod n^2)^(-1) mod n, L(x)=(x-1)/n

# CTF 场景: 服务器提供加密oracle，要求解密某个被ban的值
# 绕过: 加密 (ban_value / 2)，然后乘以 E(2)
from Crypto.Util.number import *
def paillier_bypass(c_ban, n, oracle):
    r = 2
    c_bypass = (c_ban * pow(r, n, n**2)) % (n**2)
    m_bypass = oracle(c_bypass)
    return long_to_bytes((m_bypass * inverse(r, n)) % n)
```

### Goldwasser-Micali (GM)
```python
# GM 加密单个位: E(0)=r^2 mod n, E(1)=y*r^2 mod n (y是二次非剩余)
# CTF 场景: 重放攻击 — 重复提交同一密文作为key
# oracle区分全-0和全-1 key → 泄露模式
```

---

## ZKP 攻击进阶（新增V4）

### Groth16 Broken Setup (delta == gamma)
```python
# 验证方程: e(A,B) = e(alpha,beta) * e(C,delta) * e(inputs,gamma)
# 如果 delta == gamma:
#   A=alpha, B=beta, C=-vk_x  → 任意输入通过验证!
# 动手检查: compare vk.delta == vk.gamma first
```

### DV-SNARG Forgery
```python
# 有验证oracle时:
# 1. 提交pairs that unconstrain v values
# 2. 从接受/拒绝中逐位恢复v值
# 3. 构造CRS entry cancellation → 伪造任意proof
```

### Shamir SSS 复用系数攻击
```python
# share1 = s[0] + r1*a1 + r2*a2 + ...  (每个字节）
# share2 = s[1] + r1*a1 + r2*a2 + ...  (相同随机多项式!)
# → share1 - share2 = s[0] - s[1]  # 随机项抵消!
# 只需2个share即可恢复所有字节差异
```

### Garbled Circuits Free-XOR
```python
# Free-XOR 优化: 全局offset delta
# 3个加密truth table entries XOR → 恢复global delta
# 恢复delta后 → 可解密所有gates
```

---

## DSA 攻击（新增V4）

### DSA Nonce 重用
```python
# DSA: r=(g^k mod p) mod q, s=k^(-1)*(H(m)+x*r) mod q
# 两个签名中r相同 → k相同:
def dsa_nonce_reuse(r, s1, s2, h1, h2, q):
    k = ((h1 - h2) * pow(s1 - s2, -1, q)) % q
    x = ((s1 * k - h1) * pow(r, -1, q)) % q  # 私钥!
    return x
```

### DSA 小k爆破
```python
# k只有20位 → 直接爆破
for k in range(1, 2**20):
    if pow(g, k, p) % q == r: break
```

### DSA MD5 Collision on k-generation
```python
# k = MD5(prefix + counter) → fastcoll生成碰撞
# 两个不同prefix → 相同MD5 → 相同k → 恢复私钥
```

---

## 异类密码结构（新增V4）

### Braid Group DH
```
// 辫群 Diffie-Hellman — Alexander多项式是乘性的!
// A(b1 * b2) = A(b1) * A(b2)
// Eve从公钥直接计算: shared_key_poly = A(pub_a) * A(pub_b)
```

### Tropical Semiring (Min-Plus)
```python
# DH: shared = A ⊗ B (min-plus 矩阵乘法)
# 攻击: residual b* = max(Mb[j] - M[i][j]) → O(n^2)直接恢复共享密钥
```

### BB-84 QKD MITM
```
// 量子密钥分发 (模拟) — 无认证经典信道 → 完全MITM
// Eve独立与Alice和Bob协商密钥，强制一方输出固定值
```

### FPE Feistel Brute-Force
```python
# 16-bit round key → 2^16 = 65536 种可能 → 暴力枚举
# 已知明文-密文对验证 → 剩余GF(2)混合层高斯消元
```

---

## LWE / Ring-LWE / Module-LWE（新增V4）

### LWE → CVP 求解
```python
from fpylll import IntegerMatrix, LLL, CVP

def solve_lwe(A, b, q, n):
    """A(m×n), b=As+e mod q, 恢复小向量s"""
    m = len(b)
    M = IntegerMatrix(m+n, m+n)
    for i in range(m): M[i,i] = q
    for i in range(n): M[m+i,m+i] = 1
    for i in range(m):
        for j in range(n): M[i,m+j] = int(A[i][j])
    target = [int(x) for x in b] + [0]*n
    LLL.reduction(M)
    closest = CVP.closest_vector(M, target)
    return [int(x) for x in closest[m:]]
```

### Ring/Module-LWE 识别
```
// Ring-LWE: R_q = Z_q[x]/(x^n+1) 上
// Module-LWE: 向量而非标量
// CTF常弱化: 系数小/表示有bug/泄漏降级为普通LWE
// 注意端序不匹配!
```

---

## Manger Oracle + Bellcore（新增V4）

### Manger Oracle (RSA-OAEP 计时)
```python
# Python or短路: if Y!=0 and expensive_PBKDF2(X): ...
# Y=0 → fast; Y≠0 → slow → 计时泄露!
# 完整攻击: ~1024次查询 for 1024-bit RSA
```

### Bellcore RSA-CRT Fault
```python
from math import gcd
# 单一CRT签名中s_p计算错误:
p = gcd(pow(faulty_sig, e, n) - m, n)
if 1 < p < n:
    q = n // p  # n被分解!
```
