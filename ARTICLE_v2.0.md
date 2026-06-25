# 我写了一个 CTF 工具箱，现在它有 50+ 种编码和自研密码引擎了

> 从「解码器」到「CTF 全方向武器库」，Yang-Web v2.0 重度更新。

---

打 CTF 的都知道，比赛里经常遇到各种奇怪的编码。Base64 算什么，Base91、Brainfuck、Ook!、与佛论禅、核心价值观……出题人的想象力永远比你强。

之前我写过一个 v1.4 的 Yang-Web，核心就一个智能解码面板 + 几个辅助模块。用到现在，积累了不少实战痛点，趁最近有空，直接拉到 v2.0。

---

## 📊 先看数据

| 指标 | v1.4.0 | v2.0.0 |
|------|--------|--------|
| 智能解码支持 | 14 种 | **28+ 种** |
| 密码/编码总数 | 23 | **50+** |
| 核心模块 | 5 | **9** |
| GUI 面板 | 6 | **11** |
| 中文特色密码 | 0 | **7** |
| 纯Python密码算法 | 0 | **AES/RC4/RSA + Hash 全系** |

---

## 🔓 智能解码器——粘贴即用

这是 Yang-Web 的核心。v2.0 把智能解码从 14 种扩展到了 **28+ 种**：

**自动识别**：贴一段密文进去，28 个检测器并行扫描，按置信度排序，告诉你这是什么编码。

**链式解码**：点一下「链式解码」，自动把结果当作新密文继续解，直到出现明文。Base64→Hex→UTF-8，一气呵成。

**暴力全部**：不知道是什么编码？28 种全部试一遍，可读的结果排前面。

目前覆盖的编码类型：

- **Base 系**：16 / 32 / 58 / 64 / 64url / 85 / 91 / 92
- **Rotation 系**：ROT13 / ROT47 / ROT5 / ROT18
- **进制系**：二进制 / 八进制 / 十进制 / Shellcode \x
- **传输系**：URL / HTML / Quoted-Printable / UUEncode / XXEncode / UTF-7 / Punycode
- **古典系**：摩斯电码
- **编程语言系**：Brainfuck / Ook!
- **Unicode 系**：Unicode转义

> 💡 实战案例：某题给了 `=E6=B5=8B=E8=AF=95`，贴进去秒识别为 Quoted-Printable，一解码就是明文。以前还得去 Quoted-Printable 在线工具手动输。

---

## 🈶 中文特色密码——国风题专用

近年 CTF 中国风题目越来越多。在线工具不稳定（与佛论禅的网站三天两头挂），所以全部用纯 Python 手写了一遍：

| 密码 | 示例 | 说明 |
|------|------|------|
| **与佛论禅** | 佛曰：阿悉陀夜… | 第一方网站经常挂，离线随便解 |
| **核心价值观** | 富强民主文明和谐… | 12 词映射字节，B站最爱的密码 |
| **兽音** | 嗷呜啊~ | 4 字符映射 2-bit |
| **熊曰** | 熊曰：呋食食… | 熊语加密 |
| **百家姓** | 赵钱孙李… | 95 个姓氏映射 byte |
| **中文电码** | 4222 0001… | 4 位数字码 |
| **Gan 语言** | Gan 语 | 特定社区编码 |

---

## 🔐 密码学引擎——手写 AES/RC4/RSA

这个是 v2.0 最硬核的部分。**零外部依赖，纯 Python 标准库实现**：

### AES（含完整 S-Box + GF(2⁸) 乘法）
- 128 / 192 / 256 位密钥，ECB / CBC 模式
- SubBytes → ShiftRows → MixColumns → AddRoundKey，一行行手写
- **GF(2⁸) 伽罗瓦域乘法从零实现**，不查表，彻底理解 AES 原理
- PKCS7 填充自动处理

### RC4
- KSA + PRGA 流密码纯 Python 实现
- 加密 = 解密（对称）

### RSA（教育用途）
- Miller-Rabin 素性检测 → 大素数生成
- 公私钥生成 + 加解密
- 因数分解建议分级向导

### Hash 全家桶
- MD5 / SHA1 / SHA224 / SHA256 / SHA384 / SHA512
- SHA3-256 / SHA3-512
- BLAKE2b / CRC32 / HMAC

### XOR 工具箱
- 单字节 / 多字节 XOR 加解密
- **自动爆破**：0-255 逐个尝试，按可打印字符评分，自动找明文

> ⚠️ 标注了 NOT cryptographically secure，仅用于 CTF 学习。

---

## 🧰 其他模块速览

### 反弹Shell 生成器
10 种语言一键生成（Bash / Python / PHP / Netcat / PowerShell / Perl / Ruby / Socat / Telnet / AWK），填 IP+端口，payload 直接复制。

### 隐写分析
- PNG Chunk 逐块解析（检测 IEND 后的隐藏数据）
- LSB 位平面提取（RGB 各通道）
- EXIF 元数据读取
- 文件魔术字节识别（17 种格式自动识别）

### Payload 工具箱
LFI / PHP / RCE / SQLi / SSRF / SSTI / Upload / XSS 八合一，Upload 模块含黑名单绕过分析器。

### JWT / Hash / MiscCrypto
JWT 解析 → None 攻击 → 弱密钥爆破 → 伪造；Hash 识别；23 种密码加解密。

---

## 🎨 界面

Catppuccin Mocha 暗色主题，11 个面板左侧树状导航。GUI 和 CLI 双模式：

```bash
# GUI 模式
python -m yang_web

# CLI 模式
yang-web decode "ZmxhZ3t0ZXN0fQ=="
yang-web shell bash --ip 10.0.0.1 --port 4444
```

---

## 💡 设计哲学

1. **完全离线**——CTF 比赛现场没网，零 pip 依赖，拷贝即用
2. **纯 Python**——不依赖 openssl/gmp 等系统库
3. **从零实现**——AES 的 S-Box、GF 乘法一行行写，目的不是生产安全，是理解密码学
4. **GUI + CLI 双模式**——图形界面直观，命令行高效

---

## 📮 链接

**GitHub**: [github.com/Yang-afk825/Yang-web](https://github.com/Yang-afk825/Yang-web)

**联系**: 3303257524@qq.com

---

*觉得有用就点个 Star ⭐，欢迎提 Issue / PR，一起完善 CTF 工具箱。*

*—— 晓阳，2026 年 6 月*
