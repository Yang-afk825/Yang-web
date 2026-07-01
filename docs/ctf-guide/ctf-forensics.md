# Forensics — 取证与隐写深度参考

## Quick Wins（先试这些）

```bash
# EXIF & 元数据
exiftool file.*
exiftool -a -u file.*          # 显示所有元数据
exiftool -ee file.jpeg          # 提取嵌入式数据

# Binwalk (固件/文件提取)
binwalk file.*                  # 分析
binwalk -Me file.*              # 提取

# Strings + Tail
strings file.* | grep -iE 'flag|CTF|secret|password|ISCC'
tail -c 10M file.* | strings    # 检查尾部附加数据

# 文件类型
file *

# 十六进制查看
xxd file.* | head -100
```

---

## 题型总览

| 子类 | 典型题目 | 核心工具 |
|------|---------|---------|
| **图片隐写(Image Stego)** | LSB隐写、通道分离、调色板 | StegSolve, zsteg, stegdetect |
| **音频隐写(Audio Stego)** | 频谱图、波形分析、相位隐写 | Audacity, Sonic Visualiser, sox |
| **视频隐写** | 逐帧分析、音频流 | ffmpeg, FFV1编码 |
| **文档隐写** | PDF/Docx中的隐藏层 | pdf-parser, oledump |
| **网络取证(PCAP)** | 流量分析、数据提取 | Wireshark, tshark, NetworkMiner |
| **内存取证(Memory)** | Volatility分析 | Volatility3, volatility |
| **磁盘取证** | 分区、删除文件恢复 | FTK Imager, Autopsy, sleuthkit |
| **文件雕刻** | 从碎片恢复文件 | foremost, scalpel, photorec |
| **编码/压缩混合** | 多层数据隐藏 | binwalk, 7z, dd |
| **零宽字符隐写** | 不可见Unicode | Python提取 |
| **NTFS隐写** | ADS流、$MFT | streams.exe, Python |
| **PDF隐写** | 注释/图层隐藏 | pdf-parser, Peepdf |

---

## 1) 图片隐写 (Image Steganography) ⭐⭐⭐⭐⭐

### StegSolve 使用大全

StegSolve 是图片隐写的瑞士军刀（Java程序，需从GitHub下载）。

```
File Format（文件格式）:
- 查看所有图片通道（RGB, Alpha）
- 观察是否有异常颜色

Data Extract（数据提取）:
- 选择通道组合（R0, G0, B0...） → LSB模式
- Bit Order: MSB First / LSB First
- Bit Plane Order: RGB / BGR
- 点"Preview"看是否有可见信息

Frame Browser（GIF帧）:
- 逐帧浏览GIF图片
- 有时flag分散在多帧中

Stereogram Solver（立体图）:
- 3D立体图还原
```

### LSB 隐写提取（Python实现）

```python
from PIL import Image
import numpy as np

def extract_lsb(image_path, channel=0):
    """提取指定通道的 LSB"""
    img = Image.open(image_path)
    pixels = np.array(img)
    
    # 提取 LSB
    if len(pixels.shape) == 3:  # RGB
        channel_data = pixels[:,:,channel]
    elif len(pixels.shape) == 2:  # 灰度图
        channel_data = pixels
    
    lsb = channel_data & 1
    bits = lsb.flatten()
    
    # 每8位转字符
    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | int(bits[i + j])
        if 32 <= byte <= 126:
            chars.append(chr(byte))
        else:
            break
    return ''.join(chars)

def extract_lsb_full(image_path):
    """提取所有通道和位平面组合"""
    img = Image.open(image_path)
    pixels = np.array(img)
    
    # 如果调色板图片，先转RGB
    if img.mode == 'P':
        img = img.convert('RGB')
        pixels = np.array(img)
    
    results = []
    for bit in range(1, 9):
        for ch in range(3):
            bits = (pixels[:,:,ch] >> (bit-1)) & 1
            chars = []
            for i in range(0, len(bits.flatten()) - 7, 8):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | int(bits.flatten()[i + j])
                chars.append(byte)
            text = bytes(chars)
            if b'flag' in text.lower() or b'CTF' in text:
                results.append((bit, ch, text))
    return results

# 用 zsteg 自动检测（支持多种隐写算法）
# pip install zsteg
# zsteg image.png
# zsteg -a image.png  # 全面扫描
```

### 调色板隐写

```python
# PNG调色板（Palette）隐写
from PIL import Image

img = Image.open('palette_based.png')
palette = img.getpalette()  # [R0, G0, B0, R1, G1, B1, ...]

# 提取调色板索引的 LSB
if img.mode == 'P':
    pixels = np.array(img)
    bits = (pixels.flatten() & 1)
    char_bytes = []
    for i in range(0, len(bits) - 7, 8):
        byte = int(''.join(str(b) for b in bits[i:i+8]), 2)
        char_bytes.append(byte)
    text = bytes(char_bytes)
    print(f"Palette LSB: {text}")
    
# 调色板颜色差异
# 有时调色板中的RGB值嵌入信息
palette_bytes = bytes(palette)
# 提取偶/奇位
```

### 其他图片隐写技术

```python
# 1. DCT(JPEG)系数量化 LSB
# JPEG 无损区域（如1x1像素块）修改

# 2. 图片元数据
from PIL import Image
img = Image.open('stego.jpg')
info = img.info
for k, v in info.items():
    print(f"{k}: {v}")

# 3. EXIF 注释
# exiftool -Comment img.jpg
# exiftool -ImageDescription img.jpg

# 4. 图片尺寸宽高CRC
# PNG的IHDR块中，宽高CRC错误
# 已知CRC → 爆破正确宽高
# 参考 D:\CTF常用脚本\crc爆破.py

# 5. 像素数据间隙
# 像素数组行尾的填充字节（row stride padding）

# 6. 隐写软件识别
# steghide 嵌入: steghide extract -sf image.jpg -p password
# jphide 嵌入: jphide / jpseek
# outguess: outguess -r image.jpg out.txt
# F5: f5.jar
```

### 图片隐写综合检测流程

```bash
# 1. 先运行 zsteg 自动检测（支持LSB、BPP、MSB等）
zsteg -a image.png

# 2. 用 StegSolve 手动检查所有通道和位平面
# 3. 检查文件尾部
tail -c 1M image.png | strings

# 4. 检查元数据
exiftool image.png

# 5. 检查是否有附加数据
binwalk image.png

# 6. 如果用 steghide/jphide
steghide extract -sf image.jpg
# 密码可能为空或文件名
# 或尝试字典爆破

# 7. 检查调色板
python3 check_palette.py image.png
```

---

## 2) 音频隐写 (Audio Stego) ⭐⭐⭐⭐

### Audacity 分析（首选）

```
1. 打开音频文件
2. 视图模式切换:
   - Waveform（波形）→ 看振幅异常
   - Spectrogram（频谱）→ 最常用！
     - 频谱图设置: 频率范围1-16000Hz
     - 如果flag以文字形式出现在频谱中
     - 调整对比度/亮度看清文字
3. LSB 隐写:
   - 切换到 16-bit PCM 模式
   - 查看每个采样点的最低有效位
4. 音频参数:
   - 声道数（左右耳机可能不同内容）
   - 采样率（异常的 44100/48000/96000）
   - 比特深度（8/16/24 bit）
```

### 频谱图提取自动化

```python
# 用 Python 生成频谱图（手工观察）
import numpy as np
import matplotlib.pyplot as plt
from scipy.io import wavfile

def save_spectrogram(wav_path, output_image='spectrogram.png'):
    rate, data = wavfile.read(wav_path)
    # 如果是立体声，取一个声道
    if len(data.shape) > 1:
        data = data[:, 0]
    
    plt.figure(figsize=(12, 4))
    plt.specgram(data, NFFT=1024, Fs=rate, cmap='gray')
    plt.axis('off')
    plt.savefig(output_image, bbox_inches='tight', pad_inches=0)
    print(f"Spectrogram saved: {output_image}")

# 用 sox 命令行
# sox audio.wav -n spectrogram -o spectrogram.png
# 提高分辨率: sox audio.wav -n spectrogram -x 3000 -y 1000 -o output.png
```

### 音频 LSB 提取

```python
from scipy.io import wavfile
import numpy as np

def audio_lsb_extract(wav_path):
    rate, data = wavfile.read(wav_path)
    
    # 转为单声道（如果是立体声）
    if len(data.shape) > 1:
        data = data[:, 0]
    
    # 提取 LSB
    lsb = np.bitwise_and(data, 1)
    
    # 反向检查（有些工具 MSB0 → LSB7）
    lsb_rev = np.bitwise_and(data, 0x80) >> 7
    
    bits = lsb.flatten()
    
    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | int(bits[i + j])
        chars.append(byte)
    
    text = bytes(chars)
    # 找flag
    if b'flag' in text.lower() or b'CTF' in text:
        print(f"LSB: {text[:500]}")
    
    # 有时数据在偶数/奇数采样中
    even_lsb = lsb[::2]
    odd_lsb = lsb[1::2]
```

### 静默反转（逆向音频）

```python
# 有时flag是 "隐藏" 的——正常的相反
# 如: 先播放10秒正常 + 5秒反向
# 用 Audacity → Effect → Reverse 反转选中段
# 或用 Python
from scipy.io import wavfile

rate, data = wavfile.read('audio.wav')
# 反转整个音频
reversed_data = data[::-1]
wavfile.write('reversed.wav', rate, reversed_data)
```

### 差速隐写

```python
# 两个音频文件的差值
rate1, data1 = wavfile.read('audio1.wav')
rate2, data2 = wavfile.read('audio2.wav')

# 长度对齐
min_len = min(len(data1), len(data2))
diff = np.abs(data1[:min_len] - data2[:min_len])
wavfile.write('difference.wav', rate1, diff.astype(np.int16))
```

---

## 3) 视频隐写

```bash
# 逐帧提取图片
ffmpeg -i video.mp4 frames/frame_%04d.png

# 提取音频
ffmpeg -i video.mp4 -vn audio.wav

# 检查视频元数据
ffprobe video.mp4

# 视频帧间隔
# 有时flag只出现在某一帧（如第42帧）
# 或视频中某帧包含特殊像素

# 用 Python 逐帧检查
python3 -c "
import cv2
cap = cv2.VideoCapture('video.mp4')
frame_count = 0
while True:
    ret, frame = cap.read()
    if not ret: break
    # 检查帧中是否有纯色/文字区域
    if frame_count % 100 == 0:
        print(f'Frame {frame_count}: {frame.shape}')
    frame_count += 1
print(f'Total frames: {frame_count}')
"
```

---

## 4) 文档隐写 ⭐⭐⭐

### PDF 隐写

```bash
# pdf-parser 工具
pip install pdf-parser
pdf-parser -a document.pdf             # 完整分析
pdf-parser -s /OpenAction document.pdf  # 查看自动行为
pdf-parser -s /Annot document.pdf       # 注释/链接

# Peepdf 交互式
peepdf document.pdf

# 提取所有文本
python3 -c "
import PyPDF2
reader = PyPDF2.PdfReader('document.pdf')
for page in reader.pages:
    text = page.extract_text()
    print(text)
"

# 隐藏文本（白色文字）
# PDF中可能有与背景同色的文本不可见
# 用 PyPDF2 提取所有文本

# PDF 水印/图层提取
# 使用 pdfimages 提取嵌入图片
pdfimages -j document.pdf img_prefix

# qpdf 解密/解压PDF
qpdf --decrypt encrypted.pdf decrypted.pdf
qpdf --qdf --object-streams=disable document.pdf uncompressed.pdf
# 解压后可查看PDF原始语法, 找隐藏对象/stream
```

### Office 文档隐写 (DOCX/XLSX/PPTX)

**核心思路: Office 2007+ 文档本质是 ZIP 包!**

```bash
# === DOCX 分析 ===
# 解压查看内部结构
unzip document.docx -d docx_extracted/
ls -la docx_extracted/
# 结构:
# ├── [Content_Types].xml  ← 内容类型定义
# ├── _rels/               ← 关系文件
# ├── word/
# │   ├── document.xml     ← 主文档内容 (⭐重点)
# │   ├── comments.xml     ← 评论
# │   ├── footnotes.xml    ← 脚注
# │   ├── endnotes.xml     ← 尾注
# │   ├── header*.xml      ← 页眉
# │   ├── footer*.xml      ← 页脚
# │   ├── fontTable.xml    ← 字体
# │   ├── settings.xml     ← 文档设置
# │   ├── webSettings.xml  ← Web设置
# │   ├── styles.xml       ← 样式表
# │   ├── theme/           ← 主题
# │   ├── media/           ← 嵌入图片 ⭐
# │   └── embeddings/      ← OLE嵌入对象
# └── docProps/            ← 文档属性

# 搜索 flag (大小写不敏感)
grep -ri 'flag' docx_extracted/
grep -ri 'ctf' docx_extracted/

# 查看所有文本内容
find docx_extracted/ -name "*.xml" -exec cat {} \; | strings

# 提取嵌入的图片/对象
# word/media/ 中有可能有二维码等隐写

# 利用 oletools 分析 OLE
pip install oletools
oleid document.doc        # OLE ID识别
olevba document.doc       # VBA宏提取
oledump document.doc      # OLE结构分析
```

```bash
# === XLSX 分析 ===
unzip spreadsheet.xlsx -d xlsx_extracted/

# 重点文件:
# xl/sharedStrings.xml   ← 所有文本内容 ⭐
# xl/worksheets/sheet1.xml ← 工作表数据
# xl/comments*.xml        ← 单元格注释
# xl/drawings/            ← 图表/图片
# xl/printerSettings/     ← 打印设置
# xl/theme/               ← 主题

# 隐藏行列: 查看 sheet*.xml 中的 hidden="1" 属性
# 白色文字: 查找 color 属性为 FFFFFF 的文本

# === PPTX 分析 ===
unzip presentation.pptx -d pptx_extracted/

# 重点文件:
# ppt/slides/slide*.xml  ← 每页幻灯片
# ppt/notesSlides/       ← 演讲者备注 ⭐ (常见隐藏点)
# ppt/media/             ← 图片/视频/音频
# ppt/comments/          ← 评论

# 查看备注内容
grep -r 'flag\|ctf' pptx_extracted/ppt/notesSlides/
```

### OLE 文档 (DOC/XLS 旧格式)

```bash
# 旧版 Office 使用 OLE (Object Linking and Embedding) 格式
# 工具: oletools

pip install oletools

# 分析 OLE 结构
oleid document.doc

# 列出所有 OLE 流
oledump.py document.doc

# 提取 VBA 宏代码
olevba document.doc

# 提取特定流 (如流编号8)
oledump.py -s 8 -v document.doc

# 7z 也可能解压 OLE (OLE也是复合文档)
7z x document.doc -oole_extracted/
```

### 电子文档隐写工具速查

| 工具 | 用途 | 命令 |
|------|------|------|
| oletools | OLE文档分析 | `oleid`, `olevba`, `oledump` |
| pdf-parser | PDF对象分析 | `pdf-parser -a file.pdf` |
| peepdf | PDF交互分析 | `peepdf file.pdf` |
| qpdf | PDF解密/解压 | `qpdf --qdf file.pdf out.pdf` |
| pdfimages | 提取PDF图片 | `pdfimages -j file.pdf prefix` |
| unzip/7z | 解压Office文档 | `unzip file.docx -d out/` |
| strings | 搜索隐藏字符串 | `strings file.doc \| grep -i flag` |
| binwalk | 文件雕刻 | `binwalk -Me file.doc` |

---

## 5) PCAP 网络取证

### tshark 快速查询模板

```bash
# 基本统计
tshark -r capture.pcap -q -z io,phs       # 协议分层统计

# HTTP 请求
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.request.uri -e http.user_agent

# 下载 HTTP 对象
tshark --export-objects http,/tmp/http_obj capture.pcap

# DNS 查询
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name | sort -u

# 可疑流量（非标准端口）
tshark -r capture.pcap -Y "tcp.port not in {80,443,53,22,21} and tcp.flags.syn==1" -T fields -e ip.src -e ip.dst -e tcp.dstport

# 邮件
tshark -r capture.pcap -Y "smtp or pop or imap" -T fields -e smtp.req -e pop.req -e imap.request

# 提取特定流
tshark -r capture.pcap -Y "tcp.stream eq 0" -T fields -e data.text
# 或
tshark -r capture.pcap -z follow,tcp,ascii,0
```

### Python PCAP 分析

```python
from scapy.all import *

packets = rdpcap('capture.pcap')

# 遍历包
for pkt in packets:
    if pkt.haslayer(TCP):
        payload = bytes(pkt[TCP].payload)
        if payload:
            # 检查负载中的flag
            if b'flag' in payload.lower():
                print(f"Found flag in packet: {payload}")

# 提取HTTP请求
for pkt in packets:
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        payload = pkt[Raw].load.decode(errors='ignore')
        if 'HTTP' in payload:
            print(payload[:500])

# 过滤IP和端口
for pkt in packets:
    if pkt.haslayer(IP):
        if pkt[IP].src == '192.168.1.1':
            print(pkt.summary())

# 提取文件（通过TCP重传）
from scapy.utils import rdpcap
# 使用 Scapy 的 tcp-reassemble 功能或
# 使用 Wireshark 的 "Follow TCP Stream" 导出数据
```

### 常用 Wireshark 显示过滤器

```
# 按协议
http
dns
smtp
tcp.port == 443
tcp.port == 22
arp

# 按IP
ip.addr == 192.168.1.1
ip.src == 10.0.0.1

# 按负载
http.request.uri contains "flag"
data contains "secret"
tcp.payload contains "flag"

# 按时间
frame.time >= "2024-01-01 00:00:00"

# 常见攻击检测
tcp.flags.syn == 1 and tcp.flags.ack == 0  # SYN扫描
http.request.method == "POST"               # POST请求
```

---

## 6) 内存取证 (Memory Forensics)

### Volatility 基础

```bash
# 安装
pip install volatility3

# 列出已识别的操作系统/配置文件
vol -f memory.dmp imageinfo

# 进程列表
vol -f memory.dmp windows.pstree
vol -f memory.dmp windows.pslist

# 网络连接
vol -f memory.dmp windows.netscan

# 命令历史
vol -f memory.dmp windows.cmdline

# 提取进程内存
vol -f memory.dmp windows.memdump --pid 1234

# 剪贴板
vol -f memory.dmp windows.clipboard

# 注册表
vol -f memory.dmp windows.envars
vol -f memory.dmp windows.registry.printkey

# 文件扫描
vol -f memory.dmp windows.filescan
vol -f memory.dmp windows.dumpfiles --physaddr 0xXXXXXXXX

# 内核模块
vol -f memory.dmp windows.modules
```

### 内存取证关键分析链

```
取证场景：
1. 一个可疑进程在运行
2. 检查其命令行参数 → 可能包含flag
3. 检查网络连接 → 看是否外联C2
4. 检查打开的文件 → 是否有flag.txt
5. 检查剪贴板 → 用户可能复制了flag
6. 检查注册表 → 持久化/配置数据
7. 从进程内存中字符串搜索 → strings * | grep -i flag
```

---

## 7) 文件雕刻 (File Carving)

```bash
# foremost — 基于文件头恢复
foremost -i disk_image.raw -o recovered/

# scalpel — 自定义文件头
scalpel disk_image.raw -o recovered/

# photorec — 图片恢复
# TestDisk / PhotoRec

# binwalk — 固件提取
binwalk -Me firmware.bin

# 手动提取
# dd if=image.raw of=extracted.png bs=1 skip=OFFSET count=SIZE
```

### 常用文件头速查（Magic Bytes）

| 文件类型 | 头标志 (hex) |
|---------|-------------|
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| JPEG | `FF D8 FF E0` 或 `FF D8 FF E1` |
| GIF | `47 49 46 38 39 61` 或 `47 49 46 38 37 61` |
| ZIP | `50 4B 03 04` |
| RAR | `52 61 72 21 1A 07 00` |
| PDF | `25 50 44 46` (%PDF) |
| ELF | `7F 45 4C 46` (.ELF) |
| PE | `4D 5A` (MZ) |
| MP3 | `49 44 33` (ID3) |
| WAV | `52 49 46 46` (RIFF) |
| AVI | `52 49 46 46` (RIFF) |
| FLV | `46 4C 56` (FLV) |

---

## 8) 零宽字符隐写 (Zero-Width Characters)

```python
# 不可见的 Unicode 字符
# 常见零宽字符：
ZWSP = '\u200b'      # 零宽空格
ZWNJ = '\u200c'      # 零宽非连接符
ZWJ  = '\u200d'      # 零宽连接符
LTR  = '\u200e'      # 从左到右标记
RTL  = '\u200f'      # 从右到左标记

# 编码方案：不同的零宽字符代表 0 和 1
# 简单的：ZWSP=0, ZWNJ=1

def detect_zero_width(text):
    """检测文本中是否有零宽字符"""
    zws = []
    for ch in text:
        if ch in ['\u200b', '\u200c', '\u200d', '\u200e', '\u200f', '\ufeff']:
            zws.append(ch)
    if zws:
        print(f"Found {len(zws)} zero-width chars")

def extract_zero_width(text):
    """提取零宽字符中的二进制数据"""
    zero_bits = ['\u200b', '\u200e']  # 0
    one_bits = ['\u200c', '\u200d', '\u200f', '\ufeff']  # 1
    
    bits = ''
    for ch in text:
        if ch in zero_bits:
            bits += '0'
        elif ch in one_bits:
            bits += '1'
    
    # 每8位转字符
    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte = int(bits[i:i+8], 2)
        chars.append(chr(byte))
    return ''.join(chars)
```

---

## 9) NTFS 隐写

```bash
# NTFS Alternate Data Stream (ADS)
# 文件可以有多个数据流
# 例: file.txt 带隐藏流 flag.txt

# 查看 ADS
dir /R
Get-Item -Path file.txt -Stream *
Get-Content -Path file.txt -Stream flag.txt

# 流创建
echo "hidden data" > file.txt:secret.txt
type file.txt:secret.txt

# Python 读取 ADS
import sys
with open("file.txt:secret.txt", "r") as f:
    print(f.read())
```

---

## 解题流程

```
拿到文件
  ↓ file + exiftool + strings + xxd
  ↓ 识别文件类型
  ↓
  ├── 图片 → StegSolve / zsteg → LSB / 调色板 → flag
  │   ├── JPEG → steghide / jphide / outguess / F5
  │   ├── PNG → zsteg / LSB / 调色板 / CRC
  │   └── GIF → 逐帧分析 / 帧差值
  │
  ├── 音频 → Audacity 频谱 / LSB / 速度/反转 → flag
  │   ├── WAV → LSB / 频谱图 / 差值
  │   └── MP3 → MP3Stego / 元数据
  │
  ├── PCAP → Wireshark 统计 / HTTP对象 / 提取文件 → flag
  │
  ├── 内存 → Volatility → 进程 / 网络 / 剪贴板 → flag
  │
  ├── 文档 → unzip(docx/xlsx) → 隐藏文本/注释 → flag
  │
  └── 其他 → binwalk / foremost → 文件提取 → 递归分析
  ↓
  Flag
```

---

## 补充A: 浏览器取证

### Chrome/Chromium 取证
```bash
# Chrome 用户数据目录
# Windows: %LOCALAPPDATA%\Google\Chrome\User Data\Default
# Linux: ~/.config/google-chrome/Default
# macOS: ~/Library/Application Support/Google/Chrome/Default

# 关键文件
set | Format-List Name
# History → SQLite 数据库 (浏览历史)
# Cookies → SQLite (cookies)
# Login Data → SQLite (保存的密码，加密)
# Web Data → SQLite (自动填充)
# Local Storage → LevelDB (localStorage/sessionStorage)
# IndexedDB → indexeddb 目录
# Cache → 缓存文件

# 读取 History (需要关闭 Chrome)
python3 -c "
import sqlite3
conn = sqlite3.connect('History')
for row in conn.execute('SELECT url, title, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT 20'):
    print(row)
"

# 读取 Cookies
python3 -c "
import sqlite3
conn = sqlite3.connect('Cookies')
for row in conn.execute('SELECT host_key, name, value FROM cookies LIMIT 20'):
    print(row)
"
```

### Firefox 取证
```bash
# Firefox 用户数据目录
# Windows: %APPDATA%\Roaming\Mozilla\Firefox\Profiles\xxxx.default*
# Linux: ~/.mozilla/firefox/xxxx.default*
# macOS: ~/Library/Application Support/Firefox/Profiles/xxxx.default*

# 关键文件
# places.sqlite → 历史+书签
# cookies.sqlite → cookies
# formhistory.sqlite → 表单历史
# logins.json + key4.db → 保存的密码（加密）
# sessionstore.jsonlz4 → 会话恢复

# 读取 places.sqlite
python3 -c "
import sqlite3
conn = sqlite3.connect('places.sqlite')
for row in conn.execute('SELECT url, title, visit_count FROM moz_places ORDER BY last_visit_date DESC LIMIT 20'):
    print(row)
"
```

### 恢复删除的浏览器数据
```bash
# 使用 extundelete (Linux ext*)
extundelete /dev/sda1 --restore-file /.config/google-chrome/Default/History

# 使用 Recuva (Windows)
# 或 Photorec (跨平台)
photorec /dev/sda1

# 从内存转储中恢复
# Volatility: filescan + dumpfiles
```

---

## 补充B: NTFS 备用数据流 (ADS)

NTFS 文件系统允许文件有多个数据流，常被恶意软件用于隐藏数据。

```bash
# 检测 ADS
# Windows: dir /r 显示备用数据流
dir /r suspicious.exe
# 输出: suspicious.exe:hidden.txt:$DATA

# 也可以使用 PowerShell
Get-Item suspicious.exe -Stream *

# 读取 ADS 内容
type suspicious.exe:hidden.txt:$DATA

# 写入 ADS (恶意软件常用)
echo "malicious payload" > innocent.txt:hidden.exe

# 从 ADS 执行 (wmic, forfiles, 等 LOLBAS 工具)
wmic process call create "innocent.txt:hidden.exe"
```

### CTF 中 ADS 出题
```python
# 题目可能给出文件，flag 藏在 ADS 中
# 解决步骤:
# 1. 使用工具检测 ADS (lads.exe, streams.exe)
# 2. 读取 ADS 内容
# 3. 如果 ADS 是另一个文件，继续分析

# Python 读取 ADS (Windows)
import subprocess
result = subprocess.run(['powershell', '-Command', 'Get-Item file.txt -Stream *'], 
                       capture_output=True, text=True)
print(result.stdout)
```

---

## 补充C: 移动设备取证

### Android 取证
```bash
# 获取设备信息 (需 adb)
adb devices
adb shell getprop ro.build.version.release  # Android 版本
adb shell dumpsys battery  # 电池信息

# 提取应用数据 (需 root 或备份)
adb backup -apk -shared -all -f backup.ab

# 解析 backup.ab
# 使用 Android Backup Extractor (abe)
java -jar abe.jar unpack backup.ab backup.tar

# 或从已 root 设备拉取数据
adb shell su -c "dd if=/dev/block/mmcblk0pX of=/sdcard/image.img"
adb pull /sdcard/image.img .
```

### iOS 取证
```bash
# 需要 iTunes 备份 (未加密)
# 备份位置:
# Windows: %APPDATA%\Roaming\Apple Computer\MobileSync\Backup\
# macOS: ~/Library/Application Support/MobileSync/Backup/

# 关键文件:
# Manifest.db → SQLite，记录所有备份文件
# 各应用沙盒数据

# 解析备份
# 使用 iphonebackupdecoder 或 pymobiledevice3
pip install pymobiledevice3
pymobiledevice3 backup extract --out ./extracted
```

---

## 补充D: 文件签名与魔术字节速查表

| 文件类型 | 魔术字节 (hex) | 扩展名 |
|---------|-------------------|--------|
| PNG | `89 50 4E 47 0D 0A 1A 0A` | .png |
| JPEG | `FF D8 FF E0` 或 `FF D8 FF E1` | .jpg |
| GIF | `47 49 46 38` (GIF8) | .gif |
| PDF | `25 50 44 46 2D` (%PDF-) | .pdf |
| ZIP | `50 4B 03 04` | .zip, .docx, .xlsx, .jar |
| RAR | `52 61 72 21` (Rar!) | .rar |
| 7z | `37 7A BC AF 27 1C` | .7z |
| ELF | `7F 45 4C 46` | (无，Linux可执行) |
| PE | `4D 5A` (MZ) | .exe, .dll |
| Java .class | `CA FE BA BE` | .class |
| WAV | `52 49 46 46` (RIFF) | .wav |
| AVI | `52 49 46 46` (RIFF) | .avi |
| MP4 | `66 74 79 70` (ftyp) | .mp4 |

### 使用 Python 检测文件类型
```python
def detect_file_type(data):
    signatures = {
        b'\x89PNG': 'PNG',
        b'\xff\xd8\xff': 'JPEG',
        b'GIF8': 'GIF',
        b'%PDF': 'PDF',
        b'PK\x03\x04': 'ZIP-based',
        b'Rar!': 'RAR',
        b'7z\xbc\xaf': '7z',
        b'\x7fELF': 'ELF',
        b'MZ': 'PE',
    }
    for sig, ftype in signatures.items():
        if data.startswith(sig):
            return ftype
    return 'Unknown'
```

---

## 更新后的解题流程（完整版）

```
拿到文件/流量/内存转储
  ↓ file + strings + exiftool 初步分析
  ↓ 识别文件类型 (魔术字节)
  ↓
  ├── 图片 → StegSolve/zsteg → LSB/调色板/CRC
  │    ├── JPEG → steghide/jphide/outguess/F5
  │    ├── PNG → zsteg/LSB/调色板/CRC修复
  │    └── GIF → 逐帧分析/帧差值
  │
  ├── 音频 → Audacity → 频谱/LSB/速度/反转
  │    ├── WAV → LSB/频谱图/差值
  │    └── MP3 → MP3Stego/元数据
  │
  ├── PCAP → Wireshark → 统计/HTTP对象/提取文件
  │    ├── 过滤 HTTP/FTP/DNS
  │    ├── 提取传输的文件
  │    └── 分析 C2 通信模式
  │
  ├── 内存 → Volatility → 进程/网络/注册表/剪贴板
  │    ├── pslist/pstree → 可疑进程
  │    ├── netscan → 网络连接
  │    ├── hivelist → 注册表 hive
  │    └── clipboard → 剪贴板内容
  │
  ├── 文档 → unzip → 隐藏文本/注释/元数据
  │    ├── docx/xlsx → 解压后查看 XML
  │    ├── PDF → 提取文本/图片/JavaScript
  │    └── OLE → olevba 提取宏
  │
  ├── 浏览器数据 → SQLite 取证
  │    ├── Chrome: History/Cookies/Login Data
  │    └── Firefox: places.sqlite/cookies.sqlite
  │
  ├── NTFS ADS → dir /r / Get-Item -Stream
  │    └── 读取隐藏数据流
  │
  └── 其他 → binwalk/foremost → 文件提取 → 递归分析
  ↓
  Flag = 坐标/字符串/文件内容/内存数据

---

## Windows Forensics 详细（新增V4）

### Event Logs 关键 Event ID 速查
```
4624: 成功登录      4625: 登录失败      4672: 特权分配
4688: 进程创建      4698: 计划任务创建  7045: 服务安装
1102: 日志清除      4720: 用户创建      4781: 账户重命名
1149: RDP认证成功 (TerminalServices, 含源IP!)
```

### 日志清除后的替代证据源
1. **USN Journal ($J)** — 所有NTFS文件操作时间线，日志清除后仍保留
2. **$MFT** — 主文件表，用MFTECmd解析
3. **Prefetch** (C:\Windows\Prefetch\*.pf) — 程序执行次数+最后执行时间+加载DLL
4. **Amcache** — SHA1、文件路径、首次安装时间
5. **回收站** (C:\$Recycle.Bin\<SID>\): $RXXXXXX=文件内容, $IXXXXXX=删除时间+原始路径
6. **Shimcache** (AppCompatCache) — 所有执行过的程序

```python
# 解析 $I 回收站元数据
def parse_i_file(data):
    version = data[0]          # 1=Win7, 2=Win10
    file_size = struct.unpack('<Q', data[8:16])[0]
    delete_time = filetime_to_datetime(data[16:24])  # FILETIME
    orig_path = data[24:].decode('utf-16-le', errors='replace').strip('\x00')
    return {'path': orig_path, 'deleted': delete_time, 'size': file_size}
```

---

## Linux Forensics（新增V4）
```bash
# 攻击链检查清单:
last -20; lastb -20                   # 登录记录
ps auxf                                # 进程树
netstat -antp; ss -tuln                # 网络连接
crontab -l; ls -la /etc/cron.*         # 定时任务
find / -perm -4000 -type f 2>/dev/null # SUID二进制
find / -mtime -1 -type f 2>/dev/null   # 最近24h修改
ausearch -m ALL -ts recent             # auditd审计日志

# 关键日志位置:
# Debian/Ubuntu: /var/log/auth.log
# RHEL/CentOS:   /var/log/secure
# journald:      /var/log/journal/
# 所有用户:      /etc/passwd, /etc/shadow
```

### Docker 容器取证
```bash
docker history --no-trunc image_name  # 构建历史 → 泄露构建秘密!
docker export container_id -o c.tar   # 导出文件系统
docker save image_name -o i.tar       # 层分析 (每层一个目录)
docker inspect container_id           # 运行配置
docker logs container_id              # 容器日志
```

---

## 3D Printing Forensics（新增V4）
```python
# G-code特征: 文件头通常有 ;generated by PrusaSlicer
# 侧投影可视化:
# → XZ投影看侧面文字
# → YZ投影看另一视角
# → 只画E>0的移动显示实际打印内容
import matplotlib.pyplot as plt
# 过滤 G1 中 E>0 的坐标 → scatter plot → 文本/图案出现!

# 常见flag位置: 注释中(;printer notes=flag{...})、喷嘴路径文字
```

---

## 键盘声学侧信道（新增V4）
```python
import librosa
import numpy as np

def extract_keystroke_mfcc(audio, sr=44100):
    energy = librosa.feature.rms(y=audio)[0]
    peaks = librosa.util.peak_pick(energy, 
        pre_max=5, post_max=5, pre_avg=10, post_avg=10,
        wait=int(sr*0.05))  # 击键间隔 >50ms
    
    features = []
    for peak in peaks:
        segment = audio[max(0,peak-int(sr*0.005)):min(len(audio),peak+int(sr*0.05))]
        mfcc = librosa.feature.mfcc(y=segment, sr=sr, n_mfcc=13)
        features.append(np.mean(mfcc, axis=1))
    
    return peaks, np.array(features)  # → KNN与已知训练样本匹配
```

---

## 信号与硬件取证速查（新增V4）
```
VGA/HDMI TMDS: 视频信号解码 → Saleae Logic 2
DisplayPort: 8b/10b + LFSR descrambler
UART串口: WAV音频中的方波 → 确定波特率 → 解析start/stop位
I2C: SDA/SCL线解码 → EEPROM数据
Flipper Zero: .sub文件 → 射频信号重放
```
```
