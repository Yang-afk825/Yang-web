# OSINT — 开源情报调查深度参考

## Quick Wins

```bash
# 基础信息
whois example.com
nslookup example.com
dig example.com ANY

# 子域名枚举
# subfinder -d example.com
# amass enum -d example.com

# 图片搜索
# Google Images 搜图, Yandex, TinEye, Baidu

# 社交账号搜索
# https://whatsmyname.app
# https://namechk.com
# https://checkuser.org

# 网页历史
# https://web.archive.org
```

---

## 题型总览

| 类型 | 目标 | 常用工具/平台 | CTF常见出题形式 |
|------|------|-------------|---------------|
| **地理位置** | 找到照片拍摄地 | Google Maps, 街景, 百度地图 | 一张照片找出坐标 |
| **人员追踪** | 找个人的完整信息 | 社交媒体, 搜索引擎, 通缉令 | 找到某人的手机/邮箱 |
| **时间分析** | 照片/视频拍摄时间 | 影子长度分析, Exif元数据 | 推测照片拍摄月份/时刻 |
| **社交关系** | 账号间关联 | 用户名查重, 邮箱查重 | 多个账号找到共同点 |
| **反向图像搜索** | 找原图/更多信息 | TinEye, Google, Yandex | 找到高分辨原图得信息 |
| **域名/IP调查** | 网站/服务器信息 | whois, shodan, censys | 找到幕后公司/个人 |
| **数据泄露** | 找泄露密码/AK | dehashed, 搜索引擎 | 从公开信息提取flag |
| **地理围栏/轨迹** | 分析活动范围 | 地图API, GPS元数据 | 多个点拼出路线 |
| **元数据分析** | 文件隐藏信息 | exiftool, strings | 文件头/尾标记 |
| **社交媒体挖掘** | 从帖子提取信息 | 爬虫+分析 | 特定帖子/评论得线索 |

---

## 1) 地理位置（Geolocation）—— 最常考OSINT题型

### 从照片中提取位置信息

```python
# Exif GPS 提取
import exifread

with open('photo.jpg', 'rb') as f:
    tags = exifread.process_file(f)

for tag in tags:
    if 'GPS' in tag:
        print(f"{tag}: {tags[tag]}")

# 手动提取 GPS
if 'GPS GPSLatitude' in tags and 'GPS GPSLongitude' in tags:
    lat = tags['GPS GPSLatitude'].values
    lon = tags['GPS GPSLongitude'].values
    lat_ref = tags.get('GPS GPSLatitudeRef', 'N')
    lon_ref = tags.get('GPS GPSLongitudeRef', 'E')
    
    # 度分秒 → 十进制
    lat_dec = lat[0] + lat[1]/60 + lat[2]/3600
    lon_dec = lon[0] + lon[1]/60 + lon[2]/3600
    
    if str(lat_ref) == 'S': lat_dec = -lat_dec
    if str(lon_ref) == 'W': lon_dec = -lon_dec
    
    print(f"Coordinates: {lat_dec}, {lon_dec}")
    print(f"Google Maps: https://www.google.com/maps?q={lat_dec},{lon_dec}")
    print(f"百度地图: https://api.map.baidu.com/lbsapi/getpoint/index.html?title={lat_dec},{lon_dec}")
```

### 无GPS时的定位技巧

**技巧1: 文字/招牌识别**
```
- 照片中有路牌/商店名 → 搜索该名称
- 公交车牌/地铁站 → 查公交/地铁线路
- 街道号码 → Google Maps 搜索 "门牌号 城市"
```

**技巧2: 建筑/地标识别**
```
- 标志性建筑 → 视觉匹配
- 建筑风格 → 缩小国家/地区范围
  - 红砖/维多利亚式 → 英国/澳洲
  - 混凝土/现代主义 → 欧洲/亚洲城市
  - 木结构/坡屋顶 → 日本/中国民居
  - 平顶/沙漠色 → 中东/非洲
```

**技巧3: 环境分析**
```python
# 植物/植被 → 地理区域
vegetation_map = {
    '棕榈树': ['热带/亚热带', '海南/东南亚/南加州'],
    '针叶树': ['寒带/山地', '北欧/加拿大/青藏高原'],
    '竹子': ['东亚/东南亚', '中国/日本/东南亚'],
    '仙人掌': ['沙漠/干旱', '美国西南/墨西哥/中东'],
}

# 路标/交通标志
# 欧盟：蓝底白字、圆形限速
# 美国：绿底白字、方形/矩形
# 日本：蓝底白字、汉字指示
# 中国：蓝底白字、中文字
```

**技巧4: 天空/云分析**
```python
# 从太阳方位和影子长度估算时间
import math
from datetime import datetime

def estimate_time_from_shadow(shadow_length_m, object_height_m, latitude):
    """估算大致时间（简化版）"""
    # 影子与高度比 = cot(太阳高度角)
    ratio = shadow_length_m / object_height_m
    altitude = math.atan2(1, ratio)
    # ... 需要更多参数（日期、经度）
    pass

# 网站: suncalc.org → 输入位置+时间推测影子方向
# 或: 输入影子方向+日期 → 反推拍摄时间
```

**技巧5: 基础设施特征**
```
- 电线杆样式 → 不同国家有标准设计
- 电表/水表箱 → 地区供应商
- 车牌设计 → 国家/地区
- 井盖样式 → 城市特征（东京井盖有樱花、巴黎有城徽）
- 路灯设计 → 不同城市有特定街道灯
- 垃圾桶 → 欧洲城市有定制垃圾箱
- 消防栓颜色 → 不同国家/城市
- 电源插座 → 形状判断国家
```

**技巧6: 天空/卫星图像匹配**
```
- 对比照片中的地形特征（山脉轮廓、海岸线、河流弯曲）
- 用 Google Earth 3D 视角匹配建筑轮廓
- 使用 peakvisor.com 识别山脉
```

---

## 2) 人员追踪

### 用户名查重

```bash
# 在线服务
# https://whatsmyname.app — 批量查100+平台
# https://namechk.com — 常用用户名搜索
# https://checkuser.org — 跨平台搜索
# https://usersearch.org

# 手动常见平台
# 国内: 微信/微博/知乎/B站/抖音/小红书/豆瓣/虎扑/CSDN/论坛
# 国外: GitHub/Twitter/Reddit/Instagram/Facebook/LinkedIn/Patreon
# 开发: GitLab/Bitbucket/Docker Hub/PyPI/npm
```

### 邮箱信息挖掘

```bash
# 搜索邮箱关联信息
# Google: "user@gmail.com"
# hunter.io — 公司邮箱验证
# snov.io — 公司邮箱搜索
# https://emailrep.io — 邮箱信誉检查
# https://haveibeenpwned.com — 泄露检查

# GitHub 搜索邮箱
# site:github.com "user@email.com"
```

### 反向用户名搜索

```bash
# 如果找到用户名，搜索:
# 1. 同用户名在多个平台
# 2. 用户名 + "email" → 论坛/评论
# 3. 用户名 + 特定关键词 → 更精确
# 4. 用 Wayback Machine 看旧页面
```

### 社交媒体地理信息

```python
# 从社交媒体帖子提取位置
# Twitter: tweet 里有 location 字段或 geotag
# Instagram: 照片可能有 GPS 坐标
# 签到/打卡: 地点的 Foursquare/大众点评

# 时间戳线索
# 帖子发布时间 → 可推断时区
# 天气匹配 → 照片中的天气与某地天气预报一致
# 日落时间 → 与拍摄地的日落时间匹配
```

---

## 3) 时间分析

### Exif 时间信息

```python
import exifread

with open('photo.jpg', 'rb') as f:
    tags = exifread.process_file(f)

# 拍摄时间
if 'EXIF DateTimeOriginal' in tags:
    print(f"Original: {tags['EXIF DateTimeOriginal']}")

# 数码化时间
if 'EXIF DateTimeDigitized' in tags:
    print(f"Digitized: {tags['EXIF DateTimeDigitized']}")

# 修改时间
if 'Image DateTime' in tags:
    print(f"Modified: {tags['Image DateTime']}")
```

### 影子分析

```python
# 通过影子方向和长度估算时间
# 1. 找垂直物体（灯柱、人）与影子的比例
# 2. 影子方向 → 太阳方位角
# 3. 结合日期 → 时间
# 4. 结合时间 → 可能的时区/经度范围

# 工具: suncalc.org → 输入地 + 影子方向 → 反推出时间
# 或: PhotoPills App (手机)
```

---

## 4) 域名/IP 调查

### DNS 全信息收集

```bash
# 基础
whois example.com       # 注册信息（可能含邮箱、电话、地址）
nslookup -type=any example.com
dig example.com ANY +noall +answer

# 更多
# crt.sh — 证书透明度日志
# curl -s "https://crt.sh/?q=example.com&output=json"

# 备案信息查询 (国内)
# beian.miit.gov.cn
# https://icp.chinaz.com/

# 子域名枚举
# subfinder -d example.com
# amass enum -d example.com
# sublister -d example.com

# DNS 历史
# securitytrails.com — DNS 历史记录
# whois.domaintools.com — whois 历史
```

### Shodan / Censys 侦察

```bash
# Shodan (需 API key, 免费版有限)
# https://www.shodan.io
# shodan search "port:22 country:CN"
# shodan search "title:'TeamCity'"
# shodan host IP

# Censys (类似 Shodan)
# https://search.censys.io
# 搜索: ip, services, certificates

# 常见用法
# 1. 在 Shodan 查目标的 IP、开放端口、banner
# 2. 找目标使用的软件版本 → 关联 CVE
# 3. 查目标域名的证书 → 可能找到子域名
```

---

## 5) 反向图像搜索

### 引擎选择策略

| 引擎 | 优势 | 适用场景 |
|------|------|---------|
| **Google Images** | 覆盖面广 | 一般场景 |
| **TinEye** | 找原始出处/修改版本 | 验证图片是否经PS |
| **Yandex** | 俄系资源好 | 东欧/俄罗斯相关内容 |
| **百度识图** | 国内资源 | 中文互联网的内容 |
| **Bing Images** | 中间选择 | Google不可用时 |
| **Saucenao** | 动漫/二次元 | 动画/漫画/游戏截图 |

### Exif 元数据深入提取

```python
# 更完整的 Exif 提取
from PIL import Image
from PIL.ExifTags import TAGS

img = Image.open('photo.jpg')
exif = img.getexif()

for tag_id, value in exif.items():
    tag_name = TAGS.get(tag_id, tag_id)
    print(f"{tag_name:30}: {value}")

# MakerNote — 相机厂商特定信息
# 可能包含: 序列号、固件版本、设置
```

---

## 6) 数据泄露搜索

### 公开泄露数据源

```bash
# Dehashed — 搜索泄露数据库（需付费）
# https://dehashed.com

# Have I Been Pwned — 检查邮箱泄露
# https://haveibeenpwned.com

# Firefox Monitor — Mozilla的泄露检查
# https://monitor.firefox.com

# IntelX — 深网/暗网搜索
# https://intelx.io

# 搜索引擎搜索
# site:pastebin.com "password"
# site:github.com "password" "config"
# site:github.com "aws_access_key_id" "secret_access_key"
# site:gist.github.com "password" "username"
```

### 提取 AK/SK (Access Key / Secret Key)

```python
# 常见泄露模式
import re

text = """
AWS Access Key: AKIAIOSFODNN7EXAMPLE
AWS Secret Key: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""

# AWS Key 模式
ak_pattern = r'AKIA[0-9A-Z]{16}'
sk_pattern = r'(?i)(?:(?:aws|amazon)_?(?:secret|access)_?key|secret_key)[:\s]*["\']?([A-Za-z0-9+/=]{40})'

# GitHub Token
github_token = r'ghp_[A-Za-z0-9]{36}'

# 阿里云 AK
ali_ak = r'LTAI[0-9A-Za-z]{17,}'
ali_sk = r'(?i)(?:alibaba|aliyun)_?(?:secret|access)_?key[:\s]*["\']?([A-Za-z0-9+/=]{30,})'

# 腾讯云
txy_sk = r'AKID[0-9A-Za-z]{16,}'
```

---

## 7) 社交媒体深度挖掘

### Twitter/X 搜索

```bash
# 基本搜索语法
from:username              # 该用户发的
to:username                # 发给该用户的
@username                  # 提及该用户的
"exact phrase" near:city   # 精确短语+地点
since:2024-01-01           # 开始日期
until:2024-12-31           # 结束日期
filter:images              # 只含图片
min_faves:100              # 最低点赞
```

### 国内平台搜索

```bash
# 微博
# weibo.cn/weibo.com — 搜索用户名
# 高级搜索: 关键词 + 时间范围 + 地点

# 知乎
# zhihu.com/people/username — 用户主页
# 搜索用户回答/文章

# B站
# space.bilibili.com/用户ID — 用户主页
# 视频/评论/动态/收藏

# 抖音
# 用户名搜索 + 作品分析
# 定位（如果开启）

# 小红书
# 搜索用户/笔记/地点
# 图片反向搜索
```

---

## 8) 工具集

### 在线工具推荐

| 工具 | URL | 用途 |
|------|-----|------|
| What's My Name | https://whatsmyname.app | 用户名查重 |
| TinEye | https://tineye.com | 以图搜图 |
| crt.sh | https://crt.sh | 证书日志 |
| Wayback Machine | https://web.archive.org | 网页历史 |
| Shodan | https://www.shodan.io | 联网设备搜索 |
| Censys | https://search.censys.io | 互联网全景 |
| SecurityTrails | https://securitytrails.com | DNS历史 |
| Have I Been Pwned | https://haveibeenpwned.com | 泄露邮箱 |
| IntelX | https://intelx.io | 深网搜索 |
| suncalc | https://suncalc.org | 太阳位置 |
| GeoGuessr | https://geoguessr.com | 地理训练 |
| Geohints | https://geohints.com | 各地线索 |

### 本地工具安装

```bash
# Python 包
pip install exifread shodan dnspython dnslib
pip install theHarvester  # 邮箱/域名收集
pip install holehe         # 邮箱平台验证
pip install maigret        # 用户名搜索

# Kali 工具（如有Linux环境）
# apt install subfinder amass whois dnsutils
```

---

## 9) 综合解题流程

```
拿到图片/域名/用户名/描述
  ↓
  ├── 图片 → 检查Exif → GPS坐标?
  │    ├── 有GPS → 地图定位
  │    └── 无GPS → 环境分析(招牌/植被/建筑/影子)
  │         └── 反向图像搜索 → 匹配地标
  │
  ├── 域名/IP → whois → crt.sh
  │    ├── 注册人信息
  │    ├── 子域名枚举
  │    └── Shodan/Censys 端口扫描
  │
  ├── 用户名 → 查重搜索
  │    ├── 跨平台关联
  │    ├── 搜索引擎: site:github.com username
  │    └── 社交媒体profile
  │
  └── 文字描述 → 关键词提取
       ├── 地理位置搜索
       └── 人名/组织名关联
  ↓
  flag = 坐标/邮箱/电话/特定字符串
```

### 经典 OSINT CTF 出题模式

```
1. "帮我找到这张照片拍摄地的经纬度（精确到小数点后4位）"
   → 地理定位 → 坐标拼接 → flag{xxxxx,xxxxx}

2. "调查这个论坛ID @hack3r_2020 的真实信息"
   → 用户名查重 → 跨平台信息 → 找到注册邮箱 → flag

3. "分析这个网站背后的真实运营者"
   → whois → 备案信息 → 社保/工商系统 → 真实姓名

4. "这张照片中的地点在哪条街道上？"
   → 街景匹配 → 招牌识别 → 交叉路口 → flag

5. "这条Twitter的时间线中隐藏了什么？"
   → 时间分析 → 地点标签 → 图像元数据 → 联系信息
```

---

## 补充A: Google Dorks 专项语法表

Google Dorks 是 CTF OSINT 的神器，用于精确搜索暴露的敏感文件。

| 语法 | 用途 | CTF 示例 |
|------|------|------------|
| `site:` | 限定站点 | `site:github.com "aws_secret"` |
| `filetype:` | 文件类型 | `filetype:pdf "confidential"` |
| `inurl:` | URL包含 | `inurl:admin login` |
| `intitle:` | 标题包含 | `intitle:"index of" "backup"` |
| `intext:` | 正文包含 | `intext:"BEGIN RSA PRIVATE KEY"` |
| `cache:` | 缓存页 | `cache:example.com` |
| `link:` | 链接到 | `link:target.com` |
| `related:` | 相似站 | `related:example.com` |
| `OR` / `|` | 逻辑或 | `site:pastebin.com (password OR secret)` |
| `*` | 通配符 | `filetype:log "error" *2024*` |
| `..` | 数字范围 | `2020..2024` |

### CTF 高频 Dorks 组合
```bash
# 找备份文件
"index of" "backup" "zip"
"index of" "www.tar.gz"

# 找配置文件泄露
filetype:env "DB_PASSWORD"
filetype:json "api_key"
filetype:yaml "secret"

# 找日志/数据库导出
filetype:sql "INSERT INTO"
filetype:log "password"

# 找证书/密钥
"BEGIN PRIVATE KEY"
"ssh-rsa " filetype:pub

# 找内部文档
filetype:docx "internal use only"
filetype:pptx "confidential"

# GitHub 敏感信息
site:github.com "aws_access_key_id"
site:github.com "DB_HOST"
site:github.com "sendgrid" "api_key"

# 国内特定
site:edu.cn filetype:xls "学生名单"
site:gov.cn filetype:pdf "通知"
```

---

## 补充B: Maltego 使用入门

Maltego 是强大的图形化 OSINT 工具，适合关系分析。

### 安装与配置
```bash
# 社区版免费
# 下载: https://www.paterva.com/downloads.php
# 注册后获取许可证

# 在 Kali 中
apt install maltego
```

### CTF 常用 Transforms
| Transform | 用途 |
|-----------|------|
| **DNS from Domain** | 解析子域名 |
| **IP Address from DNS** | 域名转IP |
| **MX Records from Domain** | 邮件服务器 |
| **Email Addresses from Domain** | 提取邮箱 |
| **Files from Domain** | 搜索关联文件 |
| **Locations from Location** | 地理关联 |
| **Social Media from Person** | 社交账号 |

### 基本用法
1. 新建 Graph
2. 拖入 **Domain** 实体，输入目标域名
3. 右键 → Run Transform → **To DNS Names**
4. 继续展开：DNS → IP → Location
5. 使用 **Entity List** 批量导入用户名/邮箱

---

## 补充C: CTF 平台 OSINT 攻略

### TryHackMe (THM)
```
# 常见 OSINT 房间
- OSINT: Open Source Intelligence
- Sherlock: 用户名追踪
- Google Dorking
- Geolocating Challenges
- Social Media OSINT

# 技巧：THM 的 OSINT 通常有提示图片，注意 Exif + 反向搜索
```

### HackTheBox (HTB)
```
# OSINT 挑战通常在 "Challenges" → "Misc" 分类
# 特征：
- 给一个社交媒体账号，找真实信息
- 给一张照片，找拍摄地
- 给一个域名，找管理员邮箱

# 技巧：HTB 的 flag 格式通常是 flag{...} 或 HTB{...}
```

### OverTheWire / Natas
```
# Web 安全训练，但有些关卡涉及 OSINT
# 如：从源码/注释中找到管理员邮箱
```

---

## 补充D: 高级在线工具

### SpiderFoot (自动化OSINT)
```bash
# 安装
pip install spiderfoot

# 启动
python3 sf.py -l 127.0.0.1:5001
# 浏览器访问 http://127.0.0.1:5001

# 常用模块：
# - sfp_dns - DNS解析
# - sfp_whois - whois查询
# - sfp_shodan - Shodan查询
# - sfp_haveibeenpwned - 泄露检查
# - sfp_virustotal - VT查询
```

### VirusTotal Intelligence
```
# VT 不仅查文件哈希，还能：
# - 查 URL 报告
# - 查域名/IP 的解析历史
# - 搜索文件元数据中的字符串
# 语法: entity:domain example.com
#        entity:ip 1.2.3.4
#        tag:malicious
```

### Phone Number 反查
```bash
# TrueCaller (需注册)
# https://www.truecaller.com

# Sync.me
# https://sync.me

# 国内: 百度手机卫士/360手机卫士查询
```

### Tor .onion 服务查询
```bash
# Torch (搜索引擎)
# http://dqwzfqrm43g5b56x.onion/ (示例，可能会变)

# Ahmia
# https://ahmia.fi

# 需要 Tor Browser
# https://www.torproject.org
```

---

## 补充E: OSINT 实战小技巧

### 快速判断域名是否值得深挖
```python
import whois
import requests

def domain_score(domain):
    score = 0
    # 1. 注册时间（老域名更可能有关联信息）
    try:
        w = whois.whois(domain)
        if w.creation_date:
            if isinstance(w.creation_date, list):
                age = 2024 - w.creation_date[0].year
            else:
                age = 2024 - w.creation_date.year
            if age > 5: score += 2
    except: pass
    
    # 2. 是否有 HTTPS
    try:
        r = requests.get(f'https://{domain}', timeout=5)
        if r.status_code == 200: score += 1
    except: pass
    
    # 3. 子域名数量（多子域 = 大目标）
    # 可以用 subfinder 快速检查
    
    return score
```

### 从 GitHub 搜索泄露的自动化
```bash
# 使用 GitHub CLI
gh search code "password" --owner=target --limit 100

# 或使用 github-search Python 库
pip install github-search
```

---

## 更新后的解题流程（完整版）

```
拿到图片/域名/用户名/描述
  ↓
  ├── 图片 → 检查Exif → GPS坐标?
  │    ├── 有GPS → 地图定位
  │    └── 无GPS → 环境分析(招牌/植被/建筑/影子)
  │         ├── 反向图像搜索 (Google/TinEye/Yandex)
  │         └── 街景匹配 (Google Street View)
  │
  ├── 域名/IP → whois → crt.sh → Shodan/Censys
  │    ├── 注册人信息 → 邮箱 → 泄露检查
  │    ├── 子域名枚举 (subfinder/amass)
  │    └── 端口扫描 + 服务识别
  │
  ├── 用户名 → 查重搜索 (whatsmyname/holehe)
  │    ├── 跨平台关联 (GitHub/Twitter/Instagram)
  │    ├── 搜索引擎: site:github.com username
  │    └── 社交媒体 profile 深挖
  │
  ├── 邮箱 → 泄露检查 (HIBP/dehashed)
  │    ├── 关联域名/IP
  │    └── 密码复用检查
  │
  └── 文字描述 → Google Dorks 搜索
       ├── 地理位置关键词
       └── 人名/组织名关联
  ↓
  flag = 坐标/邮箱/电话/特定字符串
  
  # 工具选择:
  # - 快速: 在线工具 (whatsmyname, crt.sh, HIBP)
  # - 深度: Maltego / SpiderFoot
  # - 自动化: theHarvester + holehe + maigret
```
