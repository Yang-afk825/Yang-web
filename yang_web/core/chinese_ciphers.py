# -*- coding: utf-8 -*-
"""CTF Chinese specialty ciphers — 中文特色密码引擎.

Includes:
    - 与佛论禅 (Buddha cipher) — convert text to Buddhist scripture style
    - 核心价值观 (Core Socialist Values) — map text to socialist values
    - 兽音 (Beast sound) — roar~ based encoding
    - 熊曰 (Bear says) — custom encoding
    - 百家姓 (Hundred family surnames) — surname mapping
    - 中文电码 (Chinese telegraph code) — 4-digit code for Chinese chars
"""
import base64


# ═══════════════════════════════════════════
# 1. 与佛论禅 (Buddha Cipher)
# ═══════════════════════════════════════════

BUDDHA_CHARS = "佛曰蘇梵吽哞嘛呢叭咪吽"


def _encode_buddha(text: str) -> str:
    """与佛论禅编码 - 将文本转为佛经格式."""
    # 简化版: 将base64转为特定格式
    encoded = base64.b64encode(text.encode('utf-8')).decode('ascii')
    return f"佛曰: {encoded} 如是我闻"


def _decode_buddha(cipher: str) -> str:
    """与佛论禅解码."""
    # Try extracting base64 from buddha text
    import re
    # Extract base64-like content
    match = re.search(r'佛曰[:：]\s*([A-Za-z0-9+/=]+)', cipher)
    if match:
        try:
            return base64.b64decode(match.group(1)).decode('utf-8', errors='replace')
        except Exception:
            pass
    # Try direct base64 on content between 佛曰 and 如是我闻
    match = re.search(r'佛曰[:：](.+?)如是我闻', cipher, re.DOTALL)
    if match:
        try:
            content = match.group(1).strip()
            return base64.b64decode(content + '==').decode('utf-8', errors='replace')
        except Exception:
            pass
    return "[!] 与佛论禅解码失败。请确认格式: 佛曰: <base64> 如是我闻"


# ═══════════════════════════════════════════
# 2. 核心价值观 (Core Socialist Values)
# ═══════════════════════════════════════════

CORE_VALUES = [
    "富强", "民主", "文明", "和谐",
    "自由", "平等", "公正", "法治",
    "爱国", "敬业", "诚信", "友善",
]


def core_values_encode(text: str) -> str:
    """核心价值观编码：将文本映射为核心价值观词汇。"""
    data = text.encode('utf-8')
    result = []
    for byte in data:
        high = byte >> 4
        low = byte & 0x0F
        if high < len(CORE_VALUES) and low < len(CORE_VALUES):
            result.append(f"{CORE_VALUES[high]}{CORE_VALUES[low]}")
        else:
            result.append(f"[{byte}]")
    return ' '.join(result)


def core_values_decode(cipher: str) -> str:
    """核心价值观解码。"""
    import re
    # Find all 核心价值观 pairs
    words = re.findall(r'[富民主文和明谐自平公治法爱敬诚友]{2}', cipher)
    result = bytearray()
    for i in range(0, len(words) - 1, 2):
        if i + 1 < len(words):
            try:
                high = CORE_VALUES.index(words[i])
                low = CORE_VALUES.index(words[i + 1])
                result.append((high << 4) | low)
            except ValueError:
                pass
    return bytes(result).decode('utf-8', errors='replace') if result else "[!] 解码失败"


# ═══════════════════════════════════════════
# 3. 兽音 (Beast Sound Cipher)
# ═══════════════════════════════════════════

BEAST_SOUNDS = ['嗷', '呜', '啊', '~']  # 00, 01, 10, 11


def beast_encode(text: str) -> str:
    """兽音编码：将文本转为"嗷呜啊~"格式。"""
    data = text.encode('utf-8')
    result = []
    for byte in data:
        for shift in [6, 4, 2, 0]:
            idx = (byte >> shift) & 0x03
            result.append(BEAST_SOUNDS[idx])
    return ''.join(result)


def beast_decode(cipher: str) -> str:
    """兽音解码。"""
    # Filter only beast sound chars
    chars = [c for c in cipher if c in BEAST_SOUNDS]
    result = bytearray()
    for i in range(0, len(chars) - 3, 4):
        byte_val = 0
        for j in range(4):
            try:
                byte_val = (byte_val << 2) | BEAST_SOUNDS.index(chars[i + j])
            except (IndexError, ValueError):
                break
        else:
            result.append(byte_val)
    return bytes(result).decode('utf-8', errors='replace') if result else "[!] 解码失败"


# ═══════════════════════════════════════════
# 4. 熊曰 (Bear Says Cipher)
# ═══════════════════════════════════════════

BEAR_PREFIX = "熊曰"


def bear_encode(text: str) -> str:
    """熊曰编码：将文本编码为熊曰格式。"""
    encoded = base64.b64encode(text.encode('utf-8')).decode('ascii')
    return f"{BEAR_PREFIX}: {encoded}"


def bear_decode(cipher: str) -> str:
    """熊曰解码。"""
    import re
    match = re.search(r'熊曰[:：]\s*([A-Za-z0-9+/=]+)', cipher)
    if match:
        try:
            return base64.b64decode(match.group(1) + '==').decode('utf-8', errors='replace')
        except Exception:
            pass
    return "[!] 熊曰解码失败"


# ═══════════════════════════════════════════
# 5. 百家姓 (Hundred Family Surnames)
# ═══════════════════════════════════════════

# Abbreviated table - maps numbers to common surnames
SURNAMES = {
    0: '赵', 1: '钱', 2: '孙', 3: '李', 4: '周', 5: '吴', 6: '郑', 7: '王',
    8: '冯', 9: '陈', 10: '褚', 11: '卫', 12: '蒋', 13: '沈', 14: '韩', 15: '杨',
    16: '朱', 17: '秦', 18: '尤', 19: '许', 20: '何', 21: '吕', 22: '施', 23: '张',
    24: '孔', 25: '曹', 26: '严', 27: '华', 28: '金', 29: '魏', 30: '陶', 31: '姜',
    32: '戚', 33: '谢', 34: '邹', 35: '喻', 36: '柏', 37: '水', 38: '窦', 39: '章',
    40: '云', 41: '苏', 42: '潘', 43: '葛', 44: '奚', 45: '范', 46: '彭', 47: '郎',
    48: '鲁', 49: '韦', 50: '昌', 51: '马', 52: '苗', 53: '凤', 54: '花', 55: '方',
    56: '俞', 57: '任', 58: '袁', 59: '柳', 60: '酆', 61: '鲍', 62: '史', 63: '唐',
    64: '费', 65: '廉', 66: '岑', 67: '薛', 68: '雷', 69: '贺', 70: '倪', 71: '汤',
    72: '滕', 73: '殷', 74: '罗', 75: '毕', 76: '郝', 77: '邬', 78: '安', 79: '常',
    80: '乐', 81: '于', 82: '时', 83: '傅', 84: '皮', 85: '卞', 86: '齐', 87: '康',
    88: '伍', 89: '余', 90: '元', 91: '卜', 92: '顾', 93: '孟', 94: '平', 95: '黄',
}

SURNAMES_REV = {v: k for k, v in SURNAMES.items()}


def surnames_encode(text: str) -> str:
    """百家姓编码：将文本转为姓氏序列。"""
    data = text.encode('utf-8')
    result = []
    for byte in data:
        if byte in SURNAMES:
            result.append(SURNAMES[byte])
        else:
            result.append(f'[{byte}]')
    return ''.join(result)


def surnames_decode(cipher: str) -> str:
    """百家姓解码。"""
    result = bytearray()
    for c in cipher:
        if c in SURNAMES_REV:
            result.append(SURNAMES_REV[c])
    return bytes(result).decode('utf-8', errors='replace') if result else "[!] 解码失败"


# ═══════════════════════════════════════════
# 6. 中文电码 (Chinese Telegraph Code)
# ═══════════════════════════════════════════

# Abbreviated telegraph code table (most common chars)
TELEGRAPH_CODE = {
    '一': '0001', '丁': '0002', '七': '0003', '万': '0004', '丈': '0005',
    '三': '0006', '上': '0007', '下': '0008', '不': '0009', '与': '0010',
    '中': '0022', '主': '0031', '义': '5030', '为': '3634',
    '人': '0086', '们': '0226', '从': '1780', '以': '0110',
    '你': '0132', '我': '2053', '他': '0115', '她': '1247', '它': '1338',
    '是': '2508', '的': '4104', '了': '0055', '在': '0961',
    '有': '2589', '和': '0735', '就': '1432', '也': '0048',
    '这': '6638', '那': '6719', '到': '0451', '说': '6141',
    '国': '0948', '家': '1367', '爱': '1947', '学': '1331',
    '大': '1129', '小': '1420', '天': '1131', '地': '0966',
    '日': '2480', '月': '2588', '年': '1628', '时': '2514',
    '工': '1562', '作': '0155', '用': '3938', '能': '5174',
    '行': '5887', '生': '3932', '会': '2585', '出': '0427',
    '好': '1170', '来': '0171', '对': '1417', '要': '6008',
    '开': '7030', '关': '7070', '发': '4099', '动': '0520',
    '网': '4988', '络': '4827', '安': '1344', '全': '0356',
    '密': '1378', '码': '4316', '破': '4273', '解': '6043',
    '数': '2422', '据': '5107', '通': '6639', '信': '0207',
    '加': '0502', '解': '6043',
    '0': '9960', '1': '9961', '2': '9962', '3': '9963', '4': '9964',
    '5': '9965', '6': '9966', '7': '9967', '8': '9968', '9': '9969',
    'A': '9874', 'B': '9875', 'C': '9876', 'D': '9877',
    'E': '9878', 'F': '9879', 'G': '9880', 'H': '9881',
    'I': '9882', 'J': '9883', 'K': '9884', 'L': '9885',
    'M': '9886', 'N': '9887', 'O': '9888', 'P': '9889',
    'Q': '9890', 'R': '9891', 'S': '9892', 'T': '9893',
    'U': '9894', 'V': '9895', 'W': '9896', 'X': '9897',
    'Y': '9898', 'Z': '9899',
}

TELEGRAPH_REV = {v: k for k, v in TELEGRAPH_CODE.items()}


def telegraph_encode(text: str) -> str:
    """中文电码编码：将文本转为4位数字电码。"""
    result = []
    for c in text:
        if c in TELEGRAPH_CODE:
            result.append(TELEGRAPH_CODE[c])
        else:
            result.append(f'[{c}]')
    return ' '.join(result)


def telegraph_decode(cipher: str) -> str:
    """中文电码解码。"""
    import re
    codes = re.findall(r'\b\d{4}\b', cipher)
    result = []
    for code in codes:
        if code in TELEGRAPH_REV:
            result.append(TELEGRAPH_REV[code])
        else:
            result.append(f'[{code}]')
    return ''.join(result)


# ═══════════════════════════════════════════
# 7. 盲水印 (Blind Watermark via DCT) - 需要 opencv
# ═══════════════════════════════════════════

def blind_watermark_hint(text: str = "") -> str:
    """盲水印提示信息。"""
    return '\n'.join([
        '[!] 盲水印需要安装 opencv-python',
        '',
        '📦 安装: pip install opencv-python',
        '📝 然后可用 OpenClaw skill 或在线工具处理',
        '🔗 推荐在线工具: https://github.com/guofei9987/blind_watermark',
    ])


# ═══════════════════════════════════════════
# 注册表
# ═══════════════════════════════════════════

CHINESE_CIPHERS = {
    'buddha': {
        'name': '与佛论禅',
        'category': '中文特色密码',
        'encode': _encode_buddha,
        'decode': _decode_buddha,
        'desc': '将文本编码为佛经格式（佛曰: ...）',
    },
    'core_values': {
        'name': '核心价值观',
        'category': '中文特色密码',
        'encode': core_values_encode,
        'decode': core_values_decode,
        'desc': '用社会主义核心价值观词汇编码数据',
    },
    'beast': {
        'name': '兽音',
        'category': '中文特色密码',
        'encode': beast_encode,
        'decode': beast_decode,
        'desc': '嗷呜啊~ 兽音编码',
    },
    'bear': {
        'name': '熊曰',
        'category': '中文特色密码',
        'encode': bear_encode,
        'decode': bear_decode,
        'desc': '熊曰格式编码',
    },
    'surnames': {
        'name': '百家姓',
        'category': '中文特色密码',
        'encode': surnames_encode,
        'decode': surnames_decode,
        'desc': '用百家姓姓氏映射编码',
    },
    'telegraph': {
        'name': '中文电码',
        'category': '中文特色密码',
        'encode': telegraph_encode,
        'decode': telegraph_decode,
        'desc': '4位数字中文电码编码',
    },
}


def get_chinese_ciphers():
    """返回所有中文特色密码列表。"""
    return [(cid, info['name'], info['category'], info['desc']) for cid, info in CHINESE_CIPHERS.items()]
