"""yang_web.core.decoder 子模块 _det_special（自 decoder.py 拆分，请勿手工重排）。"""

import re
import base64
import binascii
import string
import html as html_mod
import codecs
from typing import Optional, List, Tuple, Callable
from ..utils import is_printable, text_quality
from ..advanced_engines import (
    brainfuck_decode, ook_decode,
    quoted_printable_decode, uudecode, xxdecode,
    utf7_decode, punycode_decode, shellcode_decode,
    base91_decode, base92_decode,
    rot47_decode, rot5_decode, rot18_decode,
)
from ..chinese_ciphers import (
    _decode_buddha, core_values_decode, beast_decode,
    bear_decode, surnames_decode, telegraph_decode,
)




# ═══════════════════════════════════════════════════════════
#  编码检测函数 — 返回置信度 0-100
# ═══════════════════════════════════════════════════════════

def _is_buddha(text: str) -> int:
    """与佛论禅检测."""
    if '佛曰' in text or '佛曰' in text:
        return 90
    return 0

def _is_core_values(text: str) -> int:
    """核心价值观检测."""
    cores = ['富强','民主','文明','和谐','自由','平等','公正','法治','爱国','敬业','诚信','友善']
    count = sum(1 for c in cores if c in text)
    if count >= 2:
        return min(85, count * 25)
    return 0

def _is_beast(text: str) -> int:
    """兽音检测."""
    beast_chars = set('嗷呜啊~')
    filtered = [c for c in text if c in beast_chars]
    if len(filtered) < 4:
        return 0
    ratio = len(filtered) / max(len(text), 1)
    if ratio > 0.6:
        return int(ratio * 90)
    return 0

def _is_bear(text: str) -> int:
    """熊曰检测."""
    if '熊曰' in text:
        return 90
    return 0

def _is_surnames(text: str) -> int:
    """百家姓检测."""
    surnames_set = set('赵钱孙李周吴郑王冯陈褚卫蒋沈韩杨朱秦尤许何吕施张孔曹严华金魏陶姜戚谢邹喻柏水窦章云苏潘葛奚范彭郎鲁韦昌马苗凤花方俞任袁柳酆鲍史唐费廉岑薛雷贺倪汤滕殷罗毕郝邬安常乐于时傅皮下齐康伍余元卜顾孟平黄')
    filtered = [c for c in text if c in surnames_set]
    if len(filtered) < 2:
        return 0
    ratio = len(filtered) / max(len(text), 1)
    if ratio > 0.5:
        return int(ratio * 90)
    return 0

def _is_telegraph(text: str) -> int:
    """中文电码检测."""
    import re
    codes = re.findall(r'\b\d{4}\b', text.strip())
    if len(codes) >= 2:
        return 85
    return 0


def _is_quoted_printable(text: str) -> int:
    """Detect Quoted-Printable (=XX format)."""
    text = text.strip()
    # Count =XX hex patterns
    matches = re.findall(r'=[0-9A-Fa-f]{2}', text)
    if len(matches) < 2:
        return 0
    # Check ratio of encoded content
    encoded_len = len(''.join(matches))
    ratio = encoded_len / max(len(text), 1)
    # QP signature: 3 chars per byte (=XX), so high density
    if ratio > 0.55:  # >= 3 out of every ~5 chars are =XX
        return 95
    if ratio > 0.30:
        # Make sure it's not just base64 with random = signs
        if text.count('=') >= 3 and all(c in '0123456789ABCDEFabcdef=' for c in text):
            return 90
        return 80
    return 0

def _is_uuencode(text: str) -> int:
    """Detect UUEncode format."""
    lines = text.strip().split('\n')
    if len(lines) < 2:
        return 0
    has_begin = any('begin' in l.lower() for l in lines[:2])
    has_end = any('end' in l.lower() for l in lines[-2:])
    has_len_byte = False
    for l in lines:
        l = l.strip()
        if l and 32 <= ord(l[0]) <= 96 and l[0] not in 'M':
            has_len_byte = True
            break
    if has_begin and has_end:
        return 90
    if has_len_byte and has_begin:
        return 75
    return 0

def _is_xxencode(text: str) -> int:
    """Detect XXEncode format."""
    lines = text.strip().split('\n')
    if len(lines) < 2:
        return 0
    has_begin = any('begin' in l.lower() for l in lines[:2])
    has_len_byte = False
    xx_chars = set('+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')
    for l in lines:
        l = l.strip()
        if l and 32 <= ord(l[0]) <= 96:
            # Check if line body uses XXEncode alphabet
            body = l[1:]
            if body and all(c in xx_chars for c in body[:min(20, len(body))]):
                has_len_byte = True
                break
    if has_begin and has_len_byte:
        return 85
    if has_len_byte and text.strip().endswith('+'):
        return 70
    return 0

def _is_brainfuck(text: str) -> int:
    """Detect Brainfuck code."""
    bf_chars = set('><+-.,[]')
    clean = ''.join(c for c in text if not c.isspace())
    if not clean:
        return 0
    ratio = sum(1 for c in clean if c in bf_chars) / len(clean)
    if ratio > 0.95 and any(c in clean for c in '[]'):
        return 95
    if ratio > 0.9 and len(clean) >= 10:
        return 80
    return 0

def _is_ook(text: str) -> int:
    """Detect Ook! language."""
    clean = text.strip()
    tokens = clean.split()
    if len(tokens) < 4:
        return 0
    ook_tokens = {'Ook.', 'Ook?', 'Ook!'}
    matches = sum(1 for t in tokens if t in ook_tokens)
    if matches >= len(tokens) * 0.8:
        return 95
    if matches >= 4:
        return 75
    return 0

def _is_utf7(text: str) -> int:
    """Detect UTF-7 encoded text."""
    text = text.strip()
    # UTF-7 uses +XXX- patterns where XXX is base64
    if '+ADw-' in text or '+AD4-' in text:
        return 90
    matches = re.findall(r'\+[A-Za-z0-9+/]+-', text)
    if matches and len(text) > 5:
        return 80
    return 0

def _is_zerowidth(text: str) -> int:
    """Detect zero-width character encoding."""
    zw_chars = {'\u200b', '\u200c', '\u200d', '\ufeff'}
    count = sum(1 for c in text if c in zw_chars)
    if count >= 4:
        return 95
    if count >= 2:
        return 75
    return 0

def _is_punycode(text: str) -> int:
    """Detect Punycode/IDNA encoding."""
    if 'xn--' in text.lower():
        if '.' in text:
            return 90
        return 80
    return 0

def _is_shellcode(text: str) -> int:
    """Detect shellcode \\x format."""
    hex_pairs = re.findall(r'\\x[0-9a-fA-F]{2}', text)
    if len(hex_pairs) >= 4:
        ratio = len(''.join(hex_pairs)) / max(len(text), 1)
        if ratio > 0.4:
            return 95
        return 80
    if len(hex_pairs) >= 2 and len(text) < 40:
        return 60
    return 0
