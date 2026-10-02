"""yang_web.core.advanced_engines 子模块 _registry（自 advanced_engines.py 拆分，请勿手工重排）。"""

import re
import base64
import codecs
import struct
from typing import Optional, Tuple

from ._base9192 import (base91_decode, base91_encode, base92_decode, base92_encode)
from ._esoteric import (aaencode_decode, aaencode_encode, brainfuck_decode, brainfuck_encode, jjencode_decode, jjencode_encode, jsfuck_decode, jsfuck_encode, ook_decode, ook_encode)
from ._mailbin import (quoted_printable_decode, quoted_printable_encode, uudecode, uuencode, xxdecode, xxencode)
from ._misc import (punycode_decode, punycode_encode, shellcode_decode, shellcode_encode, utf7_decode, utf7_encode, zerowidth_decode, zerowidth_encode)
from ._rot import (rot18_decode, rot18_encode, rot47_decode, rot47_encode, rot5_decode, rot5_encode, rot8000_decode, rot8000_encode)



# ═══════════════════════════════════════════
# 编码注册表
# ═══════════════════════════════════════════

ADVANCED_ENCODERS = {
    # Brainfuck & variants
    'brainfuck': {
        'name': 'Brainfuck',
        'category': '编程语言编码',
        'encode': brainfuck_encode,
        'decode': brainfuck_decode,
        'desc': 'Brainfuck 编程语言解释器',
    },
    'ook': {
        'name': 'Ook!',
        'category': '编程语言编码',
        'encode': ook_encode,
        'decode': ook_decode,
        'desc': 'Ook! 语言 (Brainfuck 变体)',
    },
    'jsfuck': {
        'name': 'JSFuck',
        'category': '编程语言编码',
        'encode': jsfuck_encode,
        'decode': jsfuck_decode,
        'desc': 'JSFuck 编码 (仅用 []()!+ 字符)',
    },
    'aaencode': {
        'name': 'AAEncode',
        'category': '编程语言编码',
        'encode': aaencode_encode,
        'decode': aaencode_decode,
        'desc': 'AAEncode 颜文字 JS 编码',
    },
    'jjencode': {
        'name': 'JJEncode',
        'category': '编程语言编码',
        'encode': jjencode_encode,
        'decode': jjencode_decode,
        'desc': 'JJEncode 符号 JS 编码',
    },

    # Transfer encoding
    'quoted_printable': {
        'name': 'Quoted-Printable',
        'category': '传输编码',
        'encode': quoted_printable_encode,
        'decode': quoted_printable_decode,
        'desc': 'MIME Quoted-Printable 编码 (=XX格式)',
    },
    'uuencode': {
        'name': 'UUEncode',
        'category': '传输编码',
        'encode': uuencode,
        'decode': uudecode,
        'desc': 'Unix-to-Unix 编码',
    },
    'xxencode': {
        'name': 'XXEncode',
        'category': '传输编码',
        'encode': xxencode,
        'decode': xxdecode,
        'desc': 'XXEncode 编码 (+-字母表)',
    },

    # Unicode & character encoding
    'utf7': {
        'name': 'UTF-7',
        'category': '字符编码',
        'encode': utf7_encode,
        'decode': utf7_decode,
        'desc': 'UTF-7 字符编码',
    },
    'zerowidth': {
        'name': '零宽字符',
        'category': '隐写编码',
        'encode': zerowidth_encode,
        'decode': zerowidth_decode,
        'desc': '零宽字符隐写 (U+200B/C/D/FEFF)',
    },
    'punycode': {
        'name': 'Punycode',
        'category': '域名编码',
        'encode': punycode_encode,
        'decode': punycode_decode,
        'desc': 'Punycode/IDNA 国际化域名编码',
    },

    # Base extensions
    'base91': {
        'name': 'Base91',
        'category': 'Base 编码',
        'encode': base91_encode,
        'decode': base91_decode,
        'desc': 'Base91 编码 (91字符集)',
    },
    'base92': {
        'name': 'Base92',
        'category': 'Base 编码',
        'encode': base92_encode,
        'decode': base92_decode,
        'desc': 'Base92 编码 (几乎所有可打印字符)',
    },

    # Shellcode
    'shellcode': {
        'name': 'Shellcode \\x',
        'category': 'Hex 编码',
        'encode': shellcode_encode,
        'decode': shellcode_decode,
        'desc': 'Shellcode \\x 十六进制格式',
    },

    # ROT family
    'rot47': {
        'name': 'ROT47',
        'category': 'ROT 编码',
        'encode': rot47_encode,
        'decode': rot47_decode,
        'desc': 'ROT47 (所有可打印 ASCII 旋转)',
    },
    'rot5': {
        'name': 'ROT5',
        'category': 'ROT 编码',
        'encode': rot5_encode,
        'decode': rot5_decode,
        'desc': 'ROT5 (仅数字旋转)',
    },
    'rot18': {
        'name': 'ROT18',
        'category': 'ROT 编码',
        'encode': rot18_encode,
        'decode': rot18_decode,
        'desc': 'ROT18 (ROT13 + ROT5)',
    },
    'rot8000': {
        'name': 'ROT8000',
        'category': 'ROT 编码',
        'encode': rot8000_encode,
        'decode': rot8000_decode,
        'desc': 'ROT8000 Unicode BMP 旋转',
    },
}


def list_advanced():
    """列出所有高级编码器。"""
    return [(eid, info['name'], info['category'], info['desc']) for eid, info in ADVANCED_ENCODERS.items()]


def get_advanced_encoder(enc_id: str) -> dict:
    """获取指定编码器的配置。"""
    return ADVANCED_ENCODERS.get(enc_id.lower())
