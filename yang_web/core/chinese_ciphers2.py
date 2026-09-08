# -*- coding: utf-8 -*-
"""chinese_ciphers2.py — 中文特色密码第二批（对照随波逐流 V8.0 补齐）

包含：
  - 元素周期表 (periodic table) — 元素符号 ↔ 原子序数 ↔ ASCII
  - 天干地支 (heavenly stems) — 60 甲子 ↔ 字节
  - 八卦符 (bagua) — 先天八卦 ☰☱☲☳☴☵☶☷ ↔ 3bit
  - 伏羲六十四卦 (hexagram) — Unicode 卦符 U+4DC0 ↔ 6bit
  - 元音密码 (vowel cipher) — aeiou 五进制 ↔ 字节

纯 Python 标准库零依赖，API 与 cipher_classic / cipher_keyed 一致。
"""

# ═══════════════════════════════════════════
# 1. 元素周期表
# ═══════════════════════════════════════════

ELEMENTS = [
    "H", "He", "Li", "Be", "B", "C", "N", "O", "F", "Ne",
    "Na", "Mg", "Al", "Si", "P", "S", "Cl", "Ar", "K", "Ca",
    "Sc", "Ti", "V", "Cr", "Mn", "Fe", "Co", "Ni", "Cu", "Zn",
    "Ga", "Ge", "As", "Se", "Br", "Kr", "Rb", "Sr", "Y", "Zr",
    "Nb", "Mo", "Tc", "Ru", "Rh", "Pd", "Ag", "Cd", "In", "Sn",
    "Sb", "Te", "I", "Xe", "Cs", "Ba", "La", "Ce", "Pr", "Nd",
    "Pm", "Sm", "Eu", "Gd", "Tb", "Dy", "Ho", "Er", "Tm", "Yb",
    "Lu", "Hf", "Ta", "W", "Re", "Os", "Ir", "Pt", "Au", "Hg",
    "Tl", "Pb", "Bi", "Po", "At", "Rn", "Fr", "Ra", "Ac", "Th",
    "Pa", "U", "Np", "Pu", "Am", "Cm", "Bk", "Cf", "Es", "Fm",
    "Md", "No", "Lr", "Rf", "Db", "Sg", "Bh", "Hs", "Mt", "Ds",
    "Rg", "Cn", "Nh", "Fl", "Mc", "Lv", "Ts", "Og",
]


def _split_syms(token: str) -> list:
    """把元素符号串切割成符号列表（大写开头 + 可选小写），0 保留。"""
    syms = []
    i = 0
    while i < len(token):
        ch = token[i]
        if ch == '0':
            syms.append('0')
            i += 1
        elif ch.isupper():
            if i + 1 < len(token) and token[i + 1].islower():
                syms.append(token[i:i + 2])
                i += 2
            else:
                syms.append(ch)
                i += 1
        else:
            i += 1
    return syms


def periodic_table_encode(text: str) -> str:
    """文本 → 数字串（贪心切 1-118）→ 元素符号。字符间用空格分隔。"""
    result = []
    for ch in text:
        digits = str(ord(ch))
        syms = []
        i = 0
        while i < len(digits):
            if i + 3 <= len(digits) and digits[i] != '0' and 100 <= int(digits[i:i + 3]) <= 118:
                syms.append(ELEMENTS[int(digits[i:i + 3]) - 1])
                i += 3
            elif i + 2 <= len(digits) and digits[i] != '0' and int(digits[i:i + 2]) >= 10:
                syms.append(ELEMENTS[int(digits[i:i + 2]) - 1])
                i += 2
            elif digits[i] != '0':
                syms.append(ELEMENTS[int(digits[i]) - 1])
                i += 1
            else:
                syms.append('0')
                i += 1
        result.append(''.join(syms))
    return ' '.join(result)


def periodic_table_decode(cipher: str) -> str:
    """元素符号 → 原子序数 → 数字串 → ASCII。"""
    out = []
    for token in cipher.split():
        digits = ''
        for s in _split_syms(token):
            if s == '0':
                digits += '0'
            elif s in ELEMENTS:
                digits += str(ELEMENTS.index(s) + 1)
        if digits:
            out.append(chr(int(digits)))
    return ''.join(out)


# ═══════════════════════════════════════════
# 2. 天干地支
# ═══════════════════════════════════════════

TIANGAN = "甲乙丙丁戊己庚辛壬癸"
DIZHI = "子丑寅卯辰巳午未申酉戌亥"


def _ganzhi(n: int) -> str:
    return TIANGAN[n % 10] + DIZHI[n % 12]


def _ganzhi_num(gz: str) -> int:
    if len(gz) < 2:
        return -1
    ti, di = TIANGAN.index(gz[0]), DIZHI.index(gz[1])
    for n in range(60):
        if n % 10 == ti and n % 12 == di:
            return n
    return -1


def heavenly_stems_encode(text: str) -> str:
    out = []
    for b in text.encode('utf-8'):
        hi, lo = divmod(b, 60)
        out.append(_ganzhi(hi) + _ganzhi(lo))
    return ''.join(out)


def heavenly_stems_decode(cipher: str) -> str:
    out = bytearray()
    for i in range(0, len(cipher) - 3, 4):
        hi = _ganzhi_num(cipher[i:i + 2])
        lo = _ganzhi_num(cipher[i + 2:i + 4])
        if hi >= 0 and lo >= 0:
            out.append(hi * 60 + lo)
    return out.decode('utf-8', errors='replace')


# ═══════════════════════════════════════════
# 3. 八卦符（先天八卦）
# ═══════════════════════════════════════════

# 索引 = 3bit 二进制值（000-111）
BAGUA_SYMBOLS = "☷☶☵☴☳☲☱☰"          # 坤艮坎巽震离兑乾
BAGUA_HANZI = "坤艮坎巽震离兑乾"
_BAGUA_LOOKUP = {s: i for i, s in enumerate(BAGUA_SYMBOLS)}
_BAGUA_LOOKUP.update({h: i for i, h in enumerate(BAGUA_HANZI)})


def bagua_encode(text: str) -> str:
    data = text.encode('utf-8')
    bits = ''.join(f'{b:08b}' for b in data)
    while len(bits) % 3:
        bits += '0'
    return ''.join(BAGUA_SYMBOLS[int(bits[i:i + 3], 2)] for i in range(0, len(bits), 3))


def bagua_decode(cipher: str) -> str:
    bits = ''
    for c in cipher:
        if c in _BAGUA_LOOKUP:
            bits += f'{_BAGUA_LOOKUP[c]:03b}'
    out = bytearray()
    for i in range(0, len(bits), 8):
        out.append(int(bits[i:i + 8], 2))
    return out.decode('utf-8', errors='replace')


# ═══════════════════════════════════════════
# 4. 伏羲六十四卦（Unicode U+4DC0-4DFF）
# ═══════════════════════════════════════════

def hexagram_encode(text: str) -> str:
    data = text.encode('utf-8')
    bits = ''.join(f'{b:08b}' for b in data)
    while len(bits) % 6:
        bits += '0'
    return ''.join(chr(0x4DC0 + int(bits[i:i + 6], 2)) for i in range(0, len(bits), 6))


def hexagram_decode(cipher: str) -> str:
    bits = ''
    for c in cipher:
        cp = ord(c)
        if 0x4DC0 <= cp <= 0x4DFF:
            bits += f'{cp - 0x4DC0:06b}'
    out = bytearray()
    for i in range(0, len(bits), 8):
        out.append(int(bits[i:i + 8], 2))
    return out.decode('utf-8', errors='replace')


# ═══════════════════════════════════════════
# 5. 元音密码（aeiou 五进制）
# ═══════════════════════════════════════════

VOWELS = "aeiou"


def vowel_cipher_encode(text: str) -> str:
    out = []
    for b in text.encode('utf-8'):
        s = ''
        v = b
        for _ in range(4):
            s = VOWELS[v % 5] + s
            v //= 5
        out.append(s)
    return ''.join(out)


def vowel_cipher_decode(cipher: str) -> str:
    s = ''.join(c for c in cipher.lower() if c in VOWELS)
    out = bytearray()
    for i in range(0, len(s) - 3, 4):
        v = 0
        for c in s[i:i + 4]:
            v = v * 5 + VOWELS.index(c)
        out.append(v)
    return out.decode('utf-8', errors='replace')


# ═══════════════════════════════════════════
# 注册表
# ═══════════════════════════════════════════

CIPHERS = {
    "periodic_table": {"name": "元素周期表", "aliases": ["periodic_table", "元素周期表", "element", "periodic"], "category": "中文特色密码"},
    "heavenly_stems": {"name": "天干地支", "aliases": ["heavenly_stems", "天干地支", "ganzhi", "甲子"], "category": "中文特色密码"},
    "bagua": {"name": "八卦符", "aliases": ["bagua", "八卦", "bagua_symbols"], "category": "中文特色密码"},
    "hexagram": {"name": "伏羲六十四卦", "aliases": ["hexagram", "六十四卦", "hexagram64"], "category": "中文特色密码"},
    "vowel_cipher": {"name": "元音密码", "aliases": ["vowel_cipher", "元音密码", "vowel"], "category": "中文特色密码"},
}

_FUNCS = {
    "periodic_table": (periodic_table_encode, periodic_table_decode),
    "heavenly_stems": (heavenly_stems_encode, heavenly_stems_decode),
    "bagua": (bagua_encode, bagua_decode),
    "hexagram": (hexagram_encode, hexagram_decode),
    "vowel_cipher": (vowel_cipher_encode, vowel_cipher_decode),
}


def _norm(cipher_id: str) -> str:
    cid = cipher_id.lower().replace('-', '_').replace(' ', '_')
    alias_map = {}
    for cid_key, info in CIPHERS.items():
        for a in info.get("aliases", []):
            alias_map[a.lower().replace('-', '_').replace(' ', '_')] = cid_key
    return alias_map.get(cid, cid)


def encode(cipher_id: str, text: str, key: str = "", **kwargs) -> str:
    cid = _norm(cipher_id)
    if cid in _FUNCS:
        return _FUNCS[cid][0](text)
    return f"[!] 不支持编码: {cipher_id}"


def decode(cipher_id: str, cipher_text: str, key: str = "", **kwargs) -> str:
    cid = _norm(cipher_id)
    if cid in _FUNCS:
        return _FUNCS[cid][1](cipher_text)
    return f"[!] 不支持解码: {cipher_id}"


def list_ciphers(category: str = None) -> list:
    result = []
    for cid, info in CIPHERS.items():
        if category and info.get("category") != category:
            continue
        result.append({"id": cid, **info})
    return result


def get_cipher(cipher_id: str) -> dict:
    return CIPHERS.get(_norm(cipher_id))


def search_ciphers(query: str) -> list:
    q = query.lower()
    out = []
    for cid, info in CIPHERS.items():
        text = cid + " " + info["name"] + " " + " ".join(info.get("aliases", [])) + " " + info["category"]
        if q in text.lower():
            out.append({"id": cid, **info})
    return out


def get_categories() -> list:
    return sorted({info["category"] for info in CIPHERS.values()})
