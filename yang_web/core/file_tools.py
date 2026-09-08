# -*- coding: utf-8 -*-
"""file_tools.py — 文件分析/隐写工具（纯 Python 零依赖）

包含：
  - file_magic   — 文件签名（magic bytes）识别
  - zip_analyze  — ZIP 分析（列表/加密/伪加密检测/注释）
  - file_carve   — 文件雕刻（从文件中提取嵌入文件，binwalk 式）
  - bin_text     — 二进制串提取（strings 式）

API 与 shell_stego.py 一致：函数接受 bytes / 文件路径，返回人类可读文本。
"""
import io
import os
import re
import struct
import zipfile


# ═══════════════════════════════════════════
# magic bytes 签名库
# ═══════════════════════════════════════════

MAGIC_SIGNATURES = [
    (b'\x89PNG\r\n\x1a\n', 'PNG image'),
    (b'\xff\xd8\xff', 'JPEG image'),
    (b'GIF87a', 'GIF image (87a)'),
    (b'GIF89a', 'GIF image (89a)'),
    (b'PK\x03\x04', 'ZIP archive'),
    (b'PK\x05\x06', 'ZIP (empty archive)'),
    (b'PK\x07\x08', 'ZIP (spanned archive)'),
    (b'%PDF', 'PDF document'),
    (b'\x7fELF', 'ELF executable'),
    (b'MZ', 'PE executable (Windows)'),
    (b'Rar!\x1a\x07\x01\x00', 'RAR archive (v5)'),
    (b'Rar!\x1a\x07\x00', 'RAR archive (v4)'),
    (b'7z\xbc\xaf\x27\x1c', '7z archive'),
    (b'BZh', 'BZip2 compressed'),
    (b'\x1f\x8b\x08', 'GZip compressed'),
    (b'\xfd7zXZ\x00', 'XZ compressed'),
    (b'\x04\x22\x4d\x18', 'LZ4 compressed'),
    (b'SQLite format 3\x00', 'SQLite database'),
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'OLE2 (doc/xls/ppt/msi)'),
    (b'\x00\x01\x00\x00\x00', 'TTF font'),
    (b'OTTO', 'OTF font'),
    (b'ID3', 'MP3 (ID3 tag)'),
    (b'\xff\xfb', 'MP3 (MPEG audio)'),
    (b'OggS', 'Ogg container (audio/video)'),
    (b'fLaC', 'FLAC audio'),
    (b'RIFF', 'RIFF (wav/avi/webp)'),
    (b'BM', 'BMP image'),
    (b'\x00\x00\x01\x00', 'ICO icon'),
    (b'\x1a\x45\xdf\xa3', 'Matroska (mkv/webm)'),
    (b'\x00\x00\x00\x18ftyp', 'MP4 video (ftyp)'),
    (b'\x66\x74\x79\x70', 'MP4/QuickTime (ftyp offset)'),
    (b'\x25\x21', 'PostScript (ps)'),
    (b'#!', 'Shell script'),
    (b'\x1f\xa0', 'LHA archive'),
    (b'\xed\xab\xee\xdb', 'RPM package'),
    (b'\x1f\x8b', 'GZip (alt)'),
    (b'\xca\xfe\xba\xbe', 'Java class (Mach-O fat)'),
    (b'\xcf\xfa\xed\xfe', 'Mach-O (32-bit)'),
    (b'\xfe\xed\xfa\xce', 'Mach-O (32-bit, swapped)'),
    (b'\xce\xfa\xed\xfe', 'Mach-O (64-bit)'),
    (b'II*\x00', 'TIFF (little-endian)'),
    (b'MM\x00*', 'TIFF (big-endian)'),
]


def _read(data_or_path):
    if isinstance(data_or_path, (bytes, bytearray)):
        return bytes(data_or_path)
    if isinstance(data_or_path, str) and os.path.exists(data_or_path):
        with open(data_or_path, 'rb') as f:
            return f.read()
    return b''


# ═══════════════════════════════════════════
# 1. 文件签名识别
# ═══════════════════════════════════════════

def file_magic(data_or_path) -> str:
    data = _read(data_or_path)
    if not data:
        return "无法读取文件"
    lines = [f"=== 文件签名识别 ===", f"大小: {len(data)} bytes", ""]
    matched = []
    for sig, desc in MAGIC_SIGNATURES:
        if data.startswith(sig):
            matched.append(f"  {desc}  [{sig[:12].hex()}]")
    if matched:
        lines.append("主签名匹配:")
        lines.extend(matched)
    else:
        lines.append("未匹配已知签名，前 32 字节:")
        lines.append("  " + data[:32].hex(' '))
    return "\n".join(lines)


# ═══════════════════════════════════════════
# 2. ZIP 分析
# ═══════════════════════════════════════════

def zip_analyze(data_or_path) -> str:
    data = _read(data_or_path)
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception as e:
        return "不是有效的 ZIP 文件: " + str(e)
    lines = ["=== ZIP 分析 ===", ""]
    infos = zf.infolist()
    lines.append(f"文件数: {len(infos)}")
    if zf.comment:
        lines.append(f"注释: {zf.comment.decode('utf-8', errors='replace')}")
    lines.append("")
    for info in infos:
        flag = info.flag_bits
        enc = "🔒加密" if (flag & 0x1) else "明文"
        comp = {0: 'stored', 8: 'deflate', 12: 'bzip2', 14: 'lzma'}.get(info.compress_type, f'type{info.compress_type}')
        lines.append(f"  {info.filename}")
        lines.append(f"    大小={info.file_size}B 压缩={info.compress_size}B ({comp}) CRC={info.CRC:08x} {enc}")
        if flag & 0x1:
            # 伪加密检测：尝试读取
            try:
                zf.read(info.filename)
                lines.append("    ⚠ 伪加密：设置了加密位但数据可正常读取")
            except RuntimeError as e:
                lines.append(f"    → 真实加密（{e}）")
            except Exception as e:
                lines.append(f"    → 读取失败（{type(e).__name__}）")
        if flag & 0x800:
            lines.append("    (UTF-8 文件名标志)")
    # 密码尝试（常见弱密码）
    lines.append("")
    lines.append("弱密码尝试（仅当有加密文件时）:")
    encrypted = [i for i in infos if i.flag_bits & 0x1]
    if encrypted:
        found = _try_zip_passwords(data, encrypted)
        if found:
            lines.append(f"  ✓ 密码破解: {found}")
        else:
            lines.append("  未命中常见弱密码")
    else:
        lines.append("  无加密文件")
    return "\n".join(lines)


_WEAK_ZIP_PASSWORDS = [
    b'', b'123456', b'password', b'admin', b'1234', b'12345', b'12345678',
    b'0000', b'111111', b'666666', b'888888', b'qwerty', b'abc123',
    b'flag', b'ctf', b'iscc', b'password123', b'admin123', b'root', b'test',
]


def _try_zip_passwords(data, infos):
    for pwd in _WEAK_ZIP_PASSWORDS:
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
            zf.setpassword(pwd)
            zf.read(infos[0].filename)
            return pwd.decode('utf-8', errors='replace')
        except Exception:
            continue
    return None


# ═══════════════════════════════════════════
# 3. 文件雕刻（binwalk 式）
# ═══════════════════════════════════════════

def file_carve(data_or_path) -> str:
    data = _read(data_or_path)
    if not data:
        return "无法读取文件"
    findings = []
    for sig, desc in MAGIC_SIGNATURES:
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx == -1:
                break
            findings.append((idx, desc, sig))
            start = idx + 1
    findings.sort()
    # 合并相邻的（同一位置多个签名，取最长）
    dedup = []
    for idx, desc, sig in findings:
        if dedup and idx - dedup[-1][0] < 4 and len(sig) <= len(dedup[-1][2]):
            continue
        dedup.append((idx, desc, sig))
    lines = [f"=== 文件雕刻（嵌入文件扫描） ===", f"总大小: {len(data)} bytes", f"发现 {len(dedup)} 处签名:", ""]
    for idx, desc, sig in dedup:
        lines.append(f"  @0x{idx:08x} ({idx}): {desc}")
    return "\n".join(lines)


# ═══════════════════════════════════════════
# 4. 二进制串提取（strings 式）
# ═══════════════════════════════════════════

def bin_text(data_or_path, min_len: int = 4) -> str:
    data = _read(data_or_path)
    if not data:
        return "无法读取文件"
    strings = re.findall(rb'[\x20-\x7e]{%d,}' % min_len, data)
    lines = [f"=== 可打印字符串提取 (len>={min_len}) ===", f"共 {len(strings)} 条:", ""]
    for s in strings:
        lines.append("  " + s.decode('ascii', errors='replace'))
    return "\n".join(lines)


# ═══════════════════════════════════════════
# 注册表（供 GUI / API 枚举）
# ═══════════════════════════════════════════

TOOLS = {
    "file_magic": {"name": "文件签名识别", "desc": "magic bytes → 文件类型", "func": file_magic},
    "zip_analyze": {"name": "ZIP 分析", "desc": "列表/加密/伪加密/弱密码", "func": zip_analyze},
    "file_carve": {"name": "文件雕刻", "desc": "扫描嵌入文件（binwalk 式）", "func": file_carve},
    "bin_text": {"name": "字符串提取", "desc": "可打印字符串（strings）", "func": bin_text},
}


def list_tools():
    return [{"id": tid, "name": t["name"], "desc": t["desc"]} for tid, t in TOOLS.items()]


def run_tool(tool_id: str, data_or_path) -> str:
    t = TOOLS.get(tool_id)
    if not t:
        return f"[!] 未知工具: {tool_id}"
    try:
        return t["func"](data_or_path)
    except Exception as e:
        return f"[!] 执行失败: {e}"
