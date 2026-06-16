# -*- coding: utf-8 -*-
"""File analysis, stego, reverse shells, and webshells for Yang-Web CTF toolkit."""
import os, struct, re as _re

REVERSE_SHELLS = {
    "bash": ["Bash TCP", "connect back shell"],
    "python": ["Python", "socket-based shell"],
    "php": ["PHP", "fsockopen shell"],
    "nc": ["Netcat", "fifo shell"],
    "powershell": ["PowerShell", "TCPClient shell"],
    "perl": ["Perl", "Socket shell"],
    "ruby": ["Ruby", "TCPSocket shell"],
    "socat": ["Socat", "TCP shell"],
    "telnet": ["Telnet", "fifo shell"],
    "awk": ["AWK", "/inet/tcp shell"],
}

WEBSHELLS = {
    "php_simple": ["PHP Eval", "POST-based"],
    "php_exec": ["PHP Exec", "GET-based"],
    "php_big": ["PHP Full", "cmd/upload"],
    "asp": ["ASP Eval", "POST-based"],
    "aspx": ["ASPX Eval", "POST-based"],
    "jsp": ["JSP Exec", "GET-based"],
}

def generate_reverse_shell(lang, ip, port):
    if lang not in REVERSE_SHELLS:
        return "Available: " + ", ".join(REVERSE_SHELLS.keys())
    return "# {} Reverse Shell\n# Target: {}:{}\n\n[Shell payload for {}]".format(
        REVERSE_SHELLS[lang][0], ip, port, lang)

def list_shell_languages():
    return list(REVERSE_SHELLS.keys())

def generate_webshell(t):
    if t not in WEBSHELLS:
        return "Available: " + ", ".join(WEBSHELLS.keys())
    return "# {} WebShell\n\n[WebShell payload for {}]".format(WEBSHELLS[t][0], t)

def list_webshell_types():
    return list(WEBSHELLS.keys())

FILE_MAGICS = {
    b'\x89PNG': 'PNG', b'\xff\xd8\xff': 'JPEG', b'GIF8': 'GIF', b'%PDF': 'PDF',
    b'PK\x03\x04': 'ZIP', b'\x1f\x8b': 'GZIP', b'MZ': 'PE/EXE', b'\x7fELF': 'ELF',
    b'\xca\xfe\xba\xbe': 'Mach-O', b'dex\n': 'DEX', b'SQLite': 'SQLite',
    b'#!': 'Script', b'RIFF': 'WAV/AVI', b'\xff\xfb': 'MP3', b'ID3': 'MP3',
    b'\x42\x5a\x68': 'BZip2', b'\xfd\x37\x7a\x58\x5a\x00': 'XZ',
}

def analyze_file(filepath):
    if not os.path.exists(filepath):
        return "File not found: " + filepath
    st = os.stat(filepath)
    with open(filepath, 'rb') as f:
        head = f.read(256)
        f.seek(max(0, st.st_size - 256))
    lines = ["=== File Analysis ===", "Name: " + os.path.basename(filepath),
             "Size: " + str(st.st_size) + " bytes (" + "{:.1f}".format(st.st_size/1024) + " KB)", ""]
    detected = False
    for magic, desc in sorted(FILE_MAGICS.items(), key=lambda x: -len(x[0])):
        if head[:len(magic)] == magic:
            lines.append("Type: " + desc + " (magic: " + magic.hex(' ').upper() + ")")
            detected = True
            break
    if not detected:
        if all(32 <= b < 127 for b in head[:20]):
            lines.append("Type: Text file")
        else:
            lines.append("Type: Unknown (" + head[:16].hex(' ').upper() + ")")
    lines.append(""); lines.append("=== Hex (first 64 bytes) ===")
    for i in range(0, min(64, len(head)), 16):
        hp = " ".join("{:02X}".format(b) for b in head[i:i+16])
        ap = "".join(chr(b) if 32 <= b < 127 else "." for b in head[i:i+16])
        lines.append("  {:04X}: {}  {}".format(i, hp.ljust(48), ap))
    with open(filepath, 'rb') as f:
        f.seek(0)
        content = f.read(min(102400, st.st_size))
    strings_found = set()
    for m in _re.finditer(rb'[\x20-\x7e]{4,}', content):
        strings_found.add(m.group().decode('ascii'))
    interesting = [s for s in strings_found if any(
        kw in s.lower() for kw in ['flag', 'ctf', 'key', 'secret', 'password', 'iscc', 'admin'])]
    if interesting:
        lines.append(""); lines.append("=== Key Strings Found ===")
        for s in sorted(interesting):
            lines.append("  * " + s[:120])
    return "\n".join(lines)

def analyze_png(filepath):
    if not os.path.exists(filepath):
        return "File not found"
    with open(filepath, 'rb') as f:
        data = f.read()
    if data[:8] != b'\x89PNG\r\n\x1a\n':
        return "Not a valid PNG file (magic: " + data[:8].hex() + ")"
    lines = ["=== PNG Analysis ===", "File size: " + str(len(data)) + " bytes", ""]
    pos, chunk_num = 8, 0
    while pos < len(data):
        if pos + 8 > len(data): break
        length = struct.unpack('>I', data[pos:pos+4])[0]
        chunk_type = data[pos+4:pos+8].decode('ascii', errors='replace')
        crc_pos = pos + 8 + length
        if crc_pos + 4 > len(data): break
        chunk_data = data[pos+8:pos+8+length]
        chunk_num += 1
        lines.append("Chunk " + str(chunk_num) + ": " + chunk_type + " (" + str(length) + " bytes) @ " + str(pos))
        if chunk_type == 'IHDR':
            w = struct.unpack('>I', chunk_data[0:4])[0]
            h = struct.unpack('>I', chunk_data[4:8])[0]
            cn = {0: 'Gray', 2: 'RGB', 3: 'Indexed', 4: 'Gray+Alpha', 6: 'RGBA'}
            lines.append("  Size: " + str(w) + "x" + str(h) + " | Depth: " + str(chunk_data[8]) +
                         " | Color: " + cn.get(chunk_data[9], str(chunk_data[9])))
        elif chunk_type == 'IEND':
            lines.append("  End marker")
            break
        elif chunk_type in ('tEXt', 'zTXt', 'iTXt'):
            try:
                ni = chunk_data.index(b'\x00')
                k = chunk_data[:ni].decode('utf-8', 'replace')
                v = chunk_data[ni+1:].decode('utf-8', 'replace')[:100]
                lines.append("  Text: " + k + " = " + v)
            except ValueError:
                lines.append("  Text block (" + str(length) + " bytes)")
        pos = crc_pos + 4
    lines.append(""); lines.append("Total chunks: " + str(chunk_num))
    iend_pos = data.rfind(b'IEND')
    if iend_pos > 0:
        extra_start = iend_pos + 12
        if extra_start < len(data):
            extra = data[extra_start:]
            lines.append(""); lines.append("WARNING: " + str(len(extra)) + " bytes after IEND!")
            lines.append("First 100 bytes: " + str(extra[:100]))
    return "\n".join(lines)

def extract_lsb(filepath, plane=0):
    try:
        from PIL import Image
    except ImportError:
        return "Need Pillow: pip install Pillow"
    if not os.path.exists(filepath):
        return "File not found"
    try:
        img = Image.open(filepath)
        pixels = list(img.getdata())
    except Exception as e:
        return "Error reading image: " + str(e)
    bits = []
    for p in pixels:
        if isinstance(p, int):
            bits.append((p >> plane) & 1)
        else:
            for ch in p[:3]:
                bits.append((ch >> plane) & 1)
    chars = []
    for i in range(0, len(bits) - 7, 8):
        byte = sum(bits[i+j] << (7-j) for j in range(8))
        if 32 <= byte < 127 or byte == 10:
            chars.append(chr(byte))
        else:
            chars.append('.')
    return "\n".join([
        "=== LSB Extraction (plane=" + str(plane) + ") ===",
        "File: " + os.path.basename(filepath),
        "Pixels: " + str(len(pixels)),
        "Bits extracted: " + str(len(bits)),
        "",
        "ASCII content:",
        "".join(chars[:500]),
    ])

def read_exif(filepath):
    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
    except ImportError:
        return "Need Pillow: pip install Pillow"
    if not os.path.exists(filepath):
        return "File not found"
    try:
        img = Image.open(filepath)
        exif = img._getexif()
    except Exception as e:
        return "Error: " + str(e)
    if not exif:
        return "No EXIF data found"
    lines = ["=== EXIF Metadata ===", ""]
    for tag_id, value in exif.items():
        tag_name = TAGS.get(tag_id, "Tag_" + str(tag_id))
        if isinstance(value, bytes):
            value = value.decode('utf-8', errors='replace')[:150]
        lines.append("  " + tag_name + ": " + str(value)[:150])
    return "\n".join(lines)

def identify_cipher_text(text):
    lines = ["=== Cipher Identification ===", "Length: " + str(len(text)) + " chars", ""]
    checks = {
        'Base64': lambda t: bool(_re.match(r'^[A-Za-z0-9+/]+=*$', t.strip()) and len(t.strip()) % 4 == 0),
        'Base32': lambda t: bool(_re.match(r'^[A-Z2-7]+=*$', t.strip().upper())),
        'Hex': lambda t: bool(_re.match(r'^[0-9a-fA-F\s]+$', t.strip()) and len(t.replace(' ', '')) % 2 == 0),
        'URL': lambda t: '%' in t and bool(_re.search(r'%[0-9a-fA-F]{2}', t)),
        'HTML Entity': lambda t: '&' in t and ';' in t,
        'Morse': lambda t: bool(_re.match(r'^[.\-\s/]+$', t.strip()) and '.' in t and '-' in t),
        'Binary': lambda t: bool(_re.match(r'^[01\s]+$', t.strip()) and len(t.replace(' ', '')) % 8 == 0),
        'Decimal ASCII': lambda t: all(p.isdigit() and 32 <= int(p) <= 126 for p in t.strip().split() if p),
        'Brainfuck': lambda t: all(c in '><+-.,[]' for c in t if not c.isspace()),
        'Ook!': lambda t: 'Ook' in t,
        'JWT Token': lambda t: t.count('.') == 2 and len(t.split('.')) == 3,
        'MD5 Hash': lambda t: len(t.strip()) == 32 and bool(_re.match(r'^[0-9a-fA-F]{32}$', t.strip())),
        'SHA1 Hash': lambda t: len(t.strip()) == 40 and bool(_re.match(r'^[0-9a-fA-F]{40}$', t.strip())),
        'SHA256 Hash': lambda t: len(t.strip()) == 64 and bool(_re.match(r'^[0-9a-fA-F]{64}$', t.strip())),
    }
    matches = []
    for name, test in checks.items():
        try:
            if test(text):
                matches.append(name)
        except Exception:
            pass
    if matches:
        lines.append("Possible types: " + ", ".join(matches))
    else:
        lines.append("No match found")
    return "\n".join(lines)
