# -*- coding: utf-8 -*-
"""File analyzer â magic bytes detection, file type identification, hex dump."""

from __future__ import annotations
import sys
import os

# Extended magic bytes table
MAGIC_BYTES = {
    b'\x89PNG\r\n\x1a\n': "PNG image",
    b'\xff\xd8\xff': "JPEG image",
    b'GIF87a': "GIF image (87a)",
    b'GIF89a': "GIF image (89a)",
    b'BM': "BMP image",
    b'PK\x03\x04': "ZIP archive",
    b'PK\x05\x06': "ZIP (empty)",
    b'PK\x07\x08': "ZIP (spanned)",
    b'Rar!\x1a\x07': "RAR archive",
    b'\x1f\x8b\x08': "gzip compressed",
    b'BZh': "bzip2 compressed",
    b'\xfd7zXZ\x00': "XZ compressed",
    b'\x7fELF': "ELF executable",
    b'MZ': "PE executable (EXE/DLL)",
    b'\xca\xfe\xba\xbe': "Mach-O (32-bit)",
    b'\xcf\xfa\xed\xfe': "Mach-O (64-bit)",
    b'\x25\x50\x44\x46': "PDF document",
    b'\xd0\xcf\x11\xe0': "MS Office (OLE2)",
    b'\x50\x4b\x03\x04': "DOCX/XLSX/PPTX",
    b'%!PS': "PostScript",
    b'ID3': "MP3 audio",
    b'\xff\xfb': "MP3 audio (alt)",
    b'RIFF': "RIFF (WAV/AVI)",
    b'OggS': "Ogg/Vorbis",
    b'fLaC': "FLAC audio",
    b'\x1a\x45\xdf\xa3': "WebM/MKV",
    b'SQLite format 3\x00': "SQLite database",
    b'\xac\xed\x00\x05': "Java serialized",
    b'\x03\xf3\x0d\x0a': "Python pickle",
}

MAX_MAGIC_LEN = max(len(m) for m in MAGIC_BYTES)


def detect_file_type(path: str) -> dict:
    """Detect file type from magic bytes."""
    result = {"path": path, "size": os.path.getsize(path), "type": "UNKNOWN", "magic_hex": ""}

    with open(path, "rb") as f:
        header = f.read(MAX_MAGIC_LEN)
        result["magic_hex"] = header[:16].hex(" ")

        for magic, file_type in MAGIC_BYTES.items():
            if header.startswith(magic):
                result["type"] = file_type
                result["magic"] = magic.hex(" ")
                break

    return result


def hex_dump(data: bytes, offset: int = 0, max_len: int = 512) -> str:
    """Classic hex dump format."""
    lines = []
    for i in range(0, min(len(data), max_len), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset + i:08x}  {hex_part:<48s}  |{ascii_part}|")
    return "\n".join(lines)


def find_embedded_files(path: str) -> list:
    """Search for embedded file signatures within a file."""
    with open(path, "rb") as f:
        data = f.read()

    results = []
    for magic, file_type in MAGIC_BYTES.items():
        pos = 0
        while True:
            idx = data.find(magic, pos)
            if idx < 0:
                break
            if idx > 0:  # not at position 0 (that's the main file)
                results.append((idx, len(magic), file_type))
            pos = idx + 1

    return sorted(results, key=lambda x: x[0])[:20]


def string_scan(path: str, min_len: int = 4) -> list:
    """Extract all printable ASCII strings from file."""
    with open(path, "rb") as f:
        data = f.read()

    results = set()
    current = bytearray()
    for byte in data:
        if 32 <= byte < 127:
            current.append(byte)
        else:
            if len(current) >= min_len:
                results.add(current.decode("ascii"))
            current = bytearray()
    if len(current) >= min_len:
        results.add(current.decode("ascii"))
    return sorted(results, key=len, reverse=True)[:50]


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if len(sys.argv) < 2:
        print("Usage: python file_analyzer.py <file> [--hex] [--strings] [--embedded]")
        sys.exit(0)

    path = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "--all"

    if not os.path.isfile(path):
        print(f"File not found: {path}")
        sys.exit(1)

    info = detect_file_type(path)
    print(f"File: {path}")
    print(f"Size: {info['size']:,} bytes")
    print(f"Type: {info['type']}")
    print(f"Magic: {info['magic_hex']}")

    if "--hex" in sys.argv or mode == "--all":
        with open(path, "rb") as f:
            data = f.read(512)
        print(f"\n[HEX DUMP]")
        print(hex_dump(data))

    if "--strings" in sys.argv or mode == "--all":
        strings = string_scan(path)
        print(f"\n[STRINGS] ({len(strings)} found)")
        for s in strings[:20]:
            print(f"  {s}")

    if "--embedded" in sys.argv or mode == "--all":
        embedded = find_embedded_files(path)
        if embedded:
            print(f"\n[EMBEDDED FILES] ({len(embedded)} found)")
            for offset, length, ftype in embedded[:10]:
                print(f"  @{offset:08x} {ftype} ({length}B)")
        else:
            print(f"\n[EMBEDDED] none found")
