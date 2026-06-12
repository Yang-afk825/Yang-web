# -*- coding: utf-8 -*-
"""ZIP analysis & password recovery — CRC-based & known-plaintext."""

from __future__ import annotations
import struct
import zipfile
import sys
import os
import itertools
import string

ZIP_SIGNATURE = b'PK\x03\x04'


def analyze_zip(path: str) -> dict:
    """Analyze ZIP structure."""
    info = {"path": path, "size": os.path.getsize(path), "entries": []}
    try:
        with zipfile.ZipFile(path, 'r') as zf:
            for zi in zf.infolist():
                entry = {
                    "name": zi.filename,
                    "compressed": zi.compress_size,
                    "original": zi.file_size,
                    "crc32": format(zi.CRC & 0xFFFFFFFF, '08X'),
                    "encrypted": zi.flag_bits & 0x1 != 0,
                    "method": "deflate" if zi.compress_type == 8 else "store",
                }
                info["entries"].append(entry)
    except zipfile.BadZipFile:
        info["error"] = "bad zip"
    return info


def crc32_repair(known_crc: int, length: int,
                  charset: str = string.printable.strip()) -> str | None:
    """Recover small data from CRC32 by brute force."""
    import zlib
    for combo in itertools.product(charset, repeat=length):
        candidate = ''.join(combo).encode()
        if zlib.crc32(candidate) & 0xFFFFFFFF == known_crc:
            return candidate.decode()
    return None


def png_crc_repair(expected_crc: int, length: int = 4,
                    charset: str = string.digits + string.ascii_letters + '_') -> str | None:
    """Brute-force PNG chunk data from CRC."""
    import zlib
    for combo in itertools.product(charset, repeat=length):
        candidate = ''.join(combo).encode()
        if zlib.crc32(candidate) & 0xFFFFFFFF == expected_crc:
            return candidate.decode()
    return None


def zip_crc_brute(known_crc: int, length: int,
                   charset: str = string.printable.strip()[:95]) -> str | None:
    """Recover small ZIP entries from CRC only."""
    return crc32_repair(known_crc, length, charset)


def zip_known_plaintext(path: str, known: bytes) -> str | None:
    """Known-plaintext attack on ZipCrypto (pkcrack helper)."""
    print(f"[info] ZIP KPA requires pkcrack tool")
    print(f"[info] known plaintext ({len(known)}B): {known[:50]}")
    print(f"[info] Usage: pkcrack -C '{path}' -p plaintext -c ciphertext -d output.zip")
    return None


def crack_bkcrack(path: str) -> dict:
    """Guide for bkcrack usage on AES-encrypted ZIP."""
    return {
        "tool": "bkcrack",
        "steps": [
            f"1. bkcrack -C '{path}' -c <entry> -p <known_plaintext_file>",
            "2. bkcrack -C archive.zip -k <keys> -d output.zip",
        ],
        "note": "Requires at least 12 bytes of known plaintext for AES-256 ZIP",
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python zip_tools.py <zip_path> [--crc CRC LEN]")
        sys.exit(0)

    cmd = sys.argv[1]
    if cmd == "--crc":
        crc_val = int(sys.argv[2], 16)
        length = int(sys.argv[3])
        charset = sys.argv[4] if len(sys.argv) > 4 else string.printable.strip()[:80]
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        result = zip_crc_brute(crc_val, length, charset)
        if result:
            print(f"Found: {result}")
        else:
            print("Not found with given charset/length")
    elif os.path.isfile(cmd):
        info = analyze_zip(cmd)
        import json
        print(json.dumps(info, indent=2, ensure_ascii=False))
    else:
        print("File not found:", cmd)
