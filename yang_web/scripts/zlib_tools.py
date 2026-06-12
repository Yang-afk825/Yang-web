# -*- coding: utf-8 -*-
"""Compression helpers — zlib / gzip / bzip2 / lzma / inflate."""

from __future__ import annotations
import zlib
import gzip
import bz2
import lzma
import base64
import sys


def zlib_decompress(data: bytes) -> bytes:
    return zlib.decompress(data, -15)


def zlib_compress(data: bytes) -> bytes:
    return zlib.compress(data)


def gzip_decompress(data: bytes) -> bytes:
    return gzip.decompress(data)


def gzip_compress(data: bytes) -> bytes:
    return gzip.compress(data)


def bzip2_decompress(data: bytes) -> bytes:
    return bz2.decompress(data)


def bzip2_compress(data: bytes) -> bytes:
    return bz2.compress(data)


def lzma_decompress(data: bytes) -> bytes:
    return lzma.decompress(data)


def inflate_raw(data: bytes) -> bytes:
    return zlib.decompress(data, -15)


def auto_decompress(data: bytes) -> dict:
    """Try all decompressors, return best result."""
    results = {}
    algorithms = {
        "zlib": zlib_decompress,
        "gzip": gzip_decompress,
        "bzip2": bzip2_decompress,
        "lzma": lzma_decompress,
        "inflate_raw": inflate_raw,
    }
    for name, fn in algorithms.items():
        try:
            result = fn(data)
            try:
                text = result.decode("utf-8")
                printable = sum(1 for c in text if 32 <= ord(c) < 127 or c in '\n\r\t')
                score = printable / max(len(text), 1)
            except UnicodeDecodeError:
                score = 0.5 if len(result) > 0 else 0
            results[name] = {
                "success": True,
                "size": len(result),
                "score": score,
                "preview": str(result[:200]),
            }
        except Exception as e:
            results[name] = {"success": False, "error": str(e)}
    return results


def decode_base64_zlib(text: str) -> bytes | None:
    """Base64 decode then zlib decompress."""
    try:
        data = base64.b64decode(text)
        return zlib.decompress(data)
    except Exception:
        return None


def decode_base64_gzip(text: str) -> bytes | None:
    """Base64 decode then gzip decompress."""
    try:
        data = base64.b64decode(text)
        return gzip.decompress(data)
    except Exception:
        return None


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if len(sys.argv) < 2:
        print("Usage: python zlib_tools.py <base64_data> [--auto]")
        print("       python zlib_tools.py <file> --file")
        sys.exit(0)

    if sys.argv[1] == "--file" and len(sys.argv) > 2:
        with open(sys.argv[2], "rb") as f:
            data = f.read()
    else:
        data = base64.b64decode(sys.argv[1])

    results = auto_decompress(data)
    for name, result in results.items():
        if result["success"]:
            status = "+" if result["score"] > 0.5 else "?"
            print(f"{status} {name}: {result['size']}B, score={result['score']:.2f}")
            print(f"  {result['preview'][:100]}")
        else:
            print(f"x {name}: {result['error']}")
