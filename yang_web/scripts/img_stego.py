"""Image Steganography Toolkit â LSB, channel extraction, PNG chunk analysis, zero deps."""

from __future__ import annotations
import sys
import struct
import os

PNG_SIG = b'\x89PNG\r\n\x1a\n'
JPEG_SOI = b'\xff\xd8'
JPEG_EOI = b'\xff\xd9'
GIF87A = b'GIF87a'
GIF89A = b'GIF89a'
BMP_SIG = b'BM'


def detect_image_type(data: bytes) -> str:
    if data.startswith(PNG_SIG):
        return "PNG"
    if data.startswith(JPEG_SOI):
        return "JPEG"
    if data.startswith(GIF87A) or data.startswith(GIF89A):
        return "GIF"
    if data.startswith(BMP_SIG):
        return "BMP"
    return "UNKNOWN"


def extract_png_chunks(data: bytes) -> list:
    """Extract all PNG chunks."""
    if not data.startswith(PNG_SIG):
        return [("error", 0, "not a PNG")]
    chunks = []
    pos = 8  # skip signature
    while pos + 8 <= len(data):
        length = struct.unpack(">I", data[pos:pos + 4])[0]
        chunk_type = data[pos + 4:pos + 8].decode("ascii", errors="replace")
        chunk_data = data[pos + 8:pos + 8 + length] if pos + 8 + length <= len(data) else b""
        chunks.append((chunk_type, length, chunk_data[:100]))
        pos += 12 + length
        if chunk_type == "IEND":
            break
    return chunks


def extract_lsb(data: bytes, channel: str = "all", bits: int = 1) -> str:
    """Extract LSB from image data (simplified â extract from pixel data after header).

    For PNG: extract from IDAT chunks. For BMP: from pixel data.
    """
    all_bits = []

    if data.startswith(PNG_SIG):
        # Find all IDAT data
        pos = 8
        idat_data = b""
        while pos + 8 <= len(data):
            length = struct.unpack(">I", data[pos:pos + 4])[0]
            chunk_type = data[pos + 4:pos + 8].decode("ascii", errors="replace")
            if chunk_type == "IDAT":
                idat_data += data[pos + 8:pos + 8 + length]
            elif chunk_type == "IEND":
                break
            pos += 12 + length

        # Decompress zlib
        try:
            import zlib
            idat_data = zlib.decompress(idat_data)
        except Exception:
            pass

        # Extract LSB from each byte
        for byte in idat_data:
            for b in range(bits - 1, -1, -1):
                all_bits.append((byte >> b) & 1)

    elif data.startswith(BMP_SIG):
        offset = struct.unpack("<I", data[10:14])[0]
        bmp_data = data[offset:]
        for byte in bmp_data:
            for b in range(bits - 1, -1, -1):
                all_bits.append((byte >> b) & 1)
    else:
        # Generic: try from byte 256 onwards
        raw = data[256:]
        for byte in raw:
            for b in range(bits - 1, -1, -1):
                all_bits.append((byte >> b) & 1)

    # Convert bits to bytes
    result = bytearray()
    for i in range(0, len(all_bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | all_bits[i + j]
        result.append(byte)
    return result.decode("latin-1", errors="replace")


def extract_after_eof(data: bytes, eof_marker: bytes = JPEG_EOI) -> bytes | None:
    """Extract hidden data after EOF marker (JPEG/GIF)."""
    idx = data.rfind(eof_marker)
    if idx < 0:
        return None
    after = data[idx + len(eof_marker):]
    if after.strip(b'\x00'):
        return after
    return None


def search_hidden_strings(data: bytes, min_len: int = 4) -> list:
    """Search for hidden ASCII strings in binary data."""
    import re
    # Find {flag} or key=value patterns
    patterns = [
        rb'[A-Za-z0-9_]{' + str(min_len).encode() + rb',}',
        rb'flag\{[^}]+\}',
        rb'FLAG\{[^}]+\}',
        rb'ctf\{[^}]+\}',
        rb'[A-Za-z]{3,6}\{[^}]+\}',
    ]
    results = set()
    for pat in patterns:
        for m in re.findall(pat, data):
            results.add(m.decode("ascii", errors="replace"))
    return sorted(results)


def analyze_image(path: str) -> dict:
    """Comprehensive image analysis."""
    with open(path, "rb") as f:
        data = f.read()

    result = {
        "path": path,
        "size": len(data),
        "type": detect_image_type(data),
    }

    if result["type"] == "PNG":
        chunks = extract_png_chunks(data)
        result["chunks"] = [(t, l) for t, l, _ in chunks]
        result["lsb_preview"] = extract_lsb(data, bits=1)[:200]

    elif result["type"] == "JPEG":
        result["lsb_preview"] = extract_lsb(data, bits=1)[:200]

    hidden_after = extract_after_eof(data)
    if hidden_after:
        result["hidden_after_eof"] = hidden_after[:200]

    hidden_strs = search_hidden_strings(data)
    if hidden_strs:
        result["hidden_strings"] = hidden_strs[:10]

    return result


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if len(sys.argv) < 2:
        print("Usage: python img_stego.py <image.png> [--lsb] [--chunks]")
        sys.exit(0)

    path = sys.argv[1]
    mode = sys.argv[2] if len(sys.argv) > 2 else "--all"

    if not os.path.isfile(path):
        print(f"File not found: {path}")
        sys.exit(1)

    result = analyze_image(path)

    print(f"Type: {result['type']} ({result['size']} bytes)")

    if "chunks" in result:
        print(f"\nPNG Chunks:")
        for t, l in result["chunks"]:
            print(f"  {t}: {l}B")

    if "lsb_preview" in result:
        print(f"\nLSB preview:\n  {result['lsb_preview'][:200]}")

    if "hidden_after_eof" in result:
        print(f"\nHidden after EOF:\n  {result['hidden_after_eof'][:200]}")

    if "hidden_strings" in result:
        print(f"\nFound strings:")
        for s in result["hidden_strings"]:
            print(f"  {s}")
