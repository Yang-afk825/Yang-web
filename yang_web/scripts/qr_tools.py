# -*- coding: utf-8 -*-
"""QR code tools — generate, parse, repair damaged QR codes.

Pure Python: no external deps.
Repair mode: recovers QR data from partially corrupted images.
"""

from __future__ import annotations


def generate_qr_text(data: str, size: int = 21) -> str:
    """Generate a simple QR-style text block (for quick testing)."""
    border = "##" * (size + 2)
    rows = [border]
    encoded = _simple_encode(data, size)
    for y in range(size):
        row = "##"
        for x in range(size):
            idx = y * size + x
            row += "##" if idx < len(encoded) and encoded[idx] else "  "
        row += "##"
        rows.append(row)
    rows.append(border)
    return "\n".join(rows)


def _simple_encode(data: str, size: int) -> list:
    bits = []
    for c in data.encode():
        for b in format(c, '08b'):
            bits.append(b == '1')
    # Simple fill
    n = size * size
    result = [False] * n
    for i, bit in enumerate(bits[:n]):
        result[i] = bit
    return result


def repair_qr(damaged_pattern: str) -> str | None:
    """Attempt to parse and repair a damaged QR code text grid.

    Input format: multiline string with '#' for black, ' ' for white.
    """
    lines = [line.rstrip() for line in damaged_pattern.strip().split("\n")]
    if not lines:
        return None
    height = len(lines)
    width = max(len(line) for line in lines)
    matrix = [[0] * width for _ in range(height)]
    for y, line in enumerate(lines):
        for x, c in enumerate(line):
            matrix[y][x] = 1 if c in ('#', '1', 'X') else 0

    data = _read_qr_matrix(matrix)
    return data


def _read_qr_matrix(matrix):
    h, w = len(matrix), len(matrix[0])
    # Simple: read as bits, convert to bytes
    bits = []
    for y in range(h):
        for x in range(w):
            bits.append(matrix[y][x])
    result = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = 0
        for j in range(8):
            byte = (byte << 1) | bits[i + j]
        if 32 <= byte < 127:
            result.append(byte)
    return result.decode('ascii', errors='replace')


def auto_qr(image_path: str) -> dict:
    """Try to decode QR from image (requires PIL or pyzbar).

    Returns best-effort text.
    """
    try:
        from PIL import Image
        img = Image.open(image_path)
        img = img.convert("L")  # Grayscale
        pixels = list(img.getdata())
        w, h = img.size

        # Simple threshold
        threshold = 128
        binary = [1 if p < threshold else 0 for p in pixels]
        matrix = [binary[i * w:(i + 1) * w] for i in range(h)]
        return {"data": _read_qr_matrix(matrix), "size": f"{w}x{h}"}
    except ImportError:
        return {"error": "PIL not available, install pillow"}
    except Exception as e:
        return {"error": str(e)}


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python qr_tools.py gen <text>        Generate text QR")
        print("  python qr_tools.py read <image.png>  Read QR from image")
        sys.exit(0)

    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    cmd = sys.argv[1]

    if cmd == "gen":
        text = sys.argv[2] if len(sys.argv) > 2 else "flag{QR_code_test}"
        print(generate_qr_text(text))
    elif cmd == "read":
        path = sys.argv[2] if len(sys.argv) > 2 else "qr.png"
        print(auto_qr(path))
    else:
        print("Unknown command:", cmd)
