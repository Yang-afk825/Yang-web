"""Advanced string/number conversion — 128-bit, float, modular arithmetic, diff."""

from __future__ import annotations
import struct
import sys
import binascii


def hex_to_float_le(hex_str: str) -> float:
    """4-byte hex (little-endian) to float."""
    raw = bytes.fromhex(hex_str.rjust(8, '0')[:8])
    return struct.unpack('<f', raw[::-1] if len(raw) == 4 else raw)[0]


def hex_to_float_be(hex_str: str) -> float:
    """4-byte hex (big-endian) to float."""
    raw = bytes.fromhex(hex_str.rjust(8, '0')[:8])
    return struct.unpack('>f', raw)[0]


def float_to_hex(value: float, endian: str = "little") -> str:
    fmt = '<f' if endian == "little" else '>f'
    return struct.pack(fmt, value).hex()


def int_to_bytes_le(value: int, length: int) -> bytes:
    return value.to_bytes(length, 'little')


def int_to_bytes_be(value: int, length: int) -> bytes:
    return value.to_bytes(length, 'big')


def bytes_to_int_le(data: bytes) -> int:
    return int.from_bytes(data, 'little')


def bytes_to_int_be(data: bytes) -> int:
    return int.from_bytes(data, 'big')


def num_128bit_to_str(value: int, byte_order: str = "big") -> str:
    """128-bit integer to string."""
    raw = value.to_bytes(16, byte_order)
    return raw.decode("ascii", errors="replace").strip("\x00")


def str_to_128bit(text: str, byte_order: str = "big") -> int:
    raw = text.encode("ascii", errors="replace").ljust(16, b'\x00')[:16]
    return int.from_bytes(raw, byte_order)


def modular_arithmetic(modulus: int, values: list[int]) -> dict:
    """Compute basic modular arithmetic."""
    return {
        "mod": modulus,
        "values": values,
        "reduced": [v % modulus for v in values],
        "sum_mod": sum(values) % modulus,
        "prod_mod": _prod_mod(values, modulus),
    }


def _prod_mod(values: list[int], mod: int) -> int:
    result = 1
    for v in values:
        result = (result * v) % mod
    return result


def xor_strings(a: str, b: str) -> str:
    """XOR two strings (CTF common)."""
    min_len = min(len(a), len(b))
    result = []
    for i in range(min_len):
        result.append(chr(ord(a[i]) ^ ord(b[i])))
    return "".join(result)


def xor_hex(a: str, b: str) -> str:
    """XOR two hex strings."""
    a_bytes = bytes.fromhex(a)
    b_bytes = bytes.fromhex(b)
    result = bytes(x ^ y for x, y in zip(a_bytes, b_bytes))
    return result.hex()


def bin_to_ascii(text: str, bits: int = 8, reverse: bool = False) -> str:
    """Binary string to ASCII."""
    text = text.replace(" ", "").replace("\n", "")
    if reverse:
        text = text[::-1]
    result = []
    for i in range(0, len(text) - bits + 1, bits):
        chunk = text[i:i + bits]
        result.append(chr(int(chunk, 2)))
    return "".join(result)


def ascii_to_bin(text: str, bits: int = 8) -> str:
    return " ".join(format(ord(c), f'0{bits}b') for c in text)


def string_diff(a: str, b: str) -> str:
    """Show byte-level differences."""
    result = []
    max_len = max(len(a), len(b))
    for i in range(max_len):
        ca = ord(a[i]) if i < len(a) else None
        cb = ord(b[i]) if i < len(b) else None
        if ca == cb:
            result.append(f"[{i:3d}] | {ca:3d} ('{chr(ca) if ca else '?'}') | same")
        else:
            result.append(f"[{i:3d}] | {ca if ca else 'END':3} ({chr(ca) if ca and 32 <= ca < 127 else '?'}) vs {cb if cb else 'END':3} ({chr(cb) if cb and 32 <= cb < 127 else '?'}) | DIFF")
    return "\n".join(result)


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python string_convert.py hex2float <hex> --be|--le")
        print("  python string_convert.py 128tostr <int>")
        print("  python string_convert.py strto128 <text>")
        print("  python string_convert.py xorstr <a> <b>")
        print("  python string_convert.py xorhex <a> <b>")
        print("  python string_convert.py bin2ascii <text> [bits=8]")
        print("  python string_convert.py diff <a> <b>")
        sys.exit(0)

    cmd = sys.argv[1]

    if cmd == "hex2float":
        val = sys.argv[2]
        endian = sys.argv[3] if len(sys.argv) > 3 else "--le"
        fn = hex_to_float_le if endian == "--le" else hex_to_float_be
        print(fn(val))
    elif cmd == "128tostr":
        val = int(sys.argv[2])
        print(num_128bit_to_str(val))
    elif cmd == "strto128":
        val = sys.argv[2]
        print(str_to_128bit(val))
    elif cmd == "xorstr":
        print(xor_strings(sys.argv[2], sys.argv[3]))
    elif cmd == "xorhex":
        print(xor_hex(sys.argv[2], sys.argv[3]))
    elif cmd == "bin2ascii":
        bits = int(sys.argv[3]) if len(sys.argv) > 3 else 8
        print(bin_to_ascii(sys.argv[2], bits))
    elif cmd == "diff":
        print(string_diff(sys.argv[2], sys.argv[3]))
    else:
        print("Unknown command:", cmd)
