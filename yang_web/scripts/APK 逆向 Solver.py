#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generic solver for this SCM time-capsule APK family.

Usage:
    python solve_generic.py attachment-7.apk
    python solve_generic.py *.apk
    python solve_generic.py K:\\ISCC\\Re --recursive
    python solve_generic.py attachment-7.apk --p1 CT.=6`
    python solve_generic.py attachment-7.apk --p1-hex 43542E3D3660

The script derives p2/p3/p4 from the Java/native constraints and decrypts each
assets/flag.enc with the recovered 24-byte key.
"""

from __future__ import annotations

import argparse
import hashlib
import itertools
import re
import sys
import zipfile
from collections import defaultdict
from glob import glob
from pathlib import Path


ASCII_MIN = 0x20
ASCII_MAX = 0x7E
PRINTABLE = bytes(range(ASCII_MIN, ASCII_MAX + 1))
MOD24 = 1 << 24
FNV_PRIME_24 = 0x193
FNV_INV_24 = pow(FNV_PRIME_24, -1, MOD24)
FNV_INIT_24 = 0x1C9DC5
BASE64_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

DEFAULT_P1_HEX = "43542E3D3660"
DEFAULT_P4_TARGET = b"gGH52dkV"
DEFAULT_PIN_HEX = "a950927d04e7936e1ebdb7ee03f59f7a17adf1a3d962475e0c772b7899c4ff2d"


def die(message: str) -> None:
    raise SystemExit(message)


def is_ascii6(data: bytes) -> bool:
    return len(data) == 6 and all(ASCII_MIN <= b <= ASCII_MAX for b in data)


def fold_bytes_to_u24(data: bytes) -> int:
    h = FNV_INIT_24
    for b in data:
        h = ((h ^ b) * FNV_PRIME_24) & (MOD24 - 1)
    return h


def fold_ascii6_to_u24(data: bytes) -> int:
    if not is_ascii6(data):
        die(f"not printable ASCII6: {data!r}")
    return fold_bytes_to_u24(data)


def xor_ascii(data: bytes) -> int:
    acc = 0
    for b in data:
        acc ^= b
    return acc & 0xFF


def rol24(value: int, shift: int) -> int:
    shift %= 24
    value &= MOD24 - 1
    return ((value << shift) | (value >> (24 - shift))) & (MOD24 - 1)


def ror24(value: int, shift: int) -> int:
    shift %= 24
    value &= MOD24 - 1
    return ((value >> shift) | (value << (24 - shift))) & (MOD24 - 1)


def u24_to_hex6(value: int) -> str:
    return f"{value & 0xFFFFFF:06X}"


def atbash_hex6(value: str) -> str:
    out = []
    for ch in value.upper():
        if "0" <= ch <= "9":
            out.append(chr(ord("9") - ord(ch) + ord("0")))
        elif "A" <= ch <= "F":
            out.append(chr(ord("F") - ord(ch) + ord("A")))
        else:
            die(f"invalid hex char for atbash: {ch!r}")
    return "".join(out)


def part2_p2_fold_target(p1: bytes) -> int:
    u1 = fold_ascii6_to_u24(p1)
    c = int(atbash_hex6(u24_to_hex6(u1)), 16)
    b = ror24(c, 8)
    a = int(atbash_hex6(u24_to_hex6(b)), 16)
    return (a ^ 0xAAAAAA) & 0xFFFFFF


def build_prefix_table() -> dict[tuple[int, int], list[bytes]]:
    table: dict[tuple[int, int], list[bytes]] = defaultdict(list)
    for triple in itertools.product(PRINTABLE, repeat=3):
        prefix = bytes(triple)
        table[(fold_bytes_to_u24(prefix), xor_ascii(prefix))].append(prefix)
    return table


def ascii6_preimages(target_fold: int, target_xor: int, prefixes: dict[tuple[int, int], list[bytes]]) -> list[bytes]:
    out: list[bytes] = []
    for d, e, f in itertools.product(PRINTABLE, repeat=3):
        state = target_fold & 0xFFFFFF
        state = ((state * FNV_INV_24) & 0xFFFFFF) ^ f
        state = ((state * FNV_INV_24) & 0xFFFFFF) ^ e
        state = ((state * FNV_INV_24) & 0xFFFFFF) ^ d
        prefix_xor = target_xor ^ d ^ e ^ f
        suffix = bytes((d, e, f))
        for prefix in prefixes.get((state, prefix_xor), ()):
            out.append(prefix + suffix)
    return out


def derive_p4(p1: bytes, p2: bytes, p3: bytes, p4_target: bytes) -> bytes | None:
    seed = (
        fold_ascii6_to_u24(p1)
        ^ rol24(fold_ascii6_to_u24(p2), 3)
        ^ rol24(fold_ascii6_to_u24(p3), 7)
    ) & 0xFFFFFF
    shifted_alphabet = bytes(BASE64_ALPHABET[(i + (seed & 0x3F)) & 0x3F] for i in range(64))
    reverse = {ch: i for i, ch in enumerate(shifted_alphabet)}

    try:
        values = [
            (reverse[ch] ^ ((seed >> ((i * 7) % 24)) & 0x3F)) & 0x3F
            for i, ch in enumerate(p4_target)
        ]
    except KeyError:
        return None

    raw = bytearray()
    for i in (0, 4):
        value = (values[i] << 18) | (values[i + 1] << 12) | (values[i + 2] << 6) | values[i + 3]
        raw.extend(((value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF))
    p4 = bytes(raw)
    return p4 if is_ascii6(p4) else None


def rc4_crypt(data: bytes, key: bytes) -> bytes:
    sbox = list(range(256))
    j = 0
    for i in range(256):
        j = (j + sbox[i] + key[i % len(key)]) & 0xFF
        sbox[i], sbox[j] = sbox[j], sbox[i]

    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + sbox[i]) & 0xFF
        sbox[i], sbox[j] = sbox[j], sbox[i]
        out.append(b ^ sbox[(sbox[i] + sbox[j]) & 0xFF])
    return bytes(out)


def read_apk(apk_path: Path) -> tuple[bytes, bytes, list[bytes], bytes]:
    with zipfile.ZipFile(apk_path, "r") as zf:
        data_bin = zf.read("assets/data.bin")
        flag_enc = zf.read("assets/flag.enc")
        dex_blob = b"".join(zf.read(name) for name in zf.namelist() if re.fullmatch(r"classes\d*\.dex", name))
        native_blobs = [
            zf.read(name)
            for name in zf.namelist()
            if name.endswith("/libscm_native.so")
        ]
    if not native_blobs:
        die("libscm_native.so not found in APK")
    return data_bin, flag_enc, native_blobs, dex_blob


def find_p1_hash(dex_blob: bytes) -> str | None:
    matches = sorted(set(re.findall(rb"[0-9A-F]{64}", dex_blob)))
    if not matches:
        return None
    for item in matches:
        if item.startswith(b"5475D82A"):
            return item.decode("ascii")
    return matches[0].decode("ascii")


def native_sha_pins(native_blobs: list[bytes], explicit_pin: bytes | None) -> set[bytes]:
    if explicit_pin is not None:
        return {explicit_pin}

    pins = set()
    default_pin = bytes.fromhex(DEFAULT_PIN_HEX)
    for blob in native_blobs:
        if default_pin in blob:
            pins.add(default_pin)
    if pins:
        return pins

    # Fallback: keep all 32-byte native windows as possible SHA-256 pins.
    # A candidate key must hash to one of these windows; false positives are negligible.
    for blob in native_blobs:
        for i in range(0, max(0, len(blob) - 31)):
            pins.add(blob[i : i + 32])
    return pins


def data_targets_by_p2_xor(data_bin: bytes, p1: bytes) -> dict[int, list[tuple[int, int]]]:
    want_hi = xor_ascii(p1)
    targets: dict[int, list[tuple[int, int]]] = defaultdict(list)
    for off in range(0, len(data_bin) - 2):
        raw = int.from_bytes(data_bin[off : off + 3], "little")
        decoded = (raw ^ 0xDEADBE) & 0xFFFFFF
        if (decoded >> 16) == want_hi:
            p2_xor = (decoded >> 8) & 0xFF
            targets[p2_xor].append(((off ^ 0xAAAAAA) & 0xFFFFFF, decoded & 0xFF))
    return targets


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Solve SCM time-capsule APKs.")
    parser.add_argument("inputs", nargs="*", default=["attachment-7.apk"], help="APK files, directories, or glob patterns")
    parser.add_argument("-r", "--recursive", action="store_true", help="scan directories recursively for APKs")
    parser.add_argument("--p1", help="six printable ASCII chars for part1")
    parser.add_argument("--p1-hex", default=DEFAULT_P1_HEX, help="hex-encoded p1 bytes")
    parser.add_argument("--p4-target", default=DEFAULT_P4_TARGET.decode("ascii"), help="8-byte native p4 target")
    parser.add_argument("--pin", help="SHA-256 key pin in hex; defaults to native scan")
    return parser.parse_args()


def expand_inputs(inputs: list[str], recursive: bool) -> list[Path]:
    apk_paths: list[Path] = []
    for item in inputs:
        matches = glob(item)
        paths = [Path(match) for match in matches] if matches else [Path(item)]
        for path in paths:
            if path.is_dir():
                iterator = path.rglob("*.apk") if recursive else path.glob("*.apk")
                apk_paths.extend(iterator)
            elif path.is_file() and path.suffix.lower() == ".apk":
                apk_paths.append(path)
    unique = sorted({path.resolve() for path in apk_paths})
    if not unique:
        die("no APK inputs found")
    return unique


def solve_one(
    apk_path: Path,
    p1: bytes,
    p4_target: bytes,
    explicit_pin: bytes | None,
    prefixes: dict[tuple[int, int], list[bytes]],
) -> tuple[bytes, bytes, bytes, bytes, bytes, str, int]:
    data_bin, flag_enc, native_blobs, dex_blob = read_apk(apk_path)

    p1_hash = find_p1_hash(dex_blob)
    if p1_hash:
        actual = hashlib.sha256(hashlib.sha256(p1).digest()).hexdigest().upper()
        if actual != p1_hash:
            raise ValueError(f"p1 hash mismatch: got {actual}, want {p1_hash}")

    pins = native_sha_pins(native_blobs, explicit_pin)
    p2_fold = part2_p2_fold_target(p1)
    targets_by_xor = data_targets_by_p2_xor(data_bin, p1)
    if not targets_by_xor:
        raise ValueError("no data.bin targets for this p1")

    p3_cache: dict[tuple[int, int], list[bytes]] = {}
    p2_cache: dict[int, list[bytes]] = {}
    checked = 0
    for p2_xor, data_targets in targets_by_xor.items():
        if p2_xor not in p2_cache:
            p2_cache[p2_xor] = ascii6_preimages(p2_fold, p2_xor, prefixes)
        for p2 in p2_cache[p2_xor]:
            for p3_fold, p3_xor in data_targets:
                cache_key = (p3_fold, p3_xor)
                if cache_key not in p3_cache:
                    p3_cache[cache_key] = ascii6_preimages(p3_fold, p3_xor, prefixes)
                for p3 in p3_cache[cache_key]:
                    p4 = derive_p4(p1, p2, p3, p4_target)
                    if p4 is None:
                        continue
                    key = p1 + p2 + p3 + p4
                    checked += 1
                    if hashlib.sha256(key).digest() not in pins:
                        continue
                    flag = rc4_crypt(flag_enc, key).decode("utf-8")
                    return p1, p2, p3, p4, key, flag, checked

    raise ValueError(f"no key found, checked {checked} p2/p3/p4 candidates")


def main() -> None:
    args = parse_args()
    apk_paths = expand_inputs(args.inputs, args.recursive)

    p1 = args.p1.encode("ascii") if args.p1 is not None else bytes.fromhex(args.p1_hex)
    if not is_ascii6(p1):
        die("p1 must be exactly six printable ASCII characters")

    p4_target = args.p4_target.encode("ascii")
    if len(p4_target) != 8:
        die("p4 target must be exactly 8 ASCII bytes")

    explicit_pin = bytes.fromhex(args.pin) if args.pin else None
    prefixes = build_prefix_table()

    any_failed = False
    for apk_path in apk_paths:
        print(f"=== {apk_path} ===")
        try:
            p1, p2, p3, p4, key, flag, checked = solve_one(apk_path, p1, p4_target, explicit_pin, prefixes)
        except (KeyError, UnicodeDecodeError, ValueError, zipfile.BadZipFile) as exc:
            any_failed = True
            print(f"error = {exc}")
            continue
        print("p1 =", p1.decode("ascii"))
        print("p2 =", p2.decode("ascii"))
        print("p3 =", p3.decode("ascii"))
        print("p4 =", p4.decode("ascii"))
        print("key =", key.decode("ascii"))
        print("checked =", checked)
        print("flag =", flag)

    if any_failed:
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("interrupted")
