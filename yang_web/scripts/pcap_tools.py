# -*- coding: utf-8 -*-
"""PCAP/Wireshark helpers — extract data from packet captures (zero-deps)."""

from __future__ import annotations
import struct
import sys
import os

PCAP_GLOBAL_HEADER = struct.Struct("<IHHiIII")
PCAP_PACKET_HEADER = struct.Struct("<IIII")


def read_pcap(path: str) -> list:
    """Simple PCAP reader — extracts raw packet data."""
    packets = []
    with open(path, "rb") as f:
        header = f.read(24)
        if len(header) < 24:
            raise ValueError("not a valid pcap file")
        magic, ver_major, ver_minor, tz, sigfigs, snaplen, linktype = PCAP_GLOBAL_HEADER.unpack(header)

        while True:
            ph = f.read(16)
            if len(ph) < 16:
                break
            ts_sec, ts_usec, incl_len, orig_len = PCAP_PACKET_HEADER.unpack(ph)
            data = f.read(incl_len)
            if len(data) < incl_len:
                break
            packets.append({
                "ts": f"{ts_sec}.{ts_usec:06d}",
                "len": incl_len,
                "data": data,
            })
    return packets


def extract_icmp_data(path: str) -> str:
    """Extract data payloads from ICMP echo packets."""
    raw = b""
    for pkt in read_pcap(path):
        data = pkt["data"]
        # Skip Ethernet header (14) + IP header (20) + ICMP header (8)
        offset = 14 + 20 + 8
        if len(data) > offset:
            raw += data[offset:]
    return raw.decode("utf-8", errors="replace") if raw else ""


def extract_http_bodies(path: str) -> list:
    """Extract HTTP response bodies from PCAP."""
    results = []
    for pkt in read_pcap(path):
        data = pkt["data"]
        try:
            text = data.decode("utf-8", errors="ignore")
            if "HTTP/" in text and "\r\n\r\n" in text:
                body = text.split("\r\n\r\n", 1)[-1]
                if body.strip():
                    results.append(body[:500])
        except Exception:
            pass
    return results


def extract_dns_queries(path: str) -> list:
    """Extract DNS query names from PCAP."""
    queries = []
    for pkt in read_pcap(path):
        data = pkt["data"]
        offset = 14 + 20 + 8  # Eth + IP + UDP
        if len(data) > offset + 12:
            dns = data[offset + 12:]  # Skip DNS header
            try:
                name = _decode_dns_name(dns)
                if name:
                    queries.append(name)
            except Exception:
                pass
    return queries


def _decode_dns_name(data: bytes) -> str:
    parts = []
    pos = 0
    while pos < len(data):
        length = data[pos]
        if length == 0:
            break
        if length >= 0xC0:
            # Pointer
            break
        pos += 1
        parts.append(data[pos:pos + length].decode("ascii", errors="replace"))
        pos += length
    return ".".join(parts)


def extract_all_data(path: str, base64_decode: bool = False) -> dict:
    """Extract all extractable data from PCAP."""
    import base64
    result = {"icmp": extract_icmp_data(path), "http": extract_http_bodies(path),
              "dns": extract_dns_queries(path), "raw_packets": len(read_pcap(path))}

    if base64_decode and result["icmp"]:
        try:
            decoded = base64.b64decode(result["icmp"])
            result["icmp_decoded"] = decoded.decode("utf-8", errors="replace")
        except Exception:
            pass
    return result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python pcap_tools.py <file.pcap> [--icmp] [--http] [--all]")
        sys.exit(0)

    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    path = sys.argv[1]
    if not os.path.isfile(path):
        print(f"File not found: {path}")
        sys.exit(1)

    mode = sys.argv[2] if len(sys.argv) > 2 else "--all"

    if mode == "--icmp":
        data = extract_icmp_data(path)
        print("ICMP data:", data[:500])
    elif mode == "--http":
        for i, body in enumerate(extract_http_bodies(path)):
            print(f"--- HTTP body {i+1} ---")
            print(body[:300])
    elif mode == "--all":
        result = extract_all_data(path)
        print(f"Packets: {result['raw_packets']}")
        print(f"ICMP data ({len(result['icmp'])}B): {result['icmp'][:200]}")
        print(f"DNS queries: {result['dns'][:10]}")
        print(f"HTTP bodies: {len(result['http'])} found")
    else:
        print("Unknown mode:", mode)
