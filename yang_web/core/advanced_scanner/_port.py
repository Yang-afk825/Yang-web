"""yang_web.core.advanced_scanner 子模块 _port（自 advanced_scanner.py 拆分，请勿手工重排）。"""

from __future__ import annotations
import re
import ssl
import socket
import time
import threading
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, List, Optional, Tuple, Callable, Set
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from collections import defaultdict




# ═══════════════════════════════════════════════════════════
#  5. Quick Port Scanner
# ═══════════════════════════════════════════════════════════

class QuickPortScanner:
    """快速端口扫描器 — 探测目标常见端口.

    用于CTF: 发现隐藏的Web服务、数据库、Redis等服务.
    """

    # CTF常见端口及服务
    CTF_PORTS = {
        21: "FTP", 22: "SSH", 23: "Telnet",
        80: "HTTP", 443: "HTTPS", 8080: "HTTP-Alt",
        3306: "MySQL", 6379: "Redis", 27017: "MongoDB",
        5432: "PostgreSQL", 1433: "MSSQL",
        11211: "Memcached", 9200: "Elasticsearch",
        5000: "Flask-Dev", 8000: "HTTP-Dev",
        8888: "HTTP-Alt", 9000: "HTTP-Alt",
        9090: "HTTP-Alt", 3000: "Node.js",
        4000: "HTTP-Dev", 6000: "HTTP-Dev",
        7001: "WebLogic", 7002: "WebLogic-SSL",
        8088: "HTTP-Alt", 8089: "HTTP-Alt",
        8443: "HTTPS-Alt", 8880: "HTTP-Alt",
        9001: "HTTP-Alt", 10000: "Webmin",
    }

    def __init__(self, host: str, timeout: float = 1.0, max_workers: int = 30):
        self.host = host
        self.timeout = timeout
        self.max_workers = max_workers

    def scan(self, ports: List[int] = None, on_progress=None) -> dict:
        """Quick TCP connect scan.

        Args:
            ports: Port list to scan, defaults to CTF_PORTS.keys()
            on_progress: Callable(stage, item, status)

        Returns:
            {"host": str, "open_ports": [{"port": int, "service": str}],
             "total": int, "open": int}
        """
        if ports is None:
            ports = list(self.CTF_PORTS.keys())

        open_ports = []
        t0 = time.time()

        def _emit(stage, item, status):
            if on_progress:
                try:
                    on_progress(stage, item, status)
                except Exception:
                    pass

        _emit("port_scan", f"端口扫描 {self.host}", f"共 {len(ports)} 端口")

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._check_port, port): port for port in ports}
            for future in as_completed(futures, timeout=self.timeout * len(ports) + 5):
                port = futures[future]
                try:
                    is_open, banner = future.result(timeout=2)
                    if is_open:
                        service = self.CTF_PORTS.get(port, "Unknown")
                        open_ports.append({"port": port, "service": service, "banner": banner})
                        _emit("port_found", f"{port}/{service}", banner or "")
                except Exception:
                    pass

        timing = int((time.time() - t0) * 1000)
        return {
            "host": self.host,
            "open_ports": sorted(open_ports, key=lambda x: x["port"]),
            "total": len(ports),
            "open": len(open_ports),
            "timing_ms": timing,
        }

    def _check_port(self, port: int) -> Tuple[bool, str]:
        """Check if a TCP port is open and grab initial banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.host, port))
            if result == 0:
                banner = ""
                try:
                    sock.settimeout(1)
                    # Try to receive banner for common services
                    if port in (80, 8080, 8000, 8888, 9000, 3000, 5000):
                        sock.send(b"GET / HTTP/1.0\r\nHost: " + self.host.encode() + b"\r\n\r\n")
                    data = sock.recv(1024)
                    banner = data.decode("utf-8", errors="replace").split("\n")[0][:80].strip()
                except Exception:
                    pass
                sock.close()
                return True, banner
            sock.close()
            return False, ""
        except Exception:
            return False, ""
