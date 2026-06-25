import urllib.request, re, html as _html
url = 'http://80-a4a01c12-a957-470b-8673-3ad7af9e202e.challenge.ctfplus.cn'
try:
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    resp = urllib.request.urlopen(req, timeout=10)
    raw = resp.read()
    body = raw.decode('utf-8', errors='replace')
    print(f'Status: {resp.status}')
    print(f'Content-Type: {resp.headers.get("Content-Type", "")}')
    print(f'Raw length: {len(raw)} bytes')
    # Clean it
    clean = _html.unescape(re.sub(r'<[^>]+>', '', body))
    print(f'Clean length: {len(clean)} chars')
    print('='*60)
    print(clean[:3000])
except Exception as e:
    print(f'Error: {type(e).__name__}: {e}')
