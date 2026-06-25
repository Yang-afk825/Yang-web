import urllib.request
url = 'http://80-dd97d346-4448-4740-84d8-7c00b6a0c1f1.challenge.ctfplus.cn'
try:
    resp = urllib.request.urlopen(url, timeout=8)
    print(f'Status: {resp.status}')
    body = resp.read().decode('utf-8', errors='replace')
    print(f'Body({len(body)}): {body[:300]}')
except Exception as e:
    print(f'Error: {type(e).__name__}: {e}')
