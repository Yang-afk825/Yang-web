import urllib.request, re
url = 'http://80-2005f10e-b861-4aa9-8f0c-bc279804f290.challenge.ctfplus.cn'
resp = urllib.request.urlopen(url, timeout=10)
raw = resp.read().decode('utf-8', errors='replace')
# Find SYC_GEEK occurrences in raw HTML
for line in raw.split('\n'):
    if 'SYC_GEEK' in line or 'SYC_GEEK' in line:
        # Show raw bytes around SYC_GEEK
        idx = line.find('SYC_GEEK')
        snippet = line[idx:idx+30]
        print(repr(snippet))
        # Also check if dot or underscore
        for i, ch in enumerate(snippet):
            print(f"  [{i}] U+{ord(ch):04X} {repr(ch)}")
