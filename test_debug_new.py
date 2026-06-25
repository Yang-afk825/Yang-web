import sys, os, re, html as _html
sys.path.insert(0, '.')
from yang_web.core.url_analyzer import analyze_url, auto_exploit, SmartFingerprinter

url = 'http://80-a4a01c12-a957-470b-8673-3ad7af9e202e.challenge.ctfplus.cn'

# First, test raw fingerprinter
import urllib.request
req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
resp = urllib.request.urlopen(req, timeout=10)
body = resp.read().decode('utf-8', errors='replace')
headers = dict(resp.headers)

print("=== SmartFingerprinter ===")
fp = SmartFingerprinter()
result = fp.fingerprint(headers, body, url)
print(f"CMS: {result['cms']} ({result['cms_confidence']}%)")
print(f"WAF: {result['waf']}")
print(f"PHP vulns: {len(result['php_vulns'])}")
for v in result['php_vulns']:
    print(f"  [{v['confidence']}%] {v['type']} - {v['reason']}")
print(f"PHP params: {result['php_params']}")

# Check raw body for eval(
clean = _html.unescape(re.sub(r'<[^>]+>', '', body))
print(f"\n'eval(' in raw body: {'eval(' in body}")
print(f"'eval(' in clean body: {'eval(' in clean}")
print(f"'eval' in clean: {'eval' in clean}")
if 'eval' in clean:
    idx = clean.index('eval')
    print(f"  context: ...{repr(clean[idx-5:idx+30])}...")

print(f"\n'\\\$_POST' in clean: {'\$_POST' in clean}")
print(f"\$_POS in clean: {'\$_POS' in clean}")
if '\$_POS' in clean:
    idx = clean.index('\$_POS')
    print(f"  context: ...{repr(clean[idx:idx+30])}...")

print("\n=== Full analyze_url ===")
result2 = analyze_url(url)
print(f"Results: {len(result2['results'])}")
for r in result2['results']:
    print(f"  {r['type']} {r['confidence']}% params={r['params']}")
fp2 = result2.get('fingerprint', {})
print(f"Fingerprint vulns: {fp2.get('php_vulns', [])}")
