# -*- coding: utf-8 -*-
"""Debug: why FLAG_RE doesn't match the flag"""
import sys, os
sys.path.insert(0, '.')
import urllib.request
import re
import html as _html

url = 'http://80-d92fbb9d-0480-4a13-afc2-047c2ac7a6cd.challenge.ctfplus.cn'

# Simulate what send_request does
req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
resp = urllib.request.urlopen(req, timeout=10)
raw = resp.read()
body = raw.decode('utf-8', errors='replace')
body_truncated = body[:5000]

print(f"Body length: {len(body)}, truncated: {len(body_truncated)}")

# The FLAG_RE from url_analyzer.py
FLAG_RE = re.compile(
    r'(?:flag|ctf|iscc|hctf|ddctf|realworld|n1ctf|suctf|wmctf|geesec|dasctf|sigpwny|cyber|hack|pico|tjctf|angstrom|dctf|ractf|zh3r0|inctf|darkctf|csictf|ritsec|nactf|b01lers|kksctf)'
    r'\{([^}]+)\}',
    re.IGNORECASE
)

# Test FLAG_RE
flags = FLAG_RE.findall(body_truncated)
print(f"\nFLAG_RE.findall on raw body: {flags}")

# Also test on HTML-stripped body
clean = _html.unescape(re.sub(r'<[^>]+>', '', body))
flags_clean = FLAG_RE.findall(clean)
print(f"FLAG_RE.findall on clean body: {flags_clean}")

# Also test direct regex
simple_re = re.compile(r'Geesec\{([^}]+)\}', re.IGNORECASE)
flags_simple = simple_re.findall(body_truncated)
print(f"simple_re.findall on raw body: {flags_simple}")

# Check if 'Geesec{' exists literally
print(f"\n'Geesec{{' in raw body: {'Geesec{' in body_truncated}")
idx = body_truncated.find('Geesec{')
if idx >= 0:
    print(f"  Found at index {idx}: ...{body_truncated[idx:idx+50]}...")

# Check the regex character-by-character
test_str = 'Geesec{6959879d-00da-4363-bb4d-c0edab4d43b1}'
print(f"\nTest string: {test_str}")
print(f"FLAG_RE.match: {FLAG_RE.search(test_str)}")
print(f"simple_re.match: {simple_re.search(test_str)}")
print(f"geesec in FLAG_RE alternation: {'geesec' in FLAG_RE.pattern}")
