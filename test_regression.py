# -*- coding: utf-8 -*-
"""Regression test: make sure the ;append fix doesn't break the first challenge"""
import sys, os
sys.path.insert(0, '.')
from yang_web.core.url_analyzer import analyze_url, auto_exploit

url = 'http://80-dd97d346-4448-4740-84d8-7c00b6a0c1f1.challenge.ctfplus.cn'
print("Testing first challenge...")
result = analyze_url(url)
fp = result.get('fingerprint', {})
print(f"Vulns: {[(r['type'], r['confidence']) for r in result['results']]}")

final = auto_exploit(url, result['results'], fingerprint=fp)
print(f"Flag: {final.get('flag')}")
print(f"Attacks: {final.get('attacks_run')}")
print(f"Timing: {final.get('timing_ms')/1000:.1f}s")
