import sys; sys.path.insert(0, '.')
from yang_web.core.url_analyzer import analyze_url, auto_exploit

url = 'http://80-cce2b8e8-43df-4955-b9df-9b5e00f63e01.challenge.ctfplus.cn'

r = analyze_url(url)
print(f'Results: {len(r["results"])} 个')
for x in r.get('results', []):
    print(f'  [{x["confidence"]}%] {x["type"]}: {x.get("reasons",[])[:2]}')

fp = r.get('fingerprint', {})
php_v = fp.get('php_vulns', [])
for v in php_v:
    print(f'  PHP: {v["reason"]} ({v["confidence"]}%)')

print(f'\nAll fingerprint keys: {list(fp.keys())}')

# Run auto_exploit
final = auto_exploit(url, r['results'], fingerprint=fp)
print(f'\nFlag: {final.get("flag")}')
print(f'Stages: {final.get("stages")}')
print(f'Attacks: {final.get("attacks_run")}')
