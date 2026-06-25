import sys
sys.path.insert(0, '.')
from yang_web.core.url_analyzer import analyze_url

url = 'http://80-c2103dc8-0f98-488b-bafe-852122c24402.challenge.ctfplus.cn'
r = analyze_url(url)
print("results:", len(r.get("results", [])))
c = r.get("crawl") or {}
print("params:", c.get("discovered_params", []))
for x in r.get("results", [])[:5]:
    t = x["type"]
    cn = x["type_cn"]
    conf = x["confidence"]
    pp = x.get("params", [])
    pl = len(x.get("payloads", []))
    print(f"  {t} {cn} conf={conf} params={pp} payloads={pl}")
    for pdef in x.get("payloads", [])[:2]:
        print(f"    payload: {pdef['name']}")
