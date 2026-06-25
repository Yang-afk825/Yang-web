import sys
sys.path.insert(0, '.')
from yang_web.core.url_analyzer import analyze_url, execute_attack

url = 'http://80-c2103dc8-0f98-488b-bafe-852122c24402.challenge.ctfplus.cn'
r = analyze_url(url)

for x in r.get("results", [])[:1]:
    pp = x.get("params", [""])[0]
    for pdef in x.get("payloads", [])[:2]:
        print(f"\n=== Attack: {pdef['name']} param={pp} ===")
        res = execute_attack(url, pp, pdef, http_method="GET", form_inputs=None)
        analysis = res.get("analysis", {})
        resp = res.get("response", {})
        print(f"  status={resp.get('status')} len={resp.get('body_len')} time={resp.get('elapsed_ms')}ms")
        print(f"  success={analysis.get('success')} detail={analysis.get('detail','')[:100]}")
        if resp.get('error'):
            print(f"  ERROR: {resp['error'][:200]}")
        body = resp.get('body', '')
        if body:
            print(f"  body[:300]: {body[:300]}")
