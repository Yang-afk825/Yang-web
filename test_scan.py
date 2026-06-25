import sys
sys.path.insert(0, '.')
from yang_web.core.url_analyzer import analyze_url

for path in ['/login', '/admin', '/flag']:
    url = f'http://80-c2103dc8-0f98-488b-bafe-852122c24402.challenge.ctfplus.cn{path}'
    r = analyze_url(url)
    c = r.get('crawl') or {}
    body = c.get('body', '')[:300]
    print(f'\n=== {path} ===')
    print(f'  results: {len(r.get("results",[]))}')
    print(f'  params: {c.get("discovered_params",[])}')
    print(f'  forms: {len(c.get("forms",[]))}')
    print(f'  body_len: {c.get("stats",{}).get("body_len")}')
    print(f'  body[:300]: {body}')
