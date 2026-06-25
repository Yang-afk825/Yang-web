import sys
sys.path.insert(0, '.')
from yang_web.core.url_analyzer import send_request, crawl_page
import re

url = 'http://80-c2103dc8-0f98-488b-bafe-852122c24402.challenge.ctfplus.cn'
r = send_request(url, timeout=8)
body = r.get('body', '')
print('ok:', r.get('ok'))
print('status:', r.get('status'))
print('body_len:', len(body))
print('GET in body:', 'GET' in body)
print('cmd in body:', 'cmd' in body)
print('_GET in body:', '_GET' in body)
# Search for PHP parameter patterns
for pat in [r'\$_GET\[[\'"](\w+)[\'"]', r'\$_POST\[[\'"](\w+)[\'"]', r'\$_REQUEST\[[\'"](\w+)[\'"]']:
    m = re.findall(pat, body)
    print(f'pattern {pat}: {m}')

# Also print the body snippet around _GET
idx = body.find('_GET')
if idx >= 0:
    print(f'Body around _GET: ...{body[max(0,idx-20):idx+80]}...')
