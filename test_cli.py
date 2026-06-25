import sys, json, io
sys.path.insert(0, r'C:\Users\阳\.qclaw\workspace\Yang-web')
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
from yang_web.core.url_analyzer import analyze_url

url = 'http://test.com/index.php?id=1'
result = analyze_url(url)
print('Results count:', len(result.get('results', [])))
print('Stats:', json.dumps(result.get('stats', {})))
if result.get('error'):
    print('Error:', result['error'])
for r in result.get('results', []):
    print(f"  - {r['type']}: {r['confidence']}%")
