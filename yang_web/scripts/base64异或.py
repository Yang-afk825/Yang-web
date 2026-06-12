import base64


# 1.先解开base64
b = base64.b64decode('aWdxNDs1NDFSOzFpa1I1MWliT08w')
# 2.转换为ascii十进制
data = list(b)

# 3.与[0, 200) 异或找到一个没有符号的
for i in range(0, 200):
    key = ''
    for j in range(len(data)):
        key += chr(data[j]^i)
    print(key)
