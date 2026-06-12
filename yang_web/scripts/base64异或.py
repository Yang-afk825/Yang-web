import base64


# 1.åè§£å¼base64
b = base64.b64decode('aWdxNDs1NDFSOzFpa1I1MWliT08w')
# 2.è½¬æ¢ä¸ºasciiåè¿å¶
data = list(b)

# 3.ä¸[0, 200) å¼ææ¾å°ä¸ä¸ªæ²¡æç¬¦å·ç
for i in range(0, 200):
    key = ''
    for j in range(len(data)):
        key += chr(data[j]^i)
    print(key)
