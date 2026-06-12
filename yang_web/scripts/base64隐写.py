import string
import argparse


parser = argparse.ArgumentParser()
parser.add_argument('-f', type=str, default=None, required=True,
                    help='è¾å¥æä»¶åç§°')
args  = parser.parse_args()

# ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
key = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"

# 1.è·åå¯æ
with open(args.f, "r") as f:
    data = f.readlines()
data = [i.replace("\n", "") for i in data]

'''
1.ä¾æ¬¡è¯»åæ¯è¡ï¼ä»ä¸­æååºéåä½ã
2.å¦ææåæ²¡æâ=âï¼è¯´ææ²¡æéåä½ï¼è·³è¿ã
3.å¦ææåæ¯ä¸ä¸ªâ=âï¼è¯´ææä¸¤ä½éåä½ï¼å°åæ°ç¬¬äºä¸ªå­ç¬¦è½¬åä¸ºå¯¹åºçäºè¿å¶ç´¢å¼ï¼ç¶åååä¸¤ä½ã
4.å¦ææåæ¯ä¸¤ä¸ªâ=âï¼è¯´ææåä½éåä½ï¼å°åæ°ç¬¬ä¸ä¸ªå­ç¬¦è½¬åä¸ºå¯¹åºçäºè¿å¶ç´¢å¼ï¼ç¶ååååä½ã
5.è®°ä½è¦è¡¥é½8ä½ååå2ä½åå4ä½ï¼å¦æä¸è¡¥é½çè¯æ¯å¦è¯´éå°äºB --> "1"ï¼è¡¥é½åè½å¾å°"01"ï¼ä¸è¡¥é½å°±æ¯"1"ï¼é£å°±éäº
6.å°æ¯è¡æååºçéåä½ä¾æ¬¡è¿æ¥èµ·æ¥ï¼æ¯8ä½ä¸ºä¸ç»è½¬æ¢ä¸ºASCIIå­ç¬¦ï¼æåä¸è¶³8ä½çä¸¢å¼ã
'''

bin_str = ""
for cipher in data:
    flag = 0
    if cipher[-1:] == "=":
        flag = 1
        if cipher[-2:] == "==":
            flag = 2
    
    if flag == 1:
        bin_str += bin(key.index(cipher[-2]))[2:].zfill(8)[-2:]
    elif flag == 2:
        bin_str += bin(key.index(cipher[-3]))[2:].zfill(8)[-4:]

print("".join(chr(int(bin_str[i*8:i*8+8], 2)) for i in range(len(bin_str) // 8)))