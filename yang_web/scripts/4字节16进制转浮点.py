import struct,os
s = input("è¾å¥4å­èç16è¿å¶å¼ï¼")
s=s.replace(" ",'')
print(s)
#<æ¯å°ç«¯ï¼>æ¯å¤§ç«¯ï¼fä»£è¡¨æµ®ç¹æ°
print(struct.unpack('<f', bytes.fromhex(s))[0])#å°ç«¯
#è¾åºï¼120.40420532226562
s = float('6.55563714424545E-10')
#print(struct.pack('<f', s).hex())#å°ç«¯
#è¾åºï¼32333430
#print(struct.pack('>f', s).hex())#å¤§ç«¯
#è¾åºï¼30343332
os.system("pause")