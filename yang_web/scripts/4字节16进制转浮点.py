import struct,os
s = input("输入4字节的16进制值：")
s=s.replace(" ",'')
print(s)
#<是小端，>是大端，f代表浮点数
print(struct.unpack('<f', bytes.fromhex(s))[0])#小端
#输出：120.40420532226562
s = float('6.55563714424545E-10')
#print(struct.pack('<f', s).hex())#小端
#输出：32333430
#print(struct.pack('>f', s).hex())#大端
#输出：30343332
os.system("pause")