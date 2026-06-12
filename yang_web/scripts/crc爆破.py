import struct
import zlib

def hexStr2bytes(s):
    b = b""
    for i in range(0,len(s),2):
        temp = s[i:i+2]
        b +=struct.pack("B",int(temp,16))
    return b

str1="49484452"
str2="0802000000"
bytes1=hexStr2bytes(str1)
bytes2=hexStr2bytes(str2)
wid,hei = 0x16f,0x16f

crc32 = "0x84b2e9ce"

for w in range(wid,wid+2000):
    for h in range(hei,hei+2000):
        width = hex(w)[2:].rjust(8,'0')
        height = hex(h)[2:].rjust(8,'0')
        bytes_temp=hexStr2bytes(width+height)
        if eval(hex(zlib.crc32(bytes1+bytes_temp+bytes2))) == eval(crc32):
            print(hex(w),hex(h))#!/usr/bin/env python

