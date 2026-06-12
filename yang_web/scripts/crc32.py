
#!/usr/bin/env python
 
# -*- coding:utf-8 -*-
import datetime
import binascii
 
def showTime():
 
    print datetime.datetime.now().strftime("%H:%M:%S")  
 
def crack():
    crcs = set([0xd1f4eb9a,0x4d80857e,0x465d77b2,0x62d0bd17,0x57c3c2d1])
    r = xrange(32, 127)
    for a in r:
        for b in r:
            for c in r:
                for d in r:
                    txt = chr(a)+chr(b)+chr(c)+chr(d)
                    crc = binascii.crc32(txt)
                    if (crc & 0xFFFFFFFF) in crcs:
                        print txt
 
 
if __name__ == "__main__":
 
    showTime()
 
    crack()
 
    showTime()
