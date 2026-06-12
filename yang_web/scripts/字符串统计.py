# -*- coding: utf-8 -*-
#!/usr/bin/env python

a="4b64ca12ace755516c178f72d05d7061"

b="ecd44646cfe5994ebeb35bf922e25dba"

c,d=list(),list()

for i in range(0,len(a),2):

    #print(a[i])

    c.append(a[i]+a[i+1])

#print(a^b)

for i in range(0,len(b),2):

    #print(a[i])

    d.append(b[i]+b[i+1])





for i in range(len(c)):



    print(chr(int(c[i],16)^int(d[i],16)),end='')