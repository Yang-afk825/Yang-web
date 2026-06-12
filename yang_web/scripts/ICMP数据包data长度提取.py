#!/usr/bin/env python
import re,base64
a=open('0.pdml','r',encoding='utf-8').read()
b=str()
b=re.findall("<field name=\"data.len\" showname=\"Length: (.*?)\" size=\"",a)
e=''
for i in range(len(b)):
    e+=chr(int(b[i]))
print(base64.b64decode(e).decode())