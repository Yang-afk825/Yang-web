#!/usr/bin/env python
#coding=utf-8
import paramiko

sshc = paramiko.SSHClient()
sshc.set_missing_host_key_policy(paramiko.AutoAddPolicy())

host = "172.16.1."

for i in range(120,131):
    tag = host+str(i)
    print tag
    try:
        try:
            sshc.connect(tag,22,'root','123456',timeout=1)
        except:
            sshc.connect(tag,22,'admin','123456',timeout=1)
        print sshc.exec_command('cat /root/flaginfo*')[1].readlines()
    except:
        print 'time out'