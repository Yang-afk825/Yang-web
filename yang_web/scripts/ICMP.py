# -*- coding: utf-8 -*-
#!/usr/bin/env python



from scapy.all import *

import optparse

import threading

import os



def scan(ipt):

    pkt=IP(dst=ipt)/ICMP()

    res=sr1(pkt,timeout=0.1,verbose=0)

    if res:

        print(ipt,' is online')

    

def main():

    parser=optparse.OptionParser("%prog "+"-t <target> -f <filename>")

    parser.add_option('-t',dest='target',type='string',help='Target')

    parser.add_option('-f',dest='fil',type='string',help='Filename')

    (options,args)=parser.parse_args()

    target=options.target

    fil=options.fil

    if(target==None) and (fil==None):

        print('Please input target(-t) or file(-f)')

        exit(0)



    if target:

        iplist=target.split('.')

        ip=iplist[0]+'.'+iplist[1]+'.'+iplist[2]+'.'

        for t in range(1,255):

            ipt=ip+str(t)

            t=threading.Thread(target=scan,args=(ipt,))

            t.start()

    if fil:

        if os.path.exists(fil):

            with open(fil) as f:

                for i in f.readlines():

                    ipt=i.strip('\n')

                    t=threading.Thread(target=scan,args=(ipt,))

                    t.start()

        else:

            print('File is not exists!')

            exit(0)



if __name__=='__main__':

    main()