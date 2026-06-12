# -*- coding: utf-8 -*-
from colorama import init,Fore,Back,Style

init(autoreset=True)

a = '''

██╗     ██████╗      ██╗   ██╗     ██████╗     ██╗    ██╗

██║       ██╔═╝      ╚██╗ ██╔╝   ██╔═════██║   ██║    ██║

██║       ██║         ╚████╔╝    ██║     ██║   ██║    ██║

██║       ██║          ╚██╔╝     ██║     ██║   ██║    ██║

██████╗ ██████╗         ██║       ╚██████╔═╝    ╚██████╔╝

╚═════╝ ╚═════╝         ╚═╝        ╚═════╝       ╚═════╝        V1.0 

    

       ██╗

    ████████╗

       ██╔══╝     作者：李由

       ██║        自动跑base所有家族的程序

       ╚═╝

    '''

print('\033[1;31;40m''{0}'.format(a))



import base64,sys

import py3base92

import base58

flag = input("输入需要解密内容：")



number = 0

i=10

while(i):

    number += 1

    try:

        flag = base64.b16decode(flag).decode()

        print(Fore.GREEN+ '【第{0}次|base16解密结果】:'.format(number)  + flag)

        print(Fore.RESET+ '-'*30)

    except:

        try:

            flag = base64.b32decode(flag).decode()

            print(Fore.BLUE+ '【第{0}次|base32解密结果】:'.format(number) + flag)

            print(Fore.RESET+'-'*30)

        except:

            try:

                flag = base58.b58decode(flag).decode()

                print(Fore.CYAN+ '【第{0}次|base58解密结果】:'.format(number) +flag)

                print(Fore.RESET+'-'*30) 

            except:

                try:

                    flag = base64.b64decode(flag).decode()

                    print(Fore.RED+ '【第{0}次|base64解密结果】:'.format(number) + flag) 

                    print(Fore.RESET+'-'*30)

                except:

                    try:

                        flag = base64.b85decode(flag).decode()

                        print(Fore.YELLOW+ '【第{0}次|base85解密结果】:'.format(number) +flag)

                        print(Fore.RESET+'-'*30) 

                    except:

                        try:

                            flag = py3base92.decode(flag)

                            print(Fore.WHITE+ '【第{0}次|base92解密结果】:'.format(number) + flag) 

                            print(Fore.RESET+'-'*30)                        

                        except:

                            i=i-1



                