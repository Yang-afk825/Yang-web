from colorama import init,Fore,Back,Style
init(autoreset=True)
a = '''
âââ     âââââââ      âââ   âââ     âââââââ     âââ    âââ
âââ       âââââ      ââââ ââââ   âââââââââââ   âââ    âââ
âââ       âââ         âââââââ    âââ     âââ   âââ    âââ
âââ       âââ          âââââ     âââ     âââ   âââ    âââ
âââââââ âââââââ         âââ       ââââââââââ    âââââââââ
âââââââ âââââââ         âââ        âââââââ       âââââââ        V1.0 
    
       âââ
    âââââââââ
       ââââââ     ä½èï¼æç±
       âââ        èªå¨è·baseææå®¶æçç¨åº
       âââ
    '''
print('\033[1;31;40m''{0}'.format(a))

import base64,sys
import py3base92
import base58
flag = input("è¾å¥éè¦è§£å¯åå®¹ï¼")

number = 0
i=10
while(i):
    number += 1
    try:
        flag = base64.b16decode(flag).decode()
        print(Fore.GREEN+ 'ãç¬¬{0}æ¬¡|base16è§£å¯ç»æã:'.format(number)  + flag)
        print(Fore.RESET+ '-'*30)
    except:
        try:
            flag = base64.b32decode(flag).decode()
            print(Fore.BLUE+ 'ãç¬¬{0}æ¬¡|base32è§£å¯ç»æã:'.format(number) + flag)
            print(Fore.RESET+'-'*30)
        except:
            try:
                flag = base58.b58decode(flag).decode()
                print(Fore.CYAN+ 'ãç¬¬{0}æ¬¡|base58è§£å¯ç»æã:'.format(number) +flag)
                print(Fore.RESET+'-'*30) 
            except:
                try:
                    flag = base64.b64decode(flag).decode()
                    print(Fore.RED+ 'ãç¬¬{0}æ¬¡|base64è§£å¯ç»æã:'.format(number) + flag) 
                    print(Fore.RESET+'-'*30)
                except:
                    try:
                        flag = base64.b85decode(flag).decode()
                        print(Fore.YELLOW+ 'ãç¬¬{0}æ¬¡|base85è§£å¯ç»æã:'.format(number) +flag)
                        print(Fore.RESET+'-'*30) 
                    except:
                        try:
                            flag = py3base92.decode(flag)
                            print(Fore.WHITE+ 'ãç¬¬{0}æ¬¡|base92è§£å¯ç»æã:'.format(number) + flag) 
                            print(Fore.RESET+'-'*30)                        
                        except:
                            i=i-1

                