#!/usr/bin/python3
# -- coding: utf-8 --
# -------------------------------
# @Author : moxiaoying
# @Time : 2023/10/03 13:23
# -------------------------------
# cron "0 9 * * *" script-path=img_ink.py,tag=水墨图床签到
#
import os

import requests

url = "https://img.ink/user/moremore.html"
cookie = os.environ["img_ink_cookie"]
headers = {
    "authority": "img.ink",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
    "cache-control": "no-cache",
    "pragma": "no-cache",
    "referer": "https://img.ink/",
    "upgrade-insecure-requests": "1",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Cookie": cookie
}

response = requests.request("GET", url, headers=headers)

print(response.text)
