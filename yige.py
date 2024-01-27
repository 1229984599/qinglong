#!/usr/bin/python3
# -- coding: utf-8 --
# -------------------------------
# @Author : moxiaoying
# @Time : 2023/10/03 13:23
# -------------------------------
# cron "0 6 * * *" script-path=yige.py,tag=文心一格签到
# yige_cookie
import requests
import os

url = "https://yige.baidu.com/api/t2p/points/task_complete"

querystring = {"t": "1679910838539", "ptask_type": "6"}
cookie = os.environ["yige_cookie"]
headers = {
    "Content-Type": "*/*",
    "Cookie": cookie,
    "Referer": "https://yige.baidu.com/points",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36 Edg/111.0.1661.54"
}

response = requests.request("GET", url, headers=headers, params=querystring)

print(response.text)
