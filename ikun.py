#!/usr/bin/python3
# -- coding: utf-8 --
# -------------------------------
# @Author : moxiaoying
# @Time : 2023/10/03 13:23
# -------------------------------
# cron "0 6 * * *" script-path=ikun.py,tag=IKuuu机场签到
# ikuuu_cookie account#password
import requests
import os

session = requests.session()


# 登录
def login(username, password):
    url = "https://ikuuu.pw/auth/login"

    headers = {
        "authority": "ikuuu.pw",
        "content-type": "application/x-www-form-urlencoded",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.41"
    }

    response = session.post(url, data={
        "email": username,
        "passwd": password,
        "code": "",
        "remember_me": "on"
    }, headers=headers)
    print(response.json())


def check_in():
    url = "https://ikuuu.pw/user/checkin"
    response = session.post(url)
    print(response.json())


def main():
    ikuuu_cookie = os.getenv("ikuuu_cookie")
    username, password = ikuuu_cookie.split("#")
    login(username, password)
    check_in()


if __name__ == '__main__':
    main()
