#!/usr/bin/python3
# -- coding: utf-8 --
# -------------------------------
# @Author : moxiaoying
# @Time : 2024/01/27 13:23
# -------------------------------
# cron "0 6 * * *" script-path=ztjun.py,tag=ztjun博客签到
# 支持多账户：account#password@account2#password2
import os
import re
import time

import requests
from bs4 import BeautifulSoup


class Ztjun:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session = requests.session()
        self.session.headers = {
            "authority": "ztjun.fun",
            "accept": "application/json, text/javascript, */*; q=0.01",
            "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            "content-type": "application/x-www-form-urlencoded",
            "origin": "https://ztjun.fun",
            "referer": "https://ztjun.fun/",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 Edg/116.0.1938.69",
            "x-requested-with": "XMLHttpRequest"
        }

    def login(self, username='', password=''):
        url = "https://ztjun.fun/wp-admin/admin-ajax.php"
        payload = {
            'action': 'zb_user_login',
            'user_name': username or self.username,
            'user_password': password or self.password,
            'rememberme': 'on',
            'nonce': self._get_nonce()
        }

        response = self.session.post(url, data=payload)
        response.encoding = 'utf-8'
        print(f'{self.username}:\t{response.json()}')
        return self.session

    def _get_nonce(self):
        url = 'https://ztjun.fun/user-2/user'
        response = self.session.get(url)
        response.encoding = 'utf-8'
        soup = BeautifulSoup(response.text, 'html.parser')
        script_tag = soup.find('script', {'id': 'main-js-extra'})
        if script_tag:
            script_text = script_tag.string
            match = re.search(r'"ajax_nonce":"(.*?)",', script_text)
            return match.group(1)
        raise Exception("未找到nonce")

    def sign(self):
        self.login()
        nonce = self._get_nonce()
        url = "https://ztjun.fun/wp-admin/admin-ajax.php"
        # payload = f"action=user_qiandao&nonce={nonce}"
        payload = {
            'action': 'zb_user_qiandao',
            'nonce': nonce
        }
        response = self.session.post(url, data=payload)
        response.encoding = 'utf-8'
        print(self.username, response.json())


def main():
    user_cookie = os.getenv("ztjun_cookie")
    for user in user_cookie.split('@'):
        spider = Ztjun(*user.split('#'))
        spider.sign()
        time.sleep(1)
        print('等待1秒后开始下一账号签到')


if __name__ == '__main__':
    main()
