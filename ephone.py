#!/usr/bin/python3
# -- coding: utf-8 --
# -------------------------------
# @Author : moxiaoying
# @Time : 2024/01/27 13:23
# -------------------------------
# cron "0 7 * * *" script-path=ephone.py,tag=益丰api签到
# 支持多账户：account#password@account2#password2
import os

import requests
import time

import hmac
import hashlib
import base64

session = requests.Session()


def generate_signature(data, key='your-secret-key-here', use_base64=False, use_upper=False):
    # Convert strings to bytes if they aren't already
    if isinstance(data, str):
        data = data.encode('utf-8')
    if isinstance(key, str):
        key = key.encode('utf-8')
    # Calculate HMAC-SHA256
    h = hmac.new(key, data, hashlib.sha256)
    # Get the result in either base64 or hex format
    if use_base64:
        result = base64.b64encode(h.digest()).decode('utf-8')
    else:
        result = h.hexdigest()
    # Convert to uppercase if requested
    if use_upper:
        result = result.upper()

    return result


def login(username, password):
    resp = session.post('https://api.ephone.ai/api/user/login?turnstile=',
                        json={'username': username, 'password': password}).json()
    if resp['success']:
        print(f"{resp['data']['username']}\t登录成功")
        return {
            'user_id': resp['data']['id'],
            'username': resp['data']['username'],
        }
    raise Exception(resp['message'])


def check_in(user_id=6179):
    url = "https://api.ephone.ai/api/user/checkin"

    # 获取当前时间的 10 位时间戳
    current_timestamp = int(time.time())
    # current_timestamp = '1736144324'

    querystring = {"timestamp": str(current_timestamp),
                   "signature": generate_signature(f'{current_timestamp}:{user_id}'),
                   "timezone": "Asia/Shanghai"}

    payload = ""
    headers = {
        "rix-api-user": str(user_id),
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
        "Connection": "keep-alive"
    }

    response = session.request("POST", url, data=payload, headers=headers, params=querystring)

    print(response.text)


def main():
    user_cookie = os.getenv("ephone")
    for user in user_cookie.split('@'):
        data = login(*user.split('#'))
        check_in(data['user_id'])
        time.sleep(1)
        print('等待1秒后开始下一账号签到')


if __name__ == '__main__':
    main()
