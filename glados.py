#!/usr/bin/python3
# -- coding: utf-8 --
# -------------------------------
# @Author : moxiaoying
# @Time : 2023/10/03 13:23
# -------------------------------
# cron "0 9 * * *" script-path=glados.py,tag=GLaDOS自动签到
# glados_cookie

import json
import os
import requests

# 获取glados账号对应cookie（在青龙面板的环境变量中设置galdos_cookie）
cookie = os.environ["glados_cookie"]


def start():
    checkin_url = "https://glados.one/api/user/checkin"
    status_url = "https://glados.one/api/user/status"
    origin = "https://glados.one"
    useragent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.75 Safari/537.36"
    payload = {
        'token': "glados.one"
    }

    checkin = requests.post(checkin_url, headers={
        'cookie': cookie,
        'origin': origin,
        'user-agent': useragent,
        'content-type': 'application/json;charset=UTF-8'
    }, data=json.dumps(payload))

    state = requests.get(status_url, headers={
        'cookie': cookie,
        'user-agent': useragent
    })
    if 'message' in checkin.text:
        mess = checkin.json()['message']
        time = state.json()['data']['leftDays'].split('.')[0]
        print("签到任务执行成功，" + '您的Glasod账号 ' + time + ' 天后到期，' + mess)


if __name__ == '__main__':
    start()
