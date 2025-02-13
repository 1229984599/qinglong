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
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from loguru import logger


def create_session():
    session = requests.session()
    # 配置重试策略
    retry_strategy = Retry(
        total=3,  # 最大重试次数
        backoff_factor=1,  # 重试间隔
        status_forcelist=[500, 502, 503, 504]  # 需要重试的HTTP状态码
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


session = create_session()


def login(username, password):
    try:
        url = "https://ikuuu.one/auth/login"
        headers = {
            "authority": "ikuuu.one",
            "content-type": "application/x-www-form-urlencoded",
            "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

        response = session.post(
            url,
            data={
                "email": username,
                "passwd": password,
                "code": "",
                "remember_me": "on"
            },
            headers=headers,
            verify=False  # 禁用SSL验证
        )
        logger.info(f"登录响应: {response.json()}")
        return response.json()
    except Exception as e:
        logger.error(f"登录失败: {str(e)}")
        raise


def check_in():
    try:
        url = "https://ikuuu.one/user/checkin"
        response = session.post(url, verify=False)  # 禁用SSL验证
        logger.info(f"签到响应: {response.json()}")
        return response.json()
    except Exception as e:
        logger.error(f"签到失败: {str(e)}")
        raise


def main():
    try:
        # 禁用SSL警告
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        ikuuu_cookie = os.getenv("ikuuu_cookie")
        if not ikuuu_cookie:
            logger.error("未设置ikuuu_cookie环境变量")
            return

        username, password = ikuuu_cookie.split("#")
        login(username, password)
        check_in()

    except Exception as e:
        logger.error(f"程序执行出错: {str(e)}")


if __name__ == '__main__':
    main()
