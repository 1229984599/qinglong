#!/usr/bin/python3
# -- coding: utf-8 --
# -------------------------------
# @Author : moxiaoying
# @Time : 2024/01/27 13:23
# -------------------------------
# cron "0 7 * * *" script-path=ephone.py,tag=益丰api签到https://api.ephone.ai/panel
# 支持多账户：account#password@account2#password2
import os
import requests
import time
import hmac
import hashlib
import base64
import traceback

ocr_url = os.getenv("ocr_url", "https://rould-bot-ddddocr.hf.space/capcode")

session = requests.Session()


def base64_to_bytes(base64_str):
    if "," in base64_str:
        base64_str = base64_str.split(",")[1]
    return base64_str
    # return base64.b64decode(base64_str)


class CaptchaSolver:
    def __init__(self):
        self.headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6',
            'cache-control': 'no-store',
            'origin': 'https://api.ephone.ai',
            'referer': 'https://api.ephone.ai/login?expired=true',
            'rix-api-user': '6179',
            'sec-ch-ua': '"Microsoft Edge";v="135", "Not-A.Brand";v="8", "Chromium";v="135"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0'
        }

    def slide_match(self, background: str, target: str):
        res = requests.post(ocr_url, json={
            "backImage": base64_to_bytes(background),
            "slidingImage": base64_to_bytes(target),
        }).json()
        return res.get('result')

    def get_captcha(self):
        """获取滑块验证码"""
        url = 'https://api.ephone.ai/api/captcha/generate'
        response = session.post(url, headers=self.headers)
        if response.status_code != 200:
            raise Exception(f"获取验证码失败: {response.status_code}, {response.text}")

        return response.json()

    def solve_captcha(self, captcha_data):
        """识别滑块位置"""
        data = captcha_data.get('data', {})
        # target_bytes = base64_to_bytes(data["tileImage"])  # 滑块
        # background_bytes = base64_to_bytes(data["masterImage"])  # 背景
        # res = det.slide_match(target_bytes, background_bytes, simple_target=True)
        res = self.slide_match(data["masterImage"], data["tileImage"])
        return {
            "dots": {
                "x": res,
                "y": data.get('thumbY', 111)
            },
            "key": data.get('dots', ''),
        }

    def verify_captcha(self, solve_result):
        """验证滑块位置"""
        url = 'https://api.ephone.ai/api/captcha/verify'
        headers = self.headers.copy()
        headers['content-type'] = 'application/json'

        payload = {
            "dots": solve_result["dots"],
            "key": solve_result["key"]
        }

        response = session.post(url, headers=headers, json=payload)
        if response.status_code != 200:
            raise Exception(f"验证失败: {response.status_code}, {response.text}")

        result = response.json()
        return result

    def get_token(self, max_retries=3):
        """获取token的对外接口"""
        for retry in range(max_retries):
            try:
                # 获取验证码
                print(f"尝试 {retry + 1}/{max_retries}：正在获取验证码...")
                captcha_response = self.get_captcha()
                # print(f"验证码获取成功")

                # 识别滑块位置
                # print("正在识别滑块位置...")
                solve_result = self.solve_captcha(captcha_response)
                # print(f"滑块位置识别完成")

                # 验证滑块位置
                # print("正在验证滑块位置...")
                verify_result = self.verify_captcha(solve_result)

                if verify_result.get('success') == True:
                    print("验证成功!")
                    return verify_result.get('token')
                else:
                    print(f"验证失败: {verify_result}")
                    if retry < max_retries - 1:
                        time.sleep(2)

            except Exception as e:
                print(f"发生错误: {str(e)}")
                print(traceback.format_exc())
                if retry < max_retries - 1:
                    print(f"将在2秒后重试...")
                    time.sleep(2)

        print(f"已达到最大重试次数 {max_retries}，验证失败")
        return None


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
    # 获取验证码token
    captcha_solver = CaptchaSolver()
    token = captcha_solver.get_token()

    if not token:
        raise Exception("获取验证码token失败")

    # 登录请求
    resp = session.post('https://api.ephone.ai/api/user/login?turnstile=',
                        json={'username': username, 'password': password, 'token': token}).json()
    if resp['success']:
        print(f"{resp['data']['username']}\t登录成功")
        return {
            'username': resp['data']['username'],
        }
    raise Exception(resp['message'])


def check_in(username):
    # 获取验证码token
    captcha_solver = CaptchaSolver()
    token = captcha_solver.get_token()
    url = "https://api.ephone.ai/api/user/checkin"

    # 获取当前时间的 10 位时间戳
    current_timestamp = int(time.time())
    # current_timestamp = '1736144324'

    querystring = {"timestamp": str(current_timestamp),
                   "signature": generate_signature(f'{current_timestamp}:{username}'),
                   "timezone": "Asia/Shanghai",
                   "slide_captcha": token
                   }

    payload = ""
    headers = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
        "Connection": "keep-alive"
    }

    response = session.request("POST", url, data=payload, headers=headers, params=querystring)

    print(response.text)


def main():
    user_cookie = os.getenv("ephone")
    for user in user_cookie.split(' '):
        if not user:
            continue
        data = login(*user.split('#'))
        check_in(**data)
        time.sleep(1)
        print('等待1秒后开始下一账号签到')


if __name__ == '__main__':
    main()
