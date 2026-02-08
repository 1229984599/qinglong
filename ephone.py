#!/usr/bin/python3
# -- coding: utf-8 --
# -------------------------------
# @Author : moxiaoying
# @Time : 2024/01/27 13:23
# -------------------------------
# cron "*/30 7-23 * * *" script-path=ephone.py,tag=益丰api签到https://api.ephone.ai/panel
# 支持多账户：account#password@account2#password2
import os
import json
import re
import requests
import time
import hmac
import hashlib
import base64
import traceback
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

ocr_url = os.getenv("ocr_url", "https://rould-bot-ddddocr.hf.space/capcode")
progress_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ephone_progress.json")

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


def parse_accounts_from_json_data(data):
    if isinstance(data, dict):
        for key in ("accounts", "data", "items", "list"):
            if isinstance(data.get(key), list):
                data = data[key]
                break

    if not isinstance(data, list):
        return []

    accounts = []
    for idx, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            print(f"JSON账号第 {idx} 项不是对象，已跳过")
            continue

        username = item.get("username")
        password = item.get("password")
        if username is None or password is None:
            print(f"JSON账号第 {idx} 项缺少 username/password，已跳过")
            continue

        username = str(username).strip()
        password = str(password).strip()
        if not username or not password:
            print(f"JSON账号第 {idx} 项 username/password 为空，已跳过")
            continue

        accounts.append((username, password))

    return accounts


def parse_accounts_from_legacy(raw_value):
    # 历史格式：account#password account2#password2
    # 兼容单行用 @ 分隔多账号的旧写法：account#password@account2#password2
    if raw_value.count("#") > 1 and "@" in raw_value and not re.search(r"\s", raw_value):
        items = [i for i in raw_value.split("@") if i]
    else:
        items = raw_value.split()

    accounts = []
    for item in items:
        if "#" not in item:
            print(f"环境变量账号格式错误，已跳过: {item}")
            continue

        username, password = item.split("#", 1)
        username = username.strip()
        password = password.strip()
        if not username or not password:
            print(f"环境变量账号缺少用户名或密码，已跳过: {item}")
            continue

        accounts.append((username, password))
    return accounts


def strip_wrapping_quotes(value):
    value = (value or "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1].strip()
    return value


def parse_accounts_from_env(raw_value):
    value = (raw_value or "").strip()
    if not value:
        return []

    # 新格式：ephone 直接放 accounts_ephone.json 的 JSON 字符串
    # 兼容外层被单/双引号包裹以及 \n 换行转义。
    json_candidates = []

    def add_candidate(candidate):
        candidate = (candidate or "").strip()
        if candidate and candidate not in json_candidates:
            json_candidates.append(candidate)

    add_candidate(value)
    add_candidate(strip_wrapping_quotes(value))
    for candidate in list(json_candidates):
        if "\\n" in candidate:
            add_candidate(candidate.replace("\\n", "\n"))

    parse_error = None
    for candidate in json_candidates:
        if candidate[0] not in "[{":
            continue
        try:
            json_accounts = parse_accounts_from_json_data(json.loads(candidate))
            if json_accounts:
                print(f"使用环境变量 ephone(JSON格式) 账号，共 {len(json_accounts)} 个")
                return json_accounts
            print("ephone JSON格式已识别，但没有可用账号，将尝试旧格式解析")
        except Exception as e:
            parse_error = e

    if parse_error is not None:
        print(f"ephone JSON解析失败，将尝试旧格式解析: {parse_error}")

    legacy_accounts = parse_accounts_from_legacy(strip_wrapping_quotes(value))
    if legacy_accounts:
        print(f"使用环境变量 ephone(旧格式) 账号，共 {len(legacy_accounts)} 个")
    return legacy_accounts


def load_accounts():
    env_value = os.getenv("ephone", "").strip()
    if not env_value:
        raise ValueError("环境变量 ephone 未设置")

    accounts = parse_accounts_from_env(env_value)
    if accounts:
        return accounts

    raise ValueError("环境变量 ephone 中未解析到可用账号")


def today_str():
    return now_shanghai().strftime("%Y-%m-%d")


def now_str():
    return now_shanghai().strftime("%Y-%m-%d %H:%M:%S")


def now_shanghai():
    try:
        return datetime.now(ZoneInfo("Asia/Shanghai"))
    except Exception:
        # 兜底：当系统缺少 IANA 时区数据时，按 UTC+8 计算。
        return datetime.utcnow() + timedelta(hours=8)


def read_progress():
    if not os.path.exists(progress_file):
        return {}

    try:
        with open(progress_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except Exception as e:
        print(f"读取断点文件失败，将从头开始: {e}")
    return {}


def write_progress(data):
    tmp_file = f"{progress_file}.tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp_file, progress_file)


def save_failed_progress(date_text, index, total, username, error):
    write_progress({
        "date": date_text,
        "next_index": index,
        "total": total,
        "completed": False,
        "last_failed_user": username,
        "last_error": str(error),
        "updated_at": now_str(),
    })


def save_running_progress(date_text, next_index, total):
    write_progress({
        "date": date_text,
        "next_index": next_index,
        "total": total,
        "completed": False,
        "updated_at": now_str(),
    })


def save_completed_progress(date_text, total):
    write_progress({
        "date": date_text,
        "next_index": 0,
        "total": total,
        "completed": True,
        "updated_at": now_str(),
    })


def get_start_index(total):
    date_text = today_str()
    progress = read_progress()

    if progress.get("date") != date_text:
        return 0, date_text

    if progress.get("completed") is True:
        print(f"{date_text} 今日账号已全部执行完成，本次跳过")
        return total, date_text

    start_index = progress.get("next_index", 0)
    if not isinstance(start_index, int):
        start_index = 0

    if start_index < 0:
        start_index = 0
    if start_index > total:
        start_index = total

    failed_user = progress.get("last_failed_user")
    if failed_user:
        print(f"检测到上次失败账号: {failed_user}，本次将从第 {start_index + 1} 个账号继续")

    return start_index, date_text


def main():
    accounts = load_accounts()
    total = len(accounts)

    start_index, date_text = get_start_index(total)
    if start_index >= total:
        return

    print(f"本次从第 {start_index + 1}/{total} 个账号开始执行")

    for index in range(start_index, total):
        username, password = accounts[index]
        try:
            print(f"\n[{index + 1}/{total}] 开始处理账号: {username}")
            data = login(username, password)
            check_in(**data)
            next_index = index + 1
            if next_index < total:
                save_running_progress(date_text, next_index, total)
            else:
                save_completed_progress(date_text, total)
                print(f"{date_text} 今日账号已全部执行完成")
        except Exception as e:
            save_failed_progress(date_text, index, total, username, e)
            print(f"{username}\t执行失败: {e}")
            print(traceback.format_exc())
            print(f"已记录断点，下次将从第 {index + 1}/{total} 个账号继续")
            raise

        if index + 1 < total:
            time.sleep(5)
            print("等待5秒后开始下一账号签到")


if __name__ == '__main__':
    main()
