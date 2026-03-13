#!/usr/bin/env python3
# -- coding: utf-8 --
# -------------------------------
# @Author : Codex
# @Time : 2026/03/13
# -------------------------------
# cron "10 9 * * *" script-path=bltcy.py,tag=柏拉图AI登录签到https://api.bltcy.cn
# 环境变量 bltcy
# 支持多账号：username#password@username2#password2
import json
import os
import re
import sys
import time
import traceback
from dataclasses import dataclass
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

import requests


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROGRESS_FILE = os.path.join(BASE_DIR, "bltcy_progress.json")
BASE_URL = os.getenv("bltcy_base_url", "https://api.bltcy.cn").rstrip("/")
LOGIN_PATH = os.getenv("bltcy_login_path", "/api/user/login")
CHECKIN_PATH = os.getenv("bltcy_checkin_path", "/api/user/checkin")
OCR_URL = os.getenv("ocr_url","")
TURNSTILE = os.getenv("bltcy_turnstile", "")
ACCOUNT_DELAY_SECONDS = int(os.getenv("bltcy_account_delay_seconds", "5"))
RETRY_COUNT = int(os.getenv("bltcy_retry_count", "2"))
RETRY_DELAY_SECONDS = int(os.getenv("bltcy_retry_delay_seconds", "3"))
RATE_LIMIT_WAIT_SECONDS = int(os.getenv("bltcy_rate_limit_wait_seconds", "60"))
AGREEMENT = os.getenv("bltcy_agreement", "true").strip().lower() not in {"0", "false", "no"}
TIMEOUT = int(os.getenv("bltcy_timeout", "20"))
SUMMARY_FILE = os.getenv("bltcy_summary_file", "")


@dataclass
class CaptchaToken:
    captcha_id: str
    captcha_token: str


class RateLimitError(RuntimeError):
    def __init__(self, message: str, wait_seconds: int | None = None):
        super().__init__(message)
        self.wait_seconds = wait_seconds


def now_shanghai():
    try:
        return datetime.now(ZoneInfo("Asia/Shanghai"))
    except Exception:
        return datetime.now() + timedelta(hours=8)


def now_str() -> str:
    return now_shanghai().strftime("%Y-%m-%d %H:%M:%S")


def today_str() -> str:
    return now_shanghai().strftime("%Y-%m-%d")


def base64_to_bytes(base64_str: str) -> str:
    if "," in base64_str:
        return base64_str.split(",", 1)[1]
    return base64_str


def strip_wrapping_quotes(value: str) -> str:
    value = (value or "").strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1].strip()
    return value


def mask_value(value: str, keep: int = 6) -> str:
    value = str(value or "")
    if len(value) <= keep * 2:
        return value
    return f"{value[:keep]}...{value[-keep:]}"


def compact_tokens(tokens: dict) -> dict:
    return {key: mask_value(value) for key, value in (tokens or {}).items()}


def compact_cookies(cookies: dict) -> dict:
    return {key: mask_value(value) for key, value in (cookies or {}).items()}


def parse_accounts_from_json_data(data):
    if isinstance(data, dict):
        for key in ("accounts", "data", "items", "list"):
            if isinstance(data.get(key), list):
                data = data[key]
                break

    if not isinstance(data, list):
        return []

    accounts = []
    for item in data:
        if not isinstance(item, dict):
            continue
        username = item.get("username") or item.get("email") or item.get("account")
        password = item.get("password")
        if username is None or password is None:
            continue
        username = str(username).strip()
        password = str(password).strip()
        if username and password:
            accounts.append((username, password))
    return accounts


def parse_accounts_from_legacy(raw_value: str):
    raw_value = strip_wrapping_quotes(raw_value)
    if raw_value.count("#") > 1 and "@" in raw_value and not re.search(r"\s", raw_value):
        items = [item for item in raw_value.split("@") if item]
    else:
        items = raw_value.split()

    accounts = []
    for item in items:
        if "#" not in item:
            continue
        username, password = item.split("#", 1)
        username = username.strip()
        password = password.strip()
        if username and password:
            accounts.append((username, password))
    return accounts


def parse_accounts_from_env(raw_value: str):
    value = (raw_value or "").strip()
    if not value:
        return []

    candidates = []

    def add_candidate(candidate: str):
        candidate = (candidate or "").strip()
        if candidate and candidate not in candidates:
            candidates.append(candidate)

    add_candidate(value)
    add_candidate(strip_wrapping_quotes(value))
    for candidate in list(candidates):
        if "\\n" in candidate:
            add_candidate(candidate.replace("\\n", "\n"))

    for candidate in candidates:
        if candidate[:1] not in "[{":
            continue
        try:
            accounts = parse_accounts_from_json_data(json.loads(candidate))
            if accounts:
                print(f"使用环境变量 bltcy(JSON格式) 账号，共 {len(accounts)} 个")
                return accounts
        except Exception:
            pass

    accounts = parse_accounts_from_legacy(value)
    if accounts:
        print(f"使用环境变量 bltcy(旧格式) 账号，共 {len(accounts)} 个")
    return accounts


def load_accounts():
    env_value = (
        os.getenv("bltcy")
        or os.getenv("BLTCY")
        or os.getenv("bltcy_accounts")
        or os.getenv("BLTCY_ACCOUNTS")
        or ""
    ).strip()
    if not env_value:
        raise ValueError("环境变量 bltcy 未设置")

    accounts = parse_accounts_from_env(env_value)
    if not accounts:
        raise ValueError("环境变量 bltcy 中未解析到可用账号")
    return accounts


def read_progress():
    if not os.path.exists(PROGRESS_FILE):
        return {}
    try:
        with open(PROGRESS_FILE, "r", encoding="utf-8") as file:
            data = json.load(file)
        if isinstance(data, dict):
            return data
    except Exception as exc:
        print(f"读取进度文件失败，将从头开始: {exc}")
    return {}


def write_progress(data):
    tmp_file = f"{PROGRESS_FILE}.tmp"
    with open(tmp_file, "w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=2)
    os.replace(tmp_file, PROGRESS_FILE)


def get_completed_accounts(date_text: str):
    progress = read_progress()
    if progress.get("date") != date_text:
        return set()
    return set(progress.get("completed_accounts", []))


def build_account_detail(username: str, status: str, attempt: int | None = None, error: str | None = None, result: dict | None = None):
    detail = {
        "username": username,
        "status": status,
        "attempt": attempt,
        "updated_at": now_str(),
    }
    if error is not None:
        detail["error"] = error
    if result is not None:
        detail["already_checked_in"] = bool(result.get("checkin_payload", {}).get("already_checked_in"))
        detail["tokens"] = compact_tokens(result.get("tokens", {}))
        detail["cookies"] = compact_cookies(result.get("cookies", {}))
        detail["login_message"] = str(result.get("login_payload", {}).get("message") or "")
        detail["checkin_message"] = str(result.get("checkin_payload", {}).get("message") or "")
    return detail


def build_success_record(result: dict) -> dict:
    return {
        "username": result["username"],
        "attempt": result["attempt"],
        "already_checked_in": bool(result["checkin_payload"].get("already_checked_in")),
        "tokens": compact_tokens(result.get("tokens", {})),
        "cookies": compact_cookies(result.get("cookies", {})),
        "checkin_message": str(result.get("checkin_payload", {}).get("message") or ""),
    }


def save_progress(date_text: str, completed_accounts, all_done: bool, summary: dict, last_failed_account: str | None = None, last_error: str | None = None):
    write_progress(
        {
            "date": date_text,
            "completed_accounts": sorted(completed_accounts),
            "all_done": all_done,
            "last_failed_account": last_failed_account,
            "last_error": last_error,
            "updated_at": now_str(),
            "summary": summary,
        }
    )


def write_summary_file(summary: dict):
    if not SUMMARY_FILE:
        return
    with open(SUMMARY_FILE, "w", encoding="utf-8") as file:
        json.dump(summary, file, ensure_ascii=False, indent=2)


def extract_tokens(data: dict) -> dict:
    if not isinstance(data, dict):
        return {}

    tokens = {}
    for key in (
        "token",
        "access_token",
        "refresh_token",
        "session",
        "session_token",
        "jwt",
        "authorization",
        "api_key",
    ):
        value = data.get(key)
        if value:
            tokens[key] = value

    nested = data.get("user")
    if isinstance(nested, dict):
        for key in ("token", "access_token", "refresh_token"):
            value = nested.get(key)
            if value and key not in tokens:
                tokens[key] = value
    return tokens


def extract_wait_seconds(message: str, fallback: int = RATE_LIMIT_WAIT_SECONDS) -> int:
    match = re.search(r"(\d+)\s*(秒|s|sec)", str(message), re.I)
    if match:
        return max(1, int(match.group(1)))
    return max(1, fallback)


def raise_for_rate_limit(response: requests.Response):
    if response.status_code != 429:
        return
    message = "rate limited"
    try:
        payload = response.json()
        message = payload.get("message") or payload.get("error", {}).get("message") or response.text
    except Exception:
        message = response.text or message
    raise RateLimitError(str(message), extract_wait_seconds(message))


class BltcyClient:
    def __init__(self, base_url: str = BASE_URL, timeout: int = TIMEOUT, ocr_url: str = OCR_URL):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.ocr_url = ocr_url
        self.session = requests.Session()
        self.session.headers.update(
            {
                "accept": "application/json, text/plain, */*",
                "accept-language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
                "content-type": "application/json",
                "new-api-user": "-1",
                "origin": self.base_url,
                "priority": "u=1, i",
                "referer": f"{self.base_url}/login",
                "sec-ch-ua": '"Not:A-Brand";v="99", "Microsoft Edge";v="145", "Chromium";v="145"',
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
                "sec-fetch-dest": "empty",
                "sec-fetch-mode": "cors",
                "sec-fetch-site": "same-origin",
                "user-agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/145.0.0.0 Safari/537.36 Edg/145.0.0.0"
                ),
            }
        )

    def generate_captcha(self) -> dict:
        response = self.session.get(f"{self.base_url}/api/captcha/generate", timeout=self.timeout)
        raise_for_rate_limit(response)
        response.raise_for_status()
        payload = response.json()
        if not payload.get("data"):
            raise RuntimeError(f"captcha generate failed: {payload}")
        return payload["data"]

    def solve_x_with_ocr(self, master_image: str, tile_image: str) -> int:
        response = requests.post(
            self.ocr_url,
            json={
                "backImage": base64_to_bytes(master_image),
                "slidingImage": base64_to_bytes(tile_image),
            },
            timeout=self.timeout,
        )
        response.raise_for_status()
        payload = response.json()
        result = payload.get("result")
        if result is None:
            raise RuntimeError(f"ocr failed: {payload}")
        return int(result)

    def solve_captcha(self) -> CaptchaToken:
        captcha = self.generate_captcha()
        x = self.solve_x_with_ocr(captcha["masterImage"], captcha["tileImage"])
        response = self.session.post(
            f"{self.base_url}/api/captcha/verify",
            json={"captchaId": captcha["captchaId"], "dots": {"x": int(x), "y": int(captcha["thumbY"])}},
            timeout=self.timeout,
        )
        raise_for_rate_limit(response)
        response.raise_for_status()
        payload = response.json()
        if not payload.get("success"):
            raise RuntimeError(f"captcha verify failed: {payload}")
        data = payload["data"]
        return CaptchaToken(captcha_id=data["captcha_id"], captcha_token=data["captcha_token"])

    def login(self, username: str, password: str) -> dict:
        token = self.solve_captcha()
        body = {
            "username": username,
            "password": password,
            "agreement": AGREEMENT,
            "captcha_id": token.captcha_id,
            "captcha_token": token.captcha_token,
        }
        response = self.session.post(
            f"{self.base_url}{LOGIN_PATH}",
            params={
                "turnstile": TURNSTILE,
                "captcha_id": token.captcha_id,
                "captcha_token": token.captcha_token,
            },
            json=body,
            timeout=self.timeout,
        )
        raise_for_rate_limit(response)
        response.raise_for_status()
        payload = response.json()
        if not payload.get("success"):
            raise RuntimeError(payload.get("message") or str(payload))
        return payload

    def checkin(self, login_payload: dict) -> dict:
        data = login_payload.get("data") or {}
        token = self.solve_captcha()

        new_api_user = data.get("id")
        if new_api_user is None and isinstance(data.get("user"), dict):
            new_api_user = data["user"].get("id")
        if new_api_user is None:
            new_api_user = self.session.headers.get("new-api-user", "-1")

        headers = self.session.headers.copy()
        headers.update(
            {
                "content-type": "application/json",
                "new-api-user": str(new_api_user),
                "referer": f"{self.base_url}/dashboard",
            }
        )

        response = self.session.get(
            f"{self.base_url}{CHECKIN_PATH}",
            params={
                "captcha_id": token.captcha_id,
                "captcha_token": token.captcha_token,
            },
            headers=headers,
            timeout=self.timeout,
        )
        raise_for_rate_limit(response)
        response.raise_for_status()
        payload = response.json()
        message = str(payload.get("message") or "")
        if not payload.get("success"):
            if "今日已签到" in message:
                return {
                    "success": True,
                    "already_checked_in": True,
                    "message": message,
                    "data": payload.get("data"),
                }
            raise RuntimeError(message or str(payload))
        return payload

    def login_and_checkin(self, username: str, password: str) -> dict:
        login_payload = self.login(username, password)
        checkin_payload = self.checkin(login_payload)
        data = login_payload.get("data") or {}
        return {
            "username": data.get("username") or username,
            "tokens": extract_tokens(data),
            "cookies": self.session.cookies.get_dict(),
            "login_payload": login_payload,
            "checkin_payload": checkin_payload,
        }


def login_checkin_with_retries(username: str, password: str) -> dict:
    last_error = None
    total_attempts = max(1, RETRY_COUNT + 1)

    for attempt in range(1, total_attempts + 1):
        client = BltcyClient()
        try:
            result = client.login_and_checkin(username, password)
            result["attempt"] = attempt
            return result
        except RateLimitError as exc:
            last_error = exc
            wait_seconds = exc.wait_seconds or RATE_LIMIT_WAIT_SECONDS
            print(f"{username}\tattempt {attempt}/{total_attempts} rate limited: {exc}")
            if attempt < total_attempts:
                print(f"等待 {wait_seconds} 秒后重试...")
                time.sleep(wait_seconds)
        except Exception as exc:
            last_error = exc
            print(f"{username}\tattempt {attempt}/{total_attempts} failed: {exc}")
            print(traceback.format_exc())
            if attempt < total_attempts:
                time.sleep(RETRY_DELAY_SECONDS)

    raise RuntimeError(str(last_error) if last_error else "unknown login/checkin error")


def main() -> int:
    accounts = load_accounts()
    total = len(accounts)
    date_text = today_str()
    progress = read_progress()
    completed = get_completed_accounts(date_text)
    pending = [(username, password) for username, password in accounts if username not in completed]

    summary = progress.get("summary", {"success": [], "failed": [], "account_details": {}}) if completed else {"success": [], "failed": [], "account_details": {}}
    success_records = summary.get("success", [])
    account_details = summary.get("account_details", {})

    if not pending:
        print(f"{date_text} 所有 {total} 个账号今日已完成，无需重复执行")
        final_summary = {"success": success_records, "failed": [], "account_details": account_details}
        write_summary_file(final_summary)
        return 0

    if completed:
        print(f"今日已完成 {len(completed)}/{total} 个账号，剩余 {len(pending)} 个待执行")
    else:
        print(f"今日共 {total} 个账号待执行")

    for index, (username, password) in enumerate(pending, start=1):
        try:
            print(f"\n[{len(completed) + 1}/{total}] 开始处理账号: {username}")
            result = login_checkin_with_retries(username, password)
            already_checked_in = bool(result["checkin_payload"].get("already_checked_in"))
            status_text = "今日已签到" if already_checked_in else "签到成功"
            print(f"{result['username']}\t{status_text} (attempt {result['attempt']})")
            if result["tokens"]:
                print(f"tokens: {json.dumps(compact_tokens(result['tokens']), ensure_ascii=False)}")
            if result["cookies"]:
                print(f"cookies: {json.dumps(compact_cookies(result['cookies']), ensure_ascii=False)}")

            record = build_success_record(result)
            success_records.append(record)
            account_details[username] = build_account_detail(username, "success", result["attempt"], result=result)

            completed.add(username)
            all_done = len(completed) >= total
            current_summary = {"success": success_records, "failed": [], "account_details": account_details}
            save_progress(date_text, completed, all_done=all_done, summary=current_summary)
            write_summary_file(current_summary)

            if all_done:
                print(f"{date_text} 今日账号已全部执行完成")
        except Exception as exc:
            account_details[username] = build_account_detail(username, "failed", error=str(exc))
            failed_summary = {"success": success_records, "failed": [{"username": username, "error": str(exc)}], "account_details": account_details}
            save_progress(date_text, completed, all_done=False, summary=failed_summary, last_failed_account=username, last_error=str(exc))
            write_summary_file(failed_summary)
            print(f"{username}\t执行失败: {exc}")
            print(traceback.format_exc())
            print(f"已记录断点，下次将跳过已完成的 {len(completed)} 个账号继续")
            raise

        if index < len(pending):
            time.sleep(ACCOUNT_DELAY_SECONDS)
            print(f"等待 {ACCOUNT_DELAY_SECONDS} 秒后开始下一个账号")

    final_summary = {"success": success_records, "failed": [], "account_details": account_details}
    print("\nsummary:")
    print(json.dumps(final_summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())