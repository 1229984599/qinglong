#!/usr/bin/python3
# -- coding: utf-8 --
# -------------------------------
# @Author : https://github.com/zhx47/anyrouter
# @Time : 2026/01/19 15:53
# -------------------------------
# cron "0 7 * * *" script-path=anyrouter.py,tag=AnyRouter签到 https://anyrouter.top
# 支持多账号：ANYROUTER_COOKIES 可用换行/逗号/JSON数组；也可提供 session=xxx 的完整 cookie

import json
import os
import re
import sys

import requests

DEFAULT_UPSTREAM = "https://anyrouter.top"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)

XOR_KEY = "3000176000856006061501533003690027800375"
UNSBOX_TABLE = [
    0xF,
    0x23,
    0x1D,
    0x18,
    0x21,
    0x10,
    0x1,
    0x26,
    0xA,
    0x9,
    0x13,
    0x1F,
    0x28,
    0x1B,
    0x16,
    0x17,
    0x19,
    0xD,
    0x6,
    0xB,
    0x27,
    0x12,
    0x14,
    0x8,
    0xE,
    0x15,
    0x20,
    0x1A,
    0x2,
    0x1E,
    0x7,
    0x4,
    0x11,
    0x5,
    0x3,
    0x1C,
    0x22,
    0x25,
    0xC,
    0x24,
]


def normalize_base_url(raw, fallback):
    base = (raw or fallback or "").strip()
    return base.rstrip("/")


def parse_cookie_list(raw):
    if not raw:
        return []
    trimmed = str(raw).strip()
    if not trimmed:
        return []

    if trimmed.startswith("["):
        try:
            arr = json.loads(trimmed)
            if isinstance(arr, list):
                return [str(item).strip() for item in arr if str(item).strip()]
        except Exception:
            pass

    parts = re.split(r"[\n,]+", trimmed)
    return [part.strip() for part in parts if part.strip()]


def extract_session_value(cookie_value):
    if not cookie_value:
        return ""
    match = re.search(r"(?:^|;)\s*session=([^;]+)", cookie_value)
    if match:
        return match.group(1).strip()
    return str(cookie_value).strip()


def compute_acw_cookie(arg1):
    if not arg1 or len(arg1) != 40:
        return None

    unsboxed = "".join(arg1[i - 1] for i in UNSBOX_TABLE)
    out = []
    for i in range(0, 40, 2):
        a = int(unsboxed[i : i + 2], 16)
        b = int(XOR_KEY[i : i + 2], 16)
        out.append(f"{a ^ b:02x}")
    return "acw_sc__v2=" + "".join(out)


def get_acw_cookie(target_url, http):
    try:
        resp = http.get(
            target_url,
            headers={"User-Agent": UA},
            allow_redirects=False,
            timeout=15,
        )
        html = resp.text or ""
        match = re.search(r"var\s+arg1\s*=\s*'([0-9a-fA-F]{40})'", html)
        if not match:
            return None
        return compute_acw_cookie(match.group(1))
    except Exception:
        return None


def sign_in_with_dynamic_cookie(upstream, session_value, http):
    sign_url = f"{upstream}/api/user/sign_in"
    candidates = [sign_url, f"{upstream}/api/user/self"]

    acw_cookie = None
    for url in candidates:
        acw_cookie = get_acw_cookie(url, http)
        if acw_cookie:
            break

    if not acw_cookie:
        return False, "获取动态Cookie失败: arg1 not found / request failed"

    headers = {
        "User-Agent": UA,
        "Cookie": f"{acw_cookie}; session={session_value}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "Origin": upstream,
        "Referer": f"{upstream}/",
    }

    try:
        resp = http.post(sign_url, headers=headers, data="", timeout=15)
    except Exception as exc:
        return False, f"请求异常: {exc}"

    if resp.status_code == 401:
        return False, "session 无效(401)"

    text = resp.text or ""
    if not resp.ok:
        return False, f"HTTP {resp.status_code}: {text}"

    try:
        data = resp.json()
    except Exception:
        return False, f"响应非JSON: {text}"

    success = data.get("success")
    message = str(data.get("message", "")).strip()

    if success is True:
        return True, message or "今日已签到"
    if success is False:
        return False, message or f"签到失败: {data}"

    return True, f"返回: {data}"


def main():
    upstream = normalize_base_url(os.getenv("UPSTREAM"), DEFAULT_UPSTREAM)

    raw_cookies = os.getenv("ANYROUTER_COOKIES") or os.getenv("anyrouter_cookies")

    sessions = [extract_session_value(item) for item in parse_cookie_list(raw_cookies)]
    sessions = [item for item in sessions if item]

    if not sessions:
        print("未配置 COOKIES/ANYROUTER_COOKIES（内容为 session 值）")
        return 1

    http = requests.Session()

    success_count = 0
    fail_count = 0

    print("AnyRouter 签到结果")
    for idx, session_value in enumerate(sessions, start=1):
        ok, msg = sign_in_with_dynamic_cookie(upstream, session_value, http)
        print(f"账号 #{idx}: {msg}")
        if ok:
            success_count += 1
        else:
            fail_count += 1

    print(f"汇总: 成功 {success_count} / 失败 {fail_count} / 总数 {len(sessions)}")
    return 0 if fail_count == 0 else 1


if __name__ == "__main__":
    main()
