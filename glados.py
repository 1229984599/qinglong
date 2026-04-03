#!/usr/bin/python3
# -- coding: utf-8 --
# -------------------------------
# @Author : moxiaoying
# @Time : 2026/04/03
# -------------------------------
# cron "0 9 * * *" script-path=glados.py,tag=GLaDOS自动签到
# GLADOS_COOKIE

from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path
from typing import Any, Callable
from urllib import error, request


CHECKIN_URL = "https://glados.one/api/user/checkin"
COOKIE_ENV = (os.getenv("GLADOS_COOKIE") or "").strip()
TOKEN = (os.getenv("GLADOS_TOKEN") or "glados.one").strip()
USER_AGENT = os.getenv("GLADOS_USER_AGENT") or (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36 Edg/146.0.0.0"
)


def load_notifier() -> Callable[[str, str], None]:
    candidates = [
        Path(__file__).resolve().parent / "notify.py",
        Path(__file__).resolve().parent.parent / "notify.py",
    ]

    for notify_path in candidates:
        if not notify_path.is_file():
            continue

        spec = importlib.util.spec_from_file_location("notify", notify_path)
        if spec is None or spec.loader is None:
            continue

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        send = getattr(module, "send", None)
        if callable(send):
            return send

    return lambda title, content: None


send_notify = load_notifier()


def split_cookies(raw_cookie: str) -> list[str]:
    return [item.strip() for item in raw_cookie.split("&") if item.strip()]


def request_json(cookie: str) -> dict[str, Any]:
    payload = json.dumps({"token": TOKEN or "glados.one"}).encode("utf-8")
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Content-Type": "application/json;charset=UTF-8",
        "Cookie": cookie,
        "Origin": "https://glados.one",
        "Referer": "https://glados.one/console/checkin",
        "User-Agent": USER_AGENT,
        "Content-Length": str(len(payload)),
    }
    req = request.Request(CHECKIN_URL, data=payload, headers=headers, method="POST")

    try:
        with request.urlopen(req, timeout=15) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            return {
                "status_code": resp.getcode(),
                "text": text,
                "data": try_parse_json(text),
            }
    except error.HTTPError as exc:
        text = exc.read().decode("utf-8", errors="replace")
        return {
            "status_code": exc.code,
            "text": text,
            "data": try_parse_json(text),
        }
    except error.URLError as exc:
        raise RuntimeError(f"Request failed: {exc.reason}") from exc


def try_parse_json(text: str) -> Any:
    try:
        return json.loads(text) if text else None
    except json.JSONDecodeError:
        return None


def extract_message(result: dict[str, Any]) -> str:
    data = result.get("data")
    if isinstance(data, dict):
        for key in ("message", "msg"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

    text = str(result.get("text") or "").strip()
    if text:
        return text

    return f"HTTP {result.get('status_code', 0)}"


def is_auth_failure(message: str) -> bool:
    return any(
        token in message.lower()
        for token in (
            "not login",
            "unauthorized",
            "forbidden",
            "invalid",
            "expired",
            "permission",
            "not found",
            "failed",
        )
    )


def is_already_checked_in(message: str) -> bool:
    return any(token in message.lower() for token in ("try tomorrow", "already", "tomorrow", "checked in"))


def build_summary(result: dict[str, Any], message: str) -> str:
    lines = [f"status: {result.get('status_code', 0)}", f"message: {message}"]
    data = result.get("data")
    interesting_keys = ("code", "leftDays", "balance", "day", "days", "email")

    if isinstance(data, dict):
        for key in interesting_keys:
            if key in data:
                lines.append(f"{key}: {json.dumps(data[key], ensure_ascii=False)}")
    elif result.get("text"):
        lines.append(f"body: {result['text']}")

    return "\n".join(lines)


def check_one(cookie: str, index: int) -> tuple[str, bool, bool]:
    result = request_json(cookie)
    message = extract_message(result)
    summary = build_summary(result, message)

    label = f"account {index}"
    account_summary = f"[{label}]\n{summary}"
    print(account_summary)

    failed = int(result.get("status_code", 0)) >= 400 or is_auth_failure(message)
    already = is_already_checked_in(message)
    return account_summary, failed, already


def main() -> int:
    cookies = split_cookies(COOKIE_ENV)
    if not cookies:
        raise RuntimeError(
            "Missing GLADOS_COOKIE. Set it in QingLong, for example: koa:sess=...; koa:sess.sig=..."
        )

    summaries: list[str] = []
    has_failure = False
    all_already = True

    for index, cookie in enumerate(cookies, start=1):
        summary, failed, already = check_one(cookie, index)
        summaries.append(summary)
        has_failure = has_failure or failed
        all_already = all_already and already

    notify_body = "\n\n".join(summaries)

    if has_failure:
        send_notify("GLaDOS Check-in Failed", notify_body)
        return 1

    if all_already:
        send_notify("GLaDOS Already Checked In", notify_body)
        return 0

    send_notify("GLaDOS Check-in Success", notify_body)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        summary = f"error: {exc}"
        print(summary, file=sys.stderr)
        send_notify("GLaDOS Check-in Failed", summary)
        raise SystemExit(1) from exc
