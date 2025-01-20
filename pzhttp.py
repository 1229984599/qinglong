#!/usr/bin/python3
# -- coding: utf-8 --
# -------------------------------
# @Author : moxiaoying
# @Time : 2025/01/20 13:23
# -------------------------------
# cron "0 8 * * 1" script-path=pzhttp.py,tag=品赞http代理签到
# 支持多账户：pzhttp_cookie="手机号#密码@手机号#密码"
import os
import time
import httpx
import random
from loguru import logger


class Encoder:
    """
    字符串编码和混淆器类
    提供字符串的Base64编码和混淆功能
    """

    def __init__(self):
        """初始化Base64编码表"""
        self.table = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P",
                      "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "a", "b", "c", "d", "e", "f",
                      "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v",
                      "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "+", "/"]

        # 混淆用的固定字符串
        self.CONFUSION_STR = "QWERIPZAN1290QWER"

    def encode(self, text: str) -> str:
        """
        实现自定义的Base64编码
        
        Args:
            text: 需要编码的字符串
            
        Returns:
            编码后的字符串
        """
        if not text:
            return ""

        byte_array = text.encode('utf-8')
        result = []
        i = 0

        while i < len(byte_array):
            # 处理第一个字节
            b1 = byte_array[i]
            result.append(self.table[b1 >> 2])

            if i + 1 >= len(byte_array):
                # 只剩一个字节的情况
                result.append(self.table[(b1 & 0x03) << 4])
                result.append("==")
                break

            # 处理第二个字节
            b2 = byte_array[i + 1]
            if i + 2 >= len(byte_array):
                # 只剩两个字节的情况
                result.append(self.table[((b1 & 0x03) << 4) | ((b2 & 0xf0) >> 4)])
                result.append(self.table[(b2 & 0x0f) << 2])
                result.append("=")
                break

            # 处理第三个字节
            b3 = byte_array[i + 2]
            result.append(self.table[((b1 & 0x03) << 4) | ((b2 & 0xf0) >> 4)])
            result.append(self.table[((b2 & 0x0f) << 2) | ((b3 & 0xc0) >> 6)])
            result.append(self.table[b3 & 0x3f])

            i += 3

        return "".join(result)

    def _generate_random_str(self, length: int) -> str:
        """
        生成指定长度的随机十六进制字符串
        
        Args:
            length: 需要生成的字符串长度
            
        Returns:
            随机字符串
        """
        return ''.join(hex(random.randint(0, 15))[2:] for _ in range(length))

    def encode_credentials(self, phone: str, password: str) -> str:
        """
        对手机号和密码进行编码和混淆
        
        Args:
            phone: 手机号
            password: 密码
            
        Returns:
            混淆后的字符串
        """
        # 生成原始编码
        encoded = self.encode(f"{phone}{self.CONFUSION_STR}{password}")

        # 生成随机字符串
        random_str = self._generate_random_str(80) * 5

        # 按照特定规则拼接字符串
        result = (
                random_str[:100] +
                encoded[:8] +
                random_str[100:200] +
                encoded[8:20] +
                random_str[200:300] +
                encoded[20:] +
                random_str[300:400]
        )

        return result


class PzSignIn:
    def __init__(self, account: str):
        self.client = httpx.Client(base_url="https://service.ipzan.com", verify=False)
        self.get_token(account)

    def get_token(self, account):
        try:
            response = self.client.post(
                '/users-login',
                json={
                    "account": account,
                    "source": "ipzan-home-one"
                }
            )
            response_json = response.json()
            token = response_json["data"]['token']
            if token:
                logger.success("登录成功，开始执行签到")
                self.client.headers["Authorization"] = "Bearer " + token
            else:
                logger.error("登录失败:token为空")
                raise ValueError("登录失败")
        except Exception as e:
            logger.error(f"登录异常: {str(e)}")
            logger.error(f"响应内容: {response.text}")
            raise

    def get_balance(self):
        try:
            response = self.client.get("/home/userWallet-find").json()
            return str(response["data"]["balance"])
        except Exception as e:
            logger.error(f"获取余额失败: {str(e)}")
            return "获取失败"

    def sign_in(self):
        try:
            response = self.client.get("/home/userWallet-receive").json()
            balance = self.get_balance()

            if response["status"] == 200 and response['data'] == '领取成功':
                logger.success(f"签到成功，当前账户余额: {balance}")
            elif response["code"] == -1:
                logger.warning(f"{response['message']}，当前账户余额: {balance}")
            else:
                logger.error(f"签到失败！响应内容: {response}")
        except Exception as e:
            logger.error(f"签到异常: {str(e)}")


if __name__ == '__main__':
    try:
        # 检查环境变量
        user_cookie = os.getenv("pzhttp_cookie")
        if user_cookie is None:
            logger.error("请先设置环境变量 pzhttp_cookie")
            logger.info("配置格式: 手机号#密码 或 手机号#密码@手机号#密码")
            exit(1)

        if not user_cookie.strip():
            logger.error("环境变量 pzhttp_cookie 的值不能为空")
            logger.info("配置格式: 手机号#密码 或 手机号#密码@手机号#密码")
            exit(1)

        encoder = Encoder()
        accounts = user_cookie.split('@')

        if not accounts:
            logger.error("未检测到有效账号配置")
            logger.info("配置格式: 手机号#密码 或 手机号#密码@手机号#密码")
            exit(1)

        logger.info(f"共检测到 {len(accounts)} 个账号")

        for index, user in enumerate(accounts, 1):
            try:
                logger.info(f"开始处理第{index}个账号")
                credentials = user.split('#')
                if len(credentials) != 2:
                    logger.error(f"账号{index}格式错误，请使用 手机号#密码 的格式")
                    continue

                phone, password = credentials
                if not phone or not password:
                    logger.error(f"账号{index}的手机号或密码不能为空")
                    continue

                encoded = encoder.encode_credentials(phone, password)
                spider = PzSignIn(encoded)
                spider.sign_in()

                if index < len(accounts):
                    logger.info("等待1秒后处理下一账号")
                    time.sleep(1)
            except Exception as e:
                logger.error(f"账号{index}处理失败: {str(e)}")
                continue

    except Exception as e:
        logger.error(f"程序执行异常: {str(e)}")
