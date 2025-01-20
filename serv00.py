#!/usr/bin/python3
# -- coding: utf-8 --
# -------------------------------
# @Author : moxiaoying
# @Time : 2025/01/17 13:23
# -------------------------------
# cron "1 * * * *" script-path=serv00.py,tag=serv00注册
# 账户配置格式：serv00_cookie="ocr_url=验证码识别接口地址;first_name=名字;last_name=姓氏;username=用户名;email=邮箱地址;proxy_secret=代理API密钥;proxy_no=代理API编号;"
# 必填项：ocr_url, first_name, last_name, username, email
# 可选项：proxy_secret和proxy_no (需同时配置才能启用代理)，对应套餐管理的提取密钥和套餐编号
# 代理API购买地址：https://www.ipzan.com?pid=e5lllafig

import requests
import json
import re
import urllib3
from typing import Tuple, Optional, Dict, Any
import os
from loguru import logger
import time

# 全局禁用 InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ProxyManager:
    def __init__(self, secret: str, no: str):
        """
        代理IP管理器初始化
        
        Args:
            secret: API密钥
            no: API编号
        """
        self.api_url = "https://service.ipzan.com/core-extract"
        self.secret = secret
        self.no = no
        self.current_proxy: Optional[Dict[str, Any]] = None
        self.last_fetch_time = 0
        self.fetch_interval = 50  # 设置50秒的最小获取间隔

    def _build_api_url(self) -> str:
        """构建完整的API URL"""
        params = {
            'num': 1,
            'minute': 1,
            'format': 'json',
            'protocol': 1,
            'pool': 'quality',
            'mode': 'whitelist',
            'secret': self.secret,
            'no': self.no
        }
        query_string = '&'.join(f'{k}={v}' for k, v in params.items())
        return f"{self.api_url}?{query_string}"

    def _fetch_new_proxy(self) -> Dict[str, Any]:
        """从API获取新的代理IP"""
        try:
            response = requests.get(self._build_api_url(), timeout=10)
            response.raise_for_status()
            result = response.json()
            
            if result['code'] != 0:
                raise ValueError(f"获取代理失败: {result['message']}")
            
            if not result.get('data') or not result['data'].get('list'):
                raise ValueError("代理数据为空")
            
            proxy_info = result['data']['list'][0]
            logger.debug(f"获取到的代理信息: {json.dumps(proxy_info, ensure_ascii=False)}")
            return proxy_info
            
        except Exception as e:
            logger.error(f"获取代理IP失败: {str(e)}")
            raise

    def get_proxy(self, force_new: bool = False) -> Dict[str, str]:
        """
        获取代理配置
        
        Args:
            force_new: 是否强制获取新代理
            
        Returns:
            代理配置字典
        """
        current_time = time.time()
        
        # 检查是否需要更新代理
        if (force_new or 
            not self.current_proxy or 
            current_time - self.last_fetch_time >= self.fetch_interval):
            
            logger.info("正在获取新的代理IP...")
            proxy_info = self._fetch_new_proxy()
            self.current_proxy = proxy_info
            self.last_fetch_time = current_time
            
            logger.info(f"成功获取新代理: {proxy_info['ip']}:{proxy_info['port']}")
        
        # 构建代理URL
        proxy_url = f"http://{self.current_proxy['ip']}:{self.current_proxy['port']}"
        
        # 如果有账号密码，则添加到URL中
        if self.current_proxy.get('account') and self.current_proxy.get('password'):
            proxy_url = f"http://{self.current_proxy['account']}:{self.current_proxy['password']}@{self.current_proxy['ip']}:{self.current_proxy['port']}"
        
        return {
            "http": proxy_url,
            "https": proxy_url
        }

    def is_proxy_valid(self) -> bool:
        """检查当前代理是否有效"""
        if not self.current_proxy:
            return False
            
        # 检查代理是否过期
        expired_time = self.current_proxy.get('expired', 0) / 1000  # 转换为秒
        return time.time() < expired_time


class Serv00Register:
    def __init__(self,
                 ocr_url: str = "",
                 proxies: Optional[Dict[str, str]] = None,
                 timeout: int = 20):
        """
        初始化注册类
        
        Args:
            base_url: Serv00网站基础URL
            ocr_url: OCR服务URL
            proxies: 代理设置
            timeout: 请求超时时间
        """
        self.base_url = "https://www.serv00.com"
        self.home_url = f"{self.base_url}/offer/create_new_account"
        self.register_url = f"{self.base_url}/offer/create_new_account.json"
        self.ocr_url = ocr_url
        self.proxies = proxies or {"http": None, "https": None}
        self.timeout = timeout

        self.session = self._init_session()

    def _init_session(self) -> requests.Session:
        """初始化会话并设置请求头"""
        session = requests.Session()
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": self.home_url
        })
        return session

    def _get_initial_tokens(self) -> Tuple[str, str]:
        """获取csrf_token和captcha_key"""
        response = self.session.get(
            self.home_url,
            proxies=self.proxies,
            timeout=self.timeout,
            verify=False
        )
        response.raise_for_status()
        html_content = response.text

        csrf_token = re.search(r"name='csrfmiddlewaretoken' value='(.*?)'", html_content)
        captcha_key = re.search(r"/captcha/image/(.*?)/", html_content)

        if not csrf_token or not captcha_key:
            raise ValueError("无法获取csrf_token或captcha_key")

        return csrf_token.group(1), captcha_key.group(1)

    def _get_captcha_image(self, captcha_key: str) -> bytes:
        """获取验证码图片"""
        captcha_url = f"{self.base_url}/captcha/image/{captcha_key}/"
        response = self.session.get(
            captcha_url,
            proxies=self.proxies,
            timeout=self.timeout,
            verify=False
        )
        response.raise_for_status()
        return response.content

    def _recognize_captcha(self, image_data: bytes) -> str:
        """识别验证码"""
        response = requests.post(
            self.ocr_url,
            files={"file": image_data},
            timeout=self.timeout
        )
        response.raise_for_status()
        return response.json().get("data", "")

    def _register_account(self, register_data: Dict[str, str]) -> Dict[str, Any]:
        """提交注册请求"""
        response = self.session.post(
            self.register_url,
            data=register_data,
            proxies=self.proxies,
            timeout=self.timeout,
            verify=False
        )

        if response.status_code == 500:
            try:
                return response.json()
            except ValueError:
                raise RuntimeError("500错误返回非JSON数据")
        elif response.status_code >= 400:
            raise RuntimeError(f"HTTP错误: {response.status_code}")

        return response.json()

    def register(self, first_name: str, last_name: str,
                 username: str, email: str, max_retries: int = 3) -> Dict[str, Any]:
        """
        执行注册流程
        
        Args:
            first_name: 名
            last_name: 姓
            username: 用户名
            email: 邮箱
            max_retries: 验证码重试最大次数
            
        Returns:
            注册响应结果
        """
        try:
            logger.info(f"开始注册流程 - 用户名: {username}, 邮箱: {email}")

            for attempt in range(max_retries):
                try:
                    # 获取token和验证码key
                    logger.info("正在获取初始化令牌...")
                    csrf_token, captcha_key = self._get_initial_tokens()
                    logger.info(f"成功获取令牌 - captcha_key: {captcha_key}")

                    # 获取并识别验证码
                    logger.info("正在获取验证码图片...")
                    image_data = self._get_captcha_image(captcha_key)
                    logger.info("正在识别验证码...")
                    captcha_result = self._recognize_captcha(image_data)
                    logger.info(f"验证码识别结果: {captcha_result}")

                    # 构建注册数据
                    register_data = {
                        "csrfmiddlewaretoken": csrf_token,
                        "first_name": first_name,
                        "last_name": last_name,
                        "username": username,
                        "email": email,
                        "captcha_0": captcha_key,
                        "captcha_1": captcha_result,
                        "question": "0",
                        "tos": "on",
                    }

                    # 提交注册
                    logger.info("正在提交注册请求...")
                    response = self._register_account(register_data)

                    # 如果验证码无效，则重试
                    if "captcha" in response and "Invalid CAPTCHA" in response["captcha"]:
                        if attempt < max_retries - 1:  # 还有重试机会
                            logger.warning(f"验证码无效，正在进行第 {attempt + 2} 次尝试...")
                            # 使用响应中的新验证码key
                            captcha_key = response["__captcha_key"]
                            continue
                        else:
                            logger.error("验证码重试次数已达上限")

                    self._handle_response(response)
                    return response

                except Exception as e:
                    if attempt < max_retries - 1:
                        logger.warning(f"第 {attempt + 1} 次尝试失败: {str(e)}, 正在重试...")
                        continue
                    raise

        except Exception as e:
            logger.error(f"注册过程出错: {str(e)}")
            raise

    def _handle_response(self, response: Dict[str, Any]) -> None:
        """处理注册响应"""
        if "username" in response:
            if "Maintenance time" in response["username"]:
                logger.warning("注册失败: 系统维护中，请稍后重试")
            elif "account limit" in response["username"]:
                logger.warning("注册失败: 服务器账户数量已达上限，请稍后重试")
            else:
                logger.success("注册成功！")
        elif "captcha" in response and "Invalid CAPTCHA" in response["captcha"]:
            logger.warning("验证码无效")
            logger.debug(f"新的验证码key: {response['__captcha_key']}")
            logger.debug(f"新的验证码图片: {self.base_url}{response['__captcha_image_src']}")
        else:
            logger.warning("收到未知响应")
        logger.debug(f"完整响应: {json.dumps(response, indent=4, ensure_ascii=False)}")


def main():
    """主函数示例"""
    logger.info("============= 开始执行 Serv00 注册任务 =============")

    try:
        # 从环境变量获取隐私信息
        env_str = os.getenv('serv00_cookie', '')
        if not env_str:
            logger.error("环境变量 serv00_cookie 未设置")
            raise ValueError(
                "请设置 serv00_cookie 环境变量，格式为: first_name=xxx;last_name=xxx;username=xxx;email=xxx;ocr_url=xxx;proxy_secret=xxx;proxy_no=xxx;")

        # 解析环境变量字符串
        logger.info("正在解析环境变量...")
        info_dict = {}
        for item in env_str.split(';'):
            if '=' in item:
                key, value = item.strip().split('=', 1)
                info_dict[key] = value

        # 验证必要的字段
        required_fields = ['first_name', 'last_name', 'username', 'email', 'ocr_url']
        missing_fields = [field for field in required_fields if field not in info_dict]
        if missing_fields:
            logger.error(f"环境变量配置不完整，缺少字段: {missing_fields}")
            raise ValueError(f"环境变量缺少必要字段: {', '.join(missing_fields)}")

        # 根据是否同时配置proxy_secret和proxy_no决定是否使用代理
        proxies = None
        if 'proxy_secret' in info_dict and 'proxy_no' in info_dict:
            logger.info("检测到完整的代理配置，正在初始化代理...")
            proxy_manager = ProxyManager(
                secret=info_dict['proxy_secret'],
                no=info_dict['proxy_no']
            )
            proxies = proxy_manager.get_proxy()
            logger.info(f"代理配置: {proxies}")
        else:
            if 'proxy_secret' in info_dict or 'proxy_no' in info_dict:
                logger.warning("代理配置不完整，需要同时设置proxy_secret和proxy_no才能使用代理")
            logger.info("将使用直接连接")

        logger.info("初始化注册客户端...")
        register_client = Serv00Register(
            ocr_url=info_dict['ocr_url'],
            proxies=proxies
        )

        logger.info("开始执行注册流程...")
        register_client.register(
            first_name=info_dict['first_name'],
            last_name=info_dict['last_name'],
            username=info_dict['username'],
            email=info_dict['email']
        )

    except Exception as e:
        logger.error(f"注册失败: {e}")
        raise
    finally:
        logger.info("============= 注册任务执行完成 =============")


if __name__ == "__main__":
    main()
