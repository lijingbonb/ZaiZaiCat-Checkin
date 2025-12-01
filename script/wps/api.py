#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WPS API模块

提供WPS签到相关的API接口和加密功能
"""

import base64
import time
import random
import string
import requests
import json
import logging
from typing import Dict, Optional
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad

logger = logging.getLogger(__name__)


class WPSEncryption:
    """WPS加密工具类"""

    @staticmethod
    def generate_aes_key(length: int = 32) -> str:
        """
        生成AES密钥: 随机字符 + 时间戳

        Args:
            length (int): 密钥长度，默认32位

        Returns:
            str: 生成的AES密钥
        """
        chars = string.ascii_lowercase + string.digits
        random_part = ''.join(random.choice(chars) for _ in range(length - 10))
        timestamp_part = str(int(time.time()))
        return random_part + timestamp_part

    @staticmethod
    def aes_encrypt(plain_text: str, aes_key: str) -> str:
        """
        AES-CBC加密

        Args:
            plain_text (str): 明文文本
            aes_key (str): AES密钥

        Returns:
            str: Base64编码的加密结果
        """
        # 将密钥转为bytes并零填充到32字节
        key_bytes = aes_key.encode('utf-8')
        key_padded = key_bytes + b'\x00' * (32 - len(key_bytes))

        # 使用前16位作为IV
        iv = aes_key[:16].encode('utf-8')

        # 创建AES加密器 (CBC模式)
        cipher = AES.new(key_padded, AES.MODE_CBC, iv)

        # PKCS7填充
        plain_bytes = plain_text.encode('utf-8')
        padded_data = pad(plain_bytes, AES.block_size)

        # 加密并返回Base64
        encrypted = cipher.encrypt(padded_data)
        return base64.b64encode(encrypted).decode('utf-8')

    @staticmethod
    def rsa_encrypt(plain_text: str, public_key_pem: str) -> str:
        """
        RSA加密

        Args:
            plain_text (str): 明文文本
            public_key_pem (str): PEM格式的RSA公钥

        Returns:
            str: Base64编码的加密结果
        """
        public_key = RSA.import_key(public_key_pem)
        cipher = PKCS1_v1_5.new(public_key)
        encrypted = cipher.encrypt(plain_text.encode('utf-8'))
        return base64.b64encode(encrypted).decode('utf-8')


class WPSAPI:
    """WPS API类"""

    def __init__(self, cookies: str, user_agent: Optional[str] = None):
        """
        初始化API类

        Args:
            cookies (str): Cookie字符串
            user_agent (Optional[str]): 用户代理字符串，可选
        """
        self.cookies = self._parse_cookies(cookies)
        self.user_agent = user_agent or (
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
            'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36'
        )
        self.base_headers = {
            'User-Agent': self.user_agent,
            'Accept': 'application/json, text/plain, */*',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Content-Type': 'application/json',
            'pragma': 'no-cache',
            'cache-control': 'no-cache',
            'sec-ch-ua-platform': '"macOS"',
            'sec-ch-ua': '"Chromium";v="142", "Brave";v="142", "Not_A Brand";v="99"',
            'sec-ch-ua-mobile': '?0',
            'sec-gpc': '1',
            'accept-language': 'zh-CN,zh;q=0.9',
            'origin': 'https://personal-act.wps.cn',
            'sec-fetch-site': 'same-site',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            'referer': 'https://personal-act.wps.cn/',
            'priority': 'u=1, i'
        }
        self.encrypt_key_url = 'https://personal-bus.wps.cn/sign_in/v1/encrypt/key'
        self.sign_in_url = 'https://personal-bus.wps.cn/sign_in/v1/sign_in'
        self.encryption = WPSEncryption()

    @staticmethod
    def _parse_cookies(cookie_str: str) -> Dict[str, str]:
        """
        解析Cookie字符串为字典

        Args:
            cookie_str (str): Cookie字符串

        Returns:
            Dict[str, str]: Cookie字典
        """
        cookies = {}
        for item in cookie_str.split('; '):
            if '=' in item:
                key, value = item.split('=', 1)
                cookies[key] = value
        return cookies


    def get_encrypt_key(self) -> Dict:
        """
        获取RSA加密公钥

        Returns:
            Dict: 包含公钥信息的字典
                {
                    'success': bool,  # 是否成功
                    'public_key': str,  # 成功时的公钥(Base64编码)
                    'error': str      # 失败时的错误信息
                }
        """
        logger.info("正在获取RSA加密公钥...")

        try:
            response = requests.get(
                self.encrypt_key_url,
                headers=self.base_headers,
                cookies=self.cookies,
                timeout=30
            )
            response.raise_for_status()

            result = response.json()

            if result.get('result') == 'ok' and 'data' in result:
                public_key_base64 = result['data']
                logger.info("✅ 成功获取RSA加密公钥")
                return {
                    'success': True,
                    'public_key': public_key_base64
                }
            else:
                error_msg = result.get('msg', '未知错误')
                logger.error(f"❌ 获取公钥失败: {error_msg}")
                return {
                    'success': False,
                    'error': error_msg
                }

        except requests.exceptions.RequestException as e:
            error_msg = f"网络请求失败: {str(e)}"
            logger.error(f"❌ {error_msg}")
            return {
                'success': False,
                'error': error_msg
            }
        except Exception as e:
            error_msg = f"未知错误: {str(e)}"
            logger.error(f"❌ {error_msg}")
            return {
                'success': False,
                'error': error_msg
            }

    def generate_crypto_data(self, public_key_base64: str, user_id: int, platform: int = 64) -> Dict:
        """
        生成加密数据和token

        Args:
            public_key_base64 (str): Base64编码的RSA公钥
            user_id (int): 用户ID（必需）
            platform (int): 平台标识，默认64

        Returns:
            Dict: 包含加密数据的字典
                {
                    'extra': str,      # AES加密的数据
                    'token': str,      # RSA加密的AES密钥
                    'aesKey': str      # AES密钥（用于调试）
                }
        """

        # 解码公钥
        public_key_pem = base64.b64decode(public_key_base64).decode('utf-8')

        # 生成AES密钥
        aes_key = self.encryption.generate_aes_key(32)

        # 准备明文数据
        plain_data = json.dumps({
            "user_id": user_id,
            "platform": platform
        }, separators=(',', ':'))

        # AES加密数据 (这是extra)
        encrypt_data = self.encryption.aes_encrypt(plain_data, aes_key)

        # RSA加密AES密钥 (这是请求头中的token)
        token = self.encryption.rsa_encrypt(aes_key, public_key_pem)

        logger.debug(f"User ID: {user_id}")
        logger.debug(f"Plain Data: {plain_data}")
        logger.debug(f"AES Key: {aes_key}")
        logger.debug(f"Extra: {encrypt_data}")
        logger.debug(f"Token (请求头): {token}")

        return {
            "extra": encrypt_data,
            "token": token,
            "aesKey": aes_key
        }

    def sign_in(self, user_id: int) -> Dict:
        """
        执行签到

        Args:
            user_id (int): 用户ID（必需）

        Returns:
            Dict: 签到结果
                {
                    'success': bool,  # 是否成功
                    'data': dict,     # 成功时的签到信息
                    'error': str      # 失败时的错误信息
                }
        """
        logger.info("开始签到...")

        try:
            # 1. 获取RSA公钥
            key_result = self.get_encrypt_key()
            if not key_result['success']:
                return {
                    'success': False,
                    'error': f"获取公钥失败: {key_result['error']}"
                }

            public_key_base64 = key_result['public_key']

            # 2. 生成加密数据和token
            crypto_result = self.generate_crypto_data(public_key_base64, user_id)

            # 3. 构造请求头 (使用生成的token)
            headers = self.base_headers.copy()
            headers['token'] = crypto_result['token']

            # 4. 构造请求数据
            data = {
                "encrypt": True,
                "extra": crypto_result['extra'],
                "pay_origin": "pc_ucs_rwzx_sign"
            }

            logger.debug(f"请求URL: {self.sign_in_url}")
            logger.debug(f"请求头Token: {crypto_result['token'][:50]}...")
            logger.debug(f"请求数据: {json.dumps(data, indent=2)}")

            # 5. 发送请求
            response = requests.post(
                self.sign_in_url,
                headers=headers,
                cookies=self.cookies,
                json=data,
                timeout=30
            )

            logger.debug(f"响应状态码: {response.status_code}")
            logger.debug(f"响应内容: {response.text}")

            # 6. 解析响应
            if response.status_code == 200:
                resp_data = response.json()
                if resp_data.get('result') == 'ok':
                    logger.info("✅ 签到成功!")
                    return {
                        'success': True,
                        'data': resp_data.get('data', {})
                    }
                else:
                    error_msg = resp_data.get('msg', '未知错误')
                    logger.error(f"❌ 签到失败: {error_msg}")
                    return {
                        'success': False,
                        'error': error_msg
                    }
            else:
                error_msg = f"HTTP {response.status_code}"
                logger.error(f"❌ 请求失败: {error_msg}")
                return {
                    'success': False,
                    'error': error_msg
                }

        except requests.exceptions.RequestException as e:
            error_msg = f"网络请求失败: {str(e)}"
            logger.error(f"❌ {error_msg}")
            return {
                'success': False,
                'error': error_msg
            }
        except Exception as e:
            error_msg = f"未知错误: {str(e)}"
            logger.error(f"❌ {error_msg}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': error_msg
            }

