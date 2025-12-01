#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WPS自动签到脚本

该脚本用于自动执行WPS的签到任务，包括：
- 读取账号配置信息
- 获取RSA加密公钥
- 执行签到操作
- 推送执行结果

Author: Assistant
Date: 2025-12-01
"""

import json
import logging
import sys
from typing import List, Dict, Any
from pathlib import Path

from api import WPSAPI

# 获取项目根目录
project_root = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(project_root))

# 导入需要的模块
from notification import send_notification, NotificationSound


class WPSTasks:
    """WPS签到任务自动化执行类"""

    def __init__(self, config_path: str = None):
        """
        初始化任务执行器

        Args:
            config_path (str): 配置文件的完整路径，如果为None则使用项目根目录下的config/token.json
        """
        # 设置配置文件路径
        if config_path is None:
            self.config_path = project_root / "config" / "token.json"
        else:
            self.config_path = Path(config_path)

        self.accounts: List[Dict[str, Any]] = []
        self.logger = self._setup_logger()
        self._init_accounts()
        self.account_results: List[Dict[str, Any]] = []

    def _setup_logger(self) -> logging.Logger:
        """
        设置日志记录器

        Returns:
            logging.Logger: 配置好的日志记录器
        """
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.INFO)

        # 创建控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        # 设置日志格式
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        console_handler.setFormatter(formatter)

        # 避免重复添加处理器
        if not logger.handlers:
            logger.addHandler(console_handler)

        return logger

    def _init_accounts(self):
        """从配置文件中读取账号信息"""
        if not self.config_path.exists():
            self.logger.error(f"配置文件不存在: {self.config_path}")
            raise FileNotFoundError(f"配置文件不存在: {self.config_path}")

        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
                # 从统一配置文件的 wps 节点读取
                wps_config = config_data.get('wps', {})
                self.accounts = wps_config.get('accounts', [])

            if not self.accounts:
                self.logger.warning("配置文件中没有找到 wps 账号信息")
            else:
                self.logger.info(f"成功加载 {len(self.accounts)} 个账号配置")

        except json.JSONDecodeError as e:
            self.logger.error(f"配置文件JSON解析失败: {e}")
            raise
        except Exception as e:
            self.logger.error(f"读取配置文件失败: {e}")
            raise

    def process_account(self, account_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        处理单个账号的签到任务

        Args:
            account_info (Dict[str, Any]): 账号信息字典

        Returns:
            Dict[str, Any]: 处理结果
        """
        account_name = account_info.get('account_name', '未命名账号')
        self.logger.info(f"\n{'=' * 60}")
        self.logger.info(f"开始处理账号: {account_name}")
        self.logger.info(f"{'=' * 60}")

        result = {
            'account_name': account_name,
            'success': False,
            'message': '',
            'sign_info': {}
        }

        try:
            # 获取账号配置
            user_id = account_info.get('user_id')
            cookies = account_info.get('cookies', '')
            user_agent = account_info.get('user_agent')

            # 检查必需参数
            if not user_id:
                error_msg = "账号配置中缺少user_id，跳过签到"
                self.logger.warning(f"⚠️ {account_name}: {error_msg}")
                result['message'] = error_msg
                return result

            if not cookies:
                error_msg = "账号配置中缺少cookies"
                self.logger.error(f"❌ {error_msg}")
                result['message'] = error_msg
                return result

            # 创建API实例
            api = WPSAPI(cookies=cookies, user_agent=user_agent)

            # 执行签到
            sign_result = api.sign_in(user_id=user_id)

            if sign_result['success']:
                result['success'] = True
                result['message'] = '签到成功'
                result['sign_info'] = sign_result.get('data', {})
                self.logger.info(f"✅ {account_name} 签到成功")

                # 打印签到信息
                if result['sign_info']:
                    self.logger.info(f"签到详情: {json.dumps(result['sign_info'], ensure_ascii=False, indent=2)}")
            else:
                result['message'] = sign_result.get('error', '签到失败')
                self.logger.error(f"❌ {account_name} 签到失败: {result['message']}")

        except Exception as e:
            error_msg = f"处理账号时发生异常: {str(e)}"
            self.logger.error(f"❌ {error_msg}")
            result['message'] = error_msg
            import traceback
            traceback.print_exc()

        return result

    def run(self):
        """执行所有账号的签到任务"""
        self.logger.info("=" * 60)
        self.logger.info("WPS自动签到任务开始")
        self.logger.info("=" * 60)

        if not self.accounts:
            self.logger.warning("没有需要处理的账号")
            return

        # 处理每个账号
        for account_info in self.accounts:
            result = self.process_account(account_info)
            self.account_results.append(result)

        # 输出统计信息
        self._print_summary()

        # 发送通知
        self._send_notification()

    def _print_summary(self):
        """打印执行结果统计"""
        self.logger.info("\n" + "=" * 60)
        self.logger.info("执行结果统计")
        self.logger.info("=" * 60)

        total = len(self.account_results)
        success = sum(1 for r in self.account_results if r['success'])
        failed = total - success

        self.logger.info(f"总账号数: {total}")
        self.logger.info(f"签到成功: {success}")
        self.logger.info(f"签到失败: {failed}")

        # 打印详细结果
        self.logger.info("\n详细结果:")
        for result in self.account_results:
            status = "✅ 成功" if result['success'] else "❌ 失败"
            self.logger.info(f"  {result['account_name']}: {status} - {result['message']}")

        self.logger.info("=" * 60)

    def _send_notification(self):
        """发送推送通知"""
        if not self.account_results:
            return

        total = len(self.account_results)
        success = sum(1 for r in self.account_results if r['success'])
        failed = total - success

        # 构造通知标题
        title = "WPS签到结果通知"

        # 构造通知内容
        content_lines = [
            f"📊 总账号数: {total}",
            f"✅ 签到成功: {success}",
            f"❌ 签到失败: {failed}",
            "",
            "📋 详细结果:"
        ]

        for result in self.account_results:
            status = "✅" if result['success'] else "❌"
            content_lines.append(f"{status} {result['account_name']}: {result['message']}")

        content = "\n".join(content_lines)

        # 发送通知
        try:
            send_notification(
                title=title,
                content=content,
                sound=NotificationSound.BIRDSONG
            )
            self.logger.info("✅ 推送通知已发送")
        except Exception as e:
            self.logger.warning(f"⚠️ 发送推送通知失败: {str(e)}")


def main():
    """主函数"""
    try:
        # 创建任务执行器
        tasks = WPSTasks()

        # 执行任务
        tasks.run()

    except FileNotFoundError as e:
        print(f"❌ 错误: {e}")
        print("请确保配置文件存在并包含WPS账号信息")
        sys.exit(1)
    except Exception as e:
        print(f"❌ 发生未知错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()