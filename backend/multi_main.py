#!/usr/bin/env python3
"""
Test Main - PlanAgent and PhoneAgent integration test.

Usage:
    python test_main.py [OPTIONS] TASK

Example:
    python test_main.py --device-id emulator-5554 "打开微信，搜索张三，发送消息"
"""

import argparse
import os
import sys
import logging
from datetime import datetime

# Set UTF-8 encoding for Windows console before any imports that might print
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
    

from phone_agent import PlanAgent, PlanAgentConfig
from phone_agent.model import ModelConfig
from phone_agent.agent import AgentConfig
# from main import check_system_requirements


class Logger:
    """Custom logger that outputs to both console and file."""
    
    def __init__(self, log_file: str | None = None):
        """Initialize logger with optional file output."""
        self.log_file = log_file
        self.console = sys.stdout
        
        if log_file:
            log_dir = os.path.dirname(log_file)
            if log_dir:
                os.makedirs(log_dir, exist_ok=True)
            self.file_handle = open(log_file, 'w', encoding='utf-8')
        else:
            self.file_handle = None
    
    def write(self, message: str):
        """Write message to both console and file."""
        self.console.write(message)
        self.console.flush()
        
        if self.file_handle and not self.file_handle.closed:
            self.file_handle.write(message)
            self.file_handle.flush()
    
    def flush(self):
        """Flush both console and file."""
        self.console.flush()
        if self.file_handle and not self.file_handle.closed:
            self.file_handle.flush()
    
    def close(self):
        """Close file handle if exists."""
        if self.file_handle and not self.file_handle.closed:
            self.file_handle.close()
            self.file_handle = None
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()



def run_task_with_planning(
    task: str,
    package: str,
    plan_model_config: ModelConfig,
    plan_agent_config: PlanAgentConfig,
    phone_model_config: ModelConfig,
    phone_agent_config: AgentConfig
) -> str:
    """
    Execute a task using PlanAgent for planning and PhoneAgent for execution.

    Args:
        task: Natural language description of the task.
        plan_model_config: Model configuration for PlanAgent.
        plan_agent_config: PlanAgent configuration.

    Returns:
        Final result message.
    """
    # Create PlanAgent for planning
    plan_agent = PlanAgent(plan_model_config=plan_model_config, plan_agent_config=plan_agent_config,phone_model_config=phone_model_config,phone_agent_config=phone_agent_config)

    print(f"📋 任务: {task}")

    result = plan_agent.run(package=package,task=task)

    return result


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Test PlanAgent and PhoneAgent integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Run with default settings
    python multi_main.py --result-dir results --package com.tencent.mm 
        """,
    )

    # Plan Model options
    parser.add_argument(
        "--plan-base-url",
        type=str,
        default=os.getenv("PLAN_AGENT_BASE_URL", "https://dashscope.aliyuncs.com/compatible-mode/v1"),
        help="Plan Agent Model API base URL",
    )

    parser.add_argument(
        "--plan-model",
        type=str,
        default=os.getenv("PLAN_AGENT_MODEL", "qwen3-vl-235b-a22b-instruct"),
        help="Plan Agent Model name",
    )

    parser.add_argument(
        "--plan-apikey",
        type=str,
        default=os.getenv("PLAN_AGENT_API_KEY", "sk-11c87318288d4bbbb102ab2a831a7b3c"),
        help="Plan Agent API key for model authentication",
    )

    # PlanAgent options
    parser.add_argument(
        "--plan-max-steps",
        type=int,
        default=int(os.getenv("PLAN_AGENT_MAX_PLAN_STEPS", "10")),
        help="Plan Agent Maximum planning steps",
    )

    # Device options
    parser.add_argument(
        "--device-id",
        "-d",
        type=str,
        default=os.getenv("DEVICE_ID","192.168.50.99:5555"),
        help="Device ID",
    )

    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress verbose output",
    )

    # Task argument
    parser.add_argument(
        "--task",
        type=str,
        help="Task to execute",
        default="模拟操作探索APP功能",
    )

    # Package argument
    parser.add_argument(
        "--package",
        type=str,
        help="Package name of the app to launch",
        default="com.kook.im",
    )

    # Result directory argument
    parser.add_argument(
        "--result-dir",
        type=str,
        default='data/com.kook.im',
        help="Directory to store results",
    )

    parser.add_argument(
        "--phone-base-url",
        type=str,
        default=os.getenv("PHONE_AGENT_BASE_URL", "https://open.bigmodel.cn/api/paas/v4"),
        help="Phone Agent Model API base URL",
    )

    parser.add_argument(
        "--phone-model",
        type=str,
        default=os.getenv("PHONE_AGENT_MODEL", "autoglm-phone"),
        help="Phone Agent Model name",
    )

    parser.add_argument(
        "--phone-apikey",
        type=str,
        default=os.getenv("PHONE_AGENT_API_KEY", "3db312763d5d47e8927c79d9ccb2bbc9.r1jcQHG2ytMkN5SQ"),
        help="Phone Agent API key for model authentication",
    )

    # PlanAgent options
    parser.add_argument(
        "--phone-max-steps",
        type=int,
        default=int(os.getenv("PHONE_AGENT_MAX_STEPS", "3")),
        help="Phone Agent Maximum execution steps",
    )
    args = parser.parse_args()

    # Create model config
    plan_model_config = ModelConfig(
        base_url=args.plan_base_url,
        api_key=args.plan_apikey,
        model_name=args.plan_model,
        extra_body={
        'enable_thinking': False,
        "thinking_budget": 81920}
    )

    # Create PlanAgent config
    plan_agent_config = PlanAgentConfig(
        max_steps=args.plan_max_steps,
        device_id=args.device_id,
        result_dir=args.result_dir
    )
    
    # Create phone model config
    phone_model_config = ModelConfig(
        base_url=args.phone_base_url,
        api_key=args.phone_apikey,
        model_name=args.phone_model
    )
    
    # Create phone agent config
    phone_agent_config = AgentConfig(
        max_steps=args.phone_max_steps,
        device_id=args.device_id
    )
    
    # Check system requirements
    #if not check_system_requirements():
    #    sys.exit(1)
    
    # Setup logger
    logger = Logger(f"{args.result_dir}/run.log")
    sys.stdout = logger
    
    # Log execution start
    print(f"\n{'=' * 60}")
    print(f"任务执行开始: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"任务描述: {args.task}")
    print(f"设备ID: {args.device_id}")
    print(f"应用包名: {args.package}")
    print(f"{'=' * 60}\n")
    
    # Run the task
    try:
        result = run_task_with_planning(
            task=args.task,
            package=args.package,
            plan_model_config=plan_model_config,
            plan_agent_config=plan_agent_config,
            phone_model_config=phone_model_config,
            phone_agent_config=phone_agent_config
        )
        print(f"\n{'=' * 60}")
        print(f"最终结果: {result}")
        print(f"任务执行完成: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'=' * 60}\n")

        sys.exit(0)

    except KeyboardInterrupt:
        print("\n\n⚠️  任务被用户中断")
        print(f"任务中断时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ 任务执行失败: {e}")
        print(f"失败时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        logger.close()


if __name__ == "__main__":
    main()
