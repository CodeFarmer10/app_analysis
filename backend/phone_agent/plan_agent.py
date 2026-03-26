"""Plan Agent for task planning."""

import base64
import json
import os
import traceback
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
import uuid

from phone_agent.config import get_plan_system_prompt
from phone_agent.device_factory import get_device_factory
from phone_agent.model import ModelClient, ModelConfig
from phone_agent.model.client import MessageBuilder
from phone_agent.agent import PhoneAgent, AgentConfig
from phone_agent.adb.traffic import TrafficCapture
from phone_agent.traffic_parser import TrafficParser, PacketInfo


@dataclass
class PlanAgentConfig:
    """Configuration for the PlanAgent."""

    max_steps: int = 20
    plan_system_prompt: str | None = None
    device_id: str | None = None
    result_dir: str | None = None

    def __post_init__(self):
        if self.plan_system_prompt is None:
            self.plan_system_prompt = get_plan_system_prompt()


@dataclass
class PlanResult:
    """Result of a planning step."""
    successed: bool = True
    finished: bool = False
    step_num: int = 0
    step: str | None = None
    before_screenshot_path: str | None = None
    after_screenshot_path: str | None = None
    message: str | None = None
    start_time: datetime = datetime.now()
    traffic_logs: list[PacketInfo] = None  # 流量日志
    def __post_init__(self):
        # Initialize default list for traffic_logs
        if self.traffic_logs is None:
            self.traffic_logs = []

    def to_dict(self) -> dict:
        """Convert PlanResult to dictionary for JSON serialization."""
        return {
            "successed": self.successed,
            "finished": self.finished,
            "step_num": self.step_num,
            "step": self.step,
            "before_screenshot_path": self.before_screenshot_path,
            "after_screenshot_path": self.after_screenshot_path,
            "message": self.message,
            "start_time": self.start_time.strftime("%Y-%m-%d %H:%M:%S.%f") if self.start_time else None,
            "traffic_logs": [p.to_dict() for p in self.traffic_logs]
        }


class PlanAgent:
    """
    AI-powered planning agent for task planning.

    The agent uses a vision-language model to:
    1. Plan overall approach to complete a task
    2. Break down task into steps
    3. Generate next execution step
    4. Update plan based on feedback

    Args:
        model_config: Configuration for the AI model.
        agent_config: Configuration for the agent behavior.

    Example:
        >>> from phone_agent import PlanAgent
        >>> from phone_agent.model import ModelConfig
        >>>
        >>> model_config = ModelConfig(base_url="http://localhost:8000/v1")
        >>> agent = PlanAgent(model_config)
        >>> result = agent.step("Open WeChat and send a message to John")
        >>> print(result.next_step)
    """

    def __init__(
        self,
        plan_model_config: ModelConfig | None = None,
        plan_agent_config: PlanAgentConfig | None = None,
        phone_agent_config: AgentConfig | None = None,
        phone_model_config: ModelConfig | None = None
    ):
        self.plan_model_config = plan_model_config or ModelConfig()
        self.plan_agent_config = plan_agent_config or PlanAgentConfig()
        self.phone_agent = PhoneAgent(agent_config=phone_agent_config, model_config=phone_model_config)

        self.plan_model_client = ModelClient(self.plan_model_config)

        # Initialize traffic capture and parser
        self.traffic_capture = TrafficCapture(
            device_id=phone_agent_config.device_id,
            host_dir=plan_agent_config.result_dir
        )
        self.traffic_parser = TrafficParser()

        self._context: list[dict[str, Any]] = []
        self._execution_results: list[PlanResult] = []
        self._step_count = 0

    def run(self,package: str, task: str) -> str:
        """
        Run the plan agent to generate a complete plan.

        Args:
            task: Natural language description of the task.

        Returns:
            Final plan or completion message.
        """
        self._context = []
        self._step_count = 0
        self._current_plan = ""
        self._execution_results = []
        if not os.path.exists(self.plan_agent_config.result_dir):
            os.makedirs(self.plan_agent_config.result_dir, exist_ok=True)
        device_factory = get_device_factory()
        plan_result=PlanResult(step_num=self._step_count,step="Launch app") 
        self._execution_results.append(plan_result)
        device_factory.launch_app_by_package(package, self.plan_agent_config.device_id)
        plan_result.successed=True
        # Start traffic capture after launching app
        self.traffic_capture.package_name=package
        self.traffic_capture.start_capture()

        screenshot = device_factory.get_screenshot(self.plan_agent_config.device_id, self.plan_agent_config.result_dir)
        plan_result.after_screenshot_path=screenshot.path
        # First step: generate initial plan
        result = self._execute_plan_step(package,task,is_first=True)

        if result.finished or not result.successed:
            self._save_results()
            return result.message or "Task completed"

        # Continue generating steps until finished or max steps reached
        while self._step_count < self.plan_agent_config.max_steps:
            result = self._execute_plan_step(package,result.message,is_first=False)
            if result.finished or not result.successed:
                self._save_results()
                return  "Task completed"
        self._save_results()
        return  "Max steps reached"

    def step(self, task: str | None = None) -> PlanResult:
        """
        Execute a single step of the plan agent.

        Useful for manual control or debugging.

        Args:
            task: Task description (only needed for first step).
            execution_result: Result of executing the previous step (optional).

        Returns:
            PlanResult with step details.
        """
        is_first = len(self._context) == 0

        if is_first and not task:
            raise ValueError("Task is required for the first step")

        return self._execute_plan_step(task, is_first)

    def reset(self) -> None:
        """Reset the agent state for a new task."""
        self._context = []
        self._step_count = 0

    def _execute_plan_step(
        self,package:str,user_message: str | None = None, is_first: bool = False) -> PlanResult:
        # Capture current screen state
        device_factory = get_device_factory()
        screenshot = device_factory.get_screenshot(self.plan_agent_config.device_id, self.plan_agent_config.result_dir)
        current_app = device_factory.get_current_app(self.plan_agent_config.device_id)
        if current_app != package:
            self._execution_results[-1].successed=False
            self._execution_results[-1].message=f"APP闪退"
            return self._execution_results[-1]
        
        plan_result=PlanResult() 
        self._execution_results.append(plan_result)
        self._step_count += 1
        plan_result.step_num=self._step_count
        plan_result.before_screenshot_path=screenshot.path
        
        print("\n" + "=" * 20 + f"PlanAgent|Step {self._step_count}" + "=" * 20 + "\n")
        # Build messages for planning
        if is_first:
            self._context.append(
                MessageBuilder.create_system_message(self.plan_agent_config.plan_system_prompt)
            )

        # base64_data = screenshot.base64_data
        text_content = f"{user_message}\n\n**运行界面**"
        self._context.append(
            MessageBuilder.create_user_message(
                text=text_content, image_base64=screenshot.base64_data
            )
        )

        # Get planning response from model
        try:
            # print("\n" + "=" * 50)
            response = self.plan_model_client.request_plan(self._context)
            # Parse plan response
        except Exception as e:
            traceback.print_exc()
            plan_result.successed=False
            plan_result.message=f"Plan Model error: {e}"
            return plan_result
        try:
            plan_response = json.loads(response)
            step = plan_response.get("next_step", "")
            status=plan_response.get("status", "")
            message=plan_response.get("message", "")
        except Exception as e:
            step = response
            status= ""
            message=""

        if status=="finished":
            plan_result.finished=True
            plan_result.message=message
            return plan_result

        self._context[-1] = MessageBuilder.remove_images_from_message(self._context[-1])
        # Add assistant response to context
        self._context.append(
            MessageBuilder.create_assistant_message(
                f"{step}"
            )
        )
        # Execute step
        plan_result.step=step
        plan_result.start_time=datetime.now()
        try:
            result = self.phone_agent.run(step)
        except Exception as e:
            traceback.print_exc()
            plan_result.successed=False
            plan_result.message=f"Phone Agent error: {str(e)}"
            return plan_result
        
        plan_result.successed=True
        plan_result.message=result.message
        plan_result.after_screenshot_path=self._save_screenshot(result.base64_data)

        return plan_result

    @property
    def context(self) -> list[dict[str, Any]]:
        """Get the current conversation context."""
        return self._context.copy()

    @property
    def step_count(self) -> int:
        """Get the current step count."""
        return self._step_count  

    def _save_screenshot(self, base64_data: str) -> str:
        """
        Save screenshot to the screenshot directory.

        Args:
            base64_data: Base64 encoded screenshot data.
            filename: Desired filename for the screenshot.

        Returns:
            Path to the saved screenshot file.
        """
        if not self.plan_agent_config.result_dir:
            return ""

        # Decode base64 and save image
        image_data = base64.b64decode(base64_data)
        file_name = f"screenshot_{uuid.uuid4()}.png"
        screenshot_path = Path(self.plan_agent_config.result_dir) / file_name

        with open(screenshot_path, 'wb') as f:
            f.write(image_data)

        return str(screenshot_path)

    def _save_results(self):
        # Stop traffic capture before saving results and get pcap file path
        pcap_path = self.traffic_capture.stop_capture()

        # Parse pcap file and map traffic logs to operations if pcap exists
        if pcap_path:
            self._map_traffic_to_operations(pcap_path)

        # Save operation results
        results_dict = [r.to_dict() for r in self._execution_results]
        results_file = f"{self.plan_agent_config.result_dir}/operation_results.json"

        with open(results_file, "w", encoding='utf-8') as f:
            json.dump(results_dict, f, indent=4, ensure_ascii=False)

        print(f"Results saved to: {results_file}")

    def _map_traffic_to_operations(self, pcap_path: str) -> None:
        """
        Parse PCAP file and map traffic packets to operations based on time intervals.

        For each operation, filter packets within the time window between its start_time
        and the next operation's start_time, then deduplicate by unique_key.

        Args:
            pcap_path: Path to the PCAP file.
        """
        # Parse all packets from pcap file
        all_packets = self.traffic_parser.parse_pcap(pcap_path,filter_expr=f"ip.dst != 127.0.0.1")
        if not all_packets:
            print(f"No packets found in PCAP file: {pcap_path}")
            return

        print(f"Parsed {len(all_packets)} packets from {pcap_path}")

        # Sort packets by timestamp for proper time window filtering
        all_packets.sort(key=lambda p: p.timestamp)

        # Map packets to each operation based on time windows
        for i, result in enumerate(self._execution_results):
            if not result.start_time:
                continue

            # Determine time window: from current start_time to next operation's start_time
            start_timestamp = result.start_time.timestamp()

            # For the last operation, use all packets after its start_time
            if i < len(self._execution_results) - 1:
                next_result = self._execution_results[i + 1]
                if next_result.start_time:
                    end_timestamp = next_result.start_time.timestamp()
                else:
                    end_timestamp = float('inf')
            else:
                end_timestamp = float('inf')

            # Filter packets within the time window
            window_packets = [
                p for p in all_packets
                if start_timestamp <= p.timestamp < end_timestamp
            ]

            # Deduplicate by unique_key
            unique_packets = {}
            for packet in window_packets:
                unique_key = packet.get_unique_key()
                if unique_key not in unique_packets:
                    unique_packets[unique_key] = packet

            # Assign deduplicated packets to traffic_logs
            result.traffic_logs = list(unique_packets.values())

            print(f"Step {result.step_num}: {len(window_packets)} packets in window, {len(result.traffic_logs)} after deduplication")





   
