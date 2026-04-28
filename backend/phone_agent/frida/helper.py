from __future__ import annotations

import json
import logging
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any

from phone_agent.frida.registry import build_frida_script, load_frida_rules

logger = logging.getLogger(__name__)
DEFAULT_FRIDA_RULES_PATH = str(Path(__file__).resolve().parent / "rules.json")


def _load_frida_module():
    try:  # pragma: no cover - optional runtime dependency
        import frida as frida_module
    except ImportError:  # pragma: no cover - optional runtime dependency
        return None
    return frida_module


@dataclass
class FridaHelperConfig:
    enabled: bool = False
    mode: str = "spawn"
    rules_path: str = DEFAULT_FRIDA_RULES_PATH
    device_timeout_seconds: int = 5
    attach_delay_seconds: float = 1.0
    auto_start_frida_server: bool = True
    adb_path: str = "adb"
    frida_server_remote_path: str = "/data/local/tmp/frida-server"
    frida_server_start_wait_seconds: float = 0.8
    persist_events: bool = True
    fail_open: bool = True
    result_dir: str | None = None


class FridaHelper:
    def __init__(self, device_id: str | None, config: FridaHelperConfig | None = None):
        self.device_id = device_id
        self.config = config or FridaHelperConfig()
        self.device = None
        self.session = None
        self.script = None
        self.pid: int | None = None
        self.package_name = ""
        self._resume_pending = False
        self._lock = Lock()
        self._events: list[dict[str, Any]] = []
        self._diagnostics: list[dict[str, Any]] = []
        self._status = "disabled" if not self.config.enabled else "idle"
        self._frida_module = None

    @property
    def mode(self) -> str:
        return str(self.config.mode or "spawn").strip().lower()

    @property
    def status(self) -> str:
        return self._status

    def start(self, package_name: str, defer_resume: bool = False) -> bool:
        """
        Start Frida instrumentation for the target package.

        - spawn mode: spawn + attach + load script.
          If `defer_resume` is False (default), process resumes immediately.
          If `defer_resume` is True, caller must invoke `resume()` manually.
        - attach mode: attach to running process and load script.

        Returns:
            bool: True when Frida session/script is started; otherwise False in fail-open paths.
        """
        if not self.config.enabled:
            self._status = "disabled"
            return False
        if self._get_frida_module() is None:
            self._record_diagnostic("frida_unavailable", "frida python package not installed")
            self._status = "unavailable"
            return False

        rules = load_frida_rules(self.config.rules_path)
        if not rules:
            self._record_diagnostic("no_rules", f"no frida rules loaded path={self.config.rules_path}")
            self._status = "no_rules"
            return False

        self.package_name = package_name
        try:
            self._ensure_frida_server_ready()
            self.device = self._resolve_device()
            if self.mode == "spawn":
                self.pid = self.device.spawn([package_name])
                self.session = self.device.attach(self.pid)
                self._resume_pending = True
            else:
                if self.config.attach_delay_seconds > 0:
                    time.sleep(self.config.attach_delay_seconds)
                self.session = self.device.attach(package_name)

            self.script = self.session.create_script(build_frida_script(rules))
            self.script.on("message", self._on_message)
            self.script.load()

            self._status = "running"
            if self._resume_pending and not defer_resume:
                self.resume()
            return True
        except Exception as exc:  # pragma: no cover - runtime dependent
            self._record_diagnostic("start_failed", str(exc))
            self._status = "failed"
            self.cleanup()
            if self.config.fail_open:
                logger.warning("frida start skipped package=%s err=%s", package_name, exc)
                return False
            raise

    def _adb_prefix(self) -> list[str]:
        command = [self.config.adb_path]
        if self.device_id:
            command.extend(["-s", self.device_id])
        return command

    def _run_adb_shell(self, shell_command: str) -> subprocess.CompletedProcess[str]:
        command = self._adb_prefix() + ["shell", shell_command]
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=max(1, int(self.config.device_timeout_seconds)),
            check=False,
        )

    def _is_frida_server_running(self) -> bool:
        check_command = "su -c 'ps -A | grep frida-server >/dev/null'"
        result = self._run_adb_shell(check_command)
        return result.returncode == 0

    def _start_frida_server(self) -> None:
        remote_path = self.config.frida_server_remote_path
        start_command = (
            f"su -c 'chmod 755 {remote_path}; "
            f"nohup {remote_path} >/dev/null 2>&1 </dev/null &'"
        )
        result = self._run_adb_shell(start_command)
        if result.returncode != 0:
            raise RuntimeError(
                f"start frida-server failed rc={result.returncode} stderr={result.stderr.strip()}"
            )

    def _ensure_frida_server_ready(self) -> None:
        if not self.config.auto_start_frida_server:
            return
        if self._is_frida_server_running():
            return
        self._record_diagnostic("frida_server_missing", "frida-server not running, starting")
        self._start_frida_server()
        if self.config.frida_server_start_wait_seconds > 0:
            time.sleep(self.config.frida_server_start_wait_seconds)
        if not self._is_frida_server_running():
            raise RuntimeError("frida-server not running after auto start")
        self._record_diagnostic("frida_server_started", "frida-server started by helper")

    def resume(self) -> None:
        if not self._resume_pending or not self.device or self.pid is None:
            return
        try:
            self.device.resume(self.pid)
            self._resume_pending = False
        except Exception as exc:  # pragma: no cover - runtime dependent
            self._record_diagnostic("resume_failed", str(exc))
            if not self.config.fail_open:
                raise

    def stop(self) -> None:
        if self._status == "stopped":
            return
        self.save_results()
        self.cleanup()
        self._status = "stopped"

    def cleanup(self) -> None:
        if self.script is not None:
            try:
                self.script.unload()
            except Exception:  # pragma: no cover - runtime dependent
                pass
            self.script = None
        if self.session is not None:
            try:
                self.session.detach()
            except Exception:  # pragma: no cover - runtime dependent
                pass
            self.session = None
        self.device = None
        self.pid = None
        self._resume_pending = False

    def export_events(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self._events]

    def export_diagnostics(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self._diagnostics]

    def map_events_to_results(self, execution_results: list[Any]) -> None:
        events = self.export_events()
        if not events:
            for result in execution_results:
                result.frida_events = []
            return

        events.sort(key=lambda item: float(item.get("timestamp") or 0))
        for index, result in enumerate(execution_results):
            start_time = getattr(result, "start_time", None)
            if not start_time:
                result.frida_events = []
                continue
            start_timestamp = start_time.timestamp()
            if index < len(execution_results) - 1:
                next_start = getattr(execution_results[index + 1], "start_time", None)
                end_timestamp = next_start.timestamp() if next_start else float("inf")
            else:
                end_timestamp = float("inf")
            result.frida_events = [
                item for item in events if start_timestamp <= float(item.get("timestamp") or 0) < end_timestamp
            ]

    def save_results(self) -> str | None:
        if not self.config.persist_events or not self.config.result_dir:
            return None
        output_path = Path(self.config.result_dir) / "frida_events.json"
        payload = {
            "status": self.status,
            "device_id": self.device_id,
            "package_name": self.package_name,
            "events": self.export_events(),
            "diagnostics": self.export_diagnostics(),
        }
        output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(output_path)

    def _resolve_device(self):
        frida_module = self._get_frida_module()
        if frida_module is None:
            raise RuntimeError("frida python package not installed")
        manager = frida_module.get_device_manager()
        if self.device_id:
            try:
                return manager.get_device(self.device_id, timeout=self.config.device_timeout_seconds)
            except Exception as exc:  # pragma: no cover - runtime dependent
                message = (
                    f"frida get_device failed device_id={self.device_id} "
                    f"timeout={self.config.device_timeout_seconds}s err={exc}"
                )
                print(message)
                logger.warning(message)
                self._record_diagnostic("get_device_failed", message)
        return frida_module.get_usb_device(timeout=self.config.device_timeout_seconds)

    def _get_frida_module(self):
        if self._frida_module is not None:
            return self._frida_module
        self._frida_module = _load_frida_module()
        return self._frida_module

    def _on_message(self, message: dict[str, Any], _data: bytes | None) -> None:
        msg_type = str(message.get("type") or "")
        if msg_type == "send":
            payload = message.get("payload") or {}
            payload_type = payload.get("type")
            if payload_type == "event":
                event = payload.get("payload") or {}
                if isinstance(event, dict):
                    normalized_event = self._normalize_event(event)
                    with self._lock:
                        self._events.append(normalized_event)
                return
            if payload_type == "state":
                self._record_diagnostic(str(payload.get("status") or "state"), json.dumps(payload, ensure_ascii=False))
                return
        if msg_type == "error":
            stack = str(message.get("stack") or message.get("description") or "script error")
            self._record_diagnostic("script_error", stack)

    def _record_diagnostic(self, status: str, message: str) -> None:
        with self._lock:
            self._diagnostics.append(
                {
                    "status": status,
                    "message": message,
                    "timestamp": time.time(),
                }
            )

    def _normalize_event(self, event: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(event)
        normalized["retval"] = self._strip_retval_class_prefix(normalized.get("retval"))
        return normalized

    def _strip_retval_class_prefix(self, value: Any) -> Any:
        if not isinstance(value, str):
            return value
        text = value.strip()
        if not text:
            return value
        separator_index = text.find(":")
        if separator_index <= 0:
            return value
        prefix = text[:separator_index]
        suffix = text[separator_index + 1 :]
        if not suffix:
            return value
        if not re.match(r"^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)+$", prefix):
            return value
        return suffix
