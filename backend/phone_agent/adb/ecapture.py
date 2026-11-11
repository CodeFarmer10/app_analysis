"""eCapture lifecycle helpers for Android decrypted TLS capture."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional


class ECaptureCapture:
    """Manage an eCapture process on an Android device."""

    def __init__(
        self,
        device_id: Optional[str] = None,
        host_dir: Optional[str] = None,
        binary_path: Optional[str] = None,
        device_binary_path: str = "/data/local/tmp/ecapture",
        device_output_path: Optional[str] = None,
        device_keylog_path: Optional[str] = None,
        host_filename: str = "decrypted_capture.pcapng",
        iface: str = "wlan0",
        ssl_version: str = "boringssl_a_15",
        enabled: bool = False,
    ):
        self.device_id = device_id
        self.host_dir = host_dir or "./captures"
        self.binary_path = binary_path or ""
        self.device_binary_path = device_binary_path
        self.device_output_path = device_output_path or "/data/local/tmp/decrypted_capture.pcapng"
        self.device_keylog_path = device_keylog_path or str(
            Path(self.device_output_path).with_suffix(".keys")
        )
        self.host_filename = host_filename
        self.iface = iface
        self.ssl_version = ssl_version
        self.enabled = enabled
        self._is_capturing = False

    def start_capture(self) -> bool:
        if not self.enabled:
            return False
        if self._is_capturing:
            return False
        host_binary = self._resolve_host_binary()
        if not host_binary:
            print(f"eCapture binary not found: {self.binary_path}")
            return False
        if not self._has_root():
            print("eCapture skipped: root permission unavailable")
            return False

        try:
            self._execute_adb_command(f"push {shlex.quote(host_binary)} {shlex.quote(self.device_binary_path)}")
            self._execute_adb_command(f"shell su -c 'chmod 755 {shlex.quote(self.device_binary_path)}'")
            self._execute_adb_command(f"shell su -c 'rm -f {shlex.quote(self.device_output_path)}'")
            self._execute_adb_command(f"shell su -c 'rm -f {shlex.quote(self.device_keylog_path)}'")
            self._execute_adb_command("shell su -c 'rm -f /data/local/tmp/ecapture.log'")
            self._stop_existing()
            capture_iface = self._resolve_capture_iface()
            start_cmd = (
                "shell su -c "
                f"'nohup {shlex.quote(self.device_binary_path)} tls -m pcap "
                f"--ssl_version={shlex.quote(self.ssl_version)} "
                f"--keylogfile {shlex.quote(self.device_keylog_path)} "
                f"--pcapfile {shlex.quote(self.device_output_path)} "
                f"-i {shlex.quote(capture_iface)} > /data/local/tmp/ecapture.log 2>&1 &'"
            )
            self._execute_adb_command(start_cmd)
            time.sleep(1.0)
            if not self._is_process_running():
                log_tail = self._read_device_file_tail("/data/local/tmp/ecapture.log", lines=20)
                print(f"eCapture exited immediately; decrypted capture disabled for this run. {log_tail}")
                return False
            self._is_capturing = True
            return True
        except Exception as exc:
            print(f"eCapture start failed, continuing without decrypted capture: {exc}")
            self._is_capturing = False
            return False

    def stop_capture(self) -> Optional[str]:
        if not self._is_capturing:
            return None
        self._stop_existing()
        host_path = self._pull_output_file()
        self._execute_best_effort(f"shell su -c 'rm -f {shlex.quote(self.device_output_path)}'")
        self._execute_best_effort(f"shell su -c 'rm -f {shlex.quote(self.device_keylog_path)}'")
        self._is_capturing = False
        return host_path

    def _resolve_host_binary(self) -> str | None:
        if not self.binary_path:
            return None
        expanded_path = Path(self.binary_path).expanduser()
        if expanded_path.is_file():
            return str(expanded_path)
        return shutil.which(self.binary_path)

    def _has_root(self) -> bool:
        try:
            result = subprocess.run(
                self._get_adb_prefix() + ["shell", "su", "-c", "id"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return result.returncode == 0 and "uid=0" in (result.stdout or "")
        except Exception:
            return False

    def _stop_existing(self) -> None:
        self._execute_best_effort("shell su -c 'pkill -TERM -x ecapture'")
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if not self._is_process_running():
                return
            time.sleep(0.1)
        self._execute_best_effort("shell su -c 'killall -SIGKILL ecapture'")

    def _resolve_capture_iface(self) -> str:
        preferred = (self.iface or "").strip()
        if preferred and self._iface_has_address(preferred):
            return preferred
        detected = self._detect_default_iface()
        return detected or preferred or "wlan0"

    def _iface_has_address(self, iface: str) -> bool:
        result = subprocess.run(
            self._get_adb_prefix()
            + ["shell", "su", "-c", f"ip -o addr show {shlex.quote(iface)} scope global"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return result.returncode == 0 and bool((result.stdout or "").strip())

    def _detect_default_iface(self) -> str | None:
        result = subprocess.run(
            self._get_adb_prefix()
            + ["shell", "su", "-c", "ip -o addr show scope global | awk '{print $2; exit}'"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            return None
        iface = (result.stdout or "").strip().splitlines()
        return iface[0].strip().rstrip(":") if iface else None

    def _is_process_running(self) -> bool:
        result = subprocess.run(
            self._get_adb_prefix() + ["shell", "su", "-c", "pidof ecapture"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return result.returncode == 0 and bool((result.stdout or "").strip())

    def _read_device_file_tail(self, path: str, lines: int = 20) -> str:
        result = subprocess.run(
            self._get_adb_prefix() + ["shell", "su", "-c", f"tail -n {int(lines)} {shlex.quote(path)}"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        output = (result.stdout or result.stderr or "").strip()
        return output[:1000]

    def _pull_output_file(self) -> Optional[str]:
        os.makedirs(self.host_dir, exist_ok=True)
        host_filepath = os.path.join(self.host_dir, self.host_filename)
        try:
            self._execute_adb_command(f"pull {shlex.quote(self.device_output_path)} {shlex.quote(host_filepath)}")
        except Exception as exc:
            print(f"Failed to pull eCapture output: {exc}")
            return None
        return host_filepath if os.path.exists(host_filepath) else None

    def _get_adb_prefix(self) -> list[str]:
        if self.device_id:
            return ["adb", "-s", self.device_id]
        return ["adb"]

    def _execute_best_effort(self, command: str) -> None:
        try:
            self._execute_adb_command(command)
        except Exception:
            pass

    def _execute_adb_command(self, command: str, timeout: Optional[int] = None) -> None:
        full_cmd = self._get_adb_prefix()
        full_cmd.extend(shlex.split(command))
        subprocess.run(full_cmd, check=True, timeout=timeout, capture_output=True, shell=False)
