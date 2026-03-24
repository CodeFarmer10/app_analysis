"""Traffic capture utilities for Android devices using tcpdump."""

import os
import re
import shlex
import subprocess
import time
from typing import Optional

# NFLOG group number for traffic capture
NFLOG_GROUP = 30

# CONNMARK value for marking app traffic
CONNMARK_VALUE = 1001


class TrafficCapture:
    """
    Manages packet capture on Android devices using tcpdump with root privileges.

    This class provides methods to start and stop packet capture,
    saving captures to pcap files on device and moving them to host.
    """

    def __init__(
        self,
        device_id: Optional[str] = None,
        host_dir: Optional[str] = None,
        device_path: Optional[str] = None,
        capture_filter: Optional[str] = None,
        package_name: Optional[str] = None
    ):
        """
        Initialize TrafficCapture with device ID and capture settings.

        Args:
            device_id: ADB device ID for multi-device setups
            host_dir: Directory on host to save pcap files (default: ./captures/)
            device_path: Path on device to save pcap file (default: /sdcard/capture.pcap)
            capture_filter: BPF filter for tcpdump (e.g., "port 80" for HTTP traffic)
            package_name: Package name to capture traffic for (e.g., "com.tencent.mm")
        """
        self.device_id = device_id
        self.host_dir = host_dir or "./captures"
        self.device_path = device_path or "/sdcard/capture.pcap"
        self.capture_filter = capture_filter or ""
        self.package_name = package_name
        self.app_uid = None
        self._is_capturing = False

    def _get_app_uid(self, package_name: str) -> Optional[int]:
        """
        Get the UID for a given package name.

        Args:
            package_name: The package name to get UID for

        Returns:
            The UID if found, None otherwise
        """
        if not package_name:
            return None

        try:
            adb_prefix = self._get_adb_prefix()
            result = subprocess.run(
                adb_prefix + ["shell", "dumpsys", "package", package_name],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=10
            )

            # Parse the output to find UID
            output = result.stdout
            for line in output.split("\n"):
                if "appId=" in line:
                    match = re.search(r"appId=(\d+)", line)
                    if match:
                        return int(match.group(1))

            # Alternative method using pm list packages
            result = subprocess.run(
                adb_prefix + ["shell", "pm", "list", "packages", "-U", package_name],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=10
            )

            output = result.stdout
            for line in output.split("\n"):
                if package_name in line and ":" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        uid_str = parts[-1].strip()
                        if uid_str.isdigit():
                            return int(uid_str)

            return None

        except subprocess.TimeoutExpired:
            print("Timeout getting app UID")
            return None
        except Exception as e:
            print(f"Error getting app UID: {e}")
            return None
    
    def _iptables_rules(self) -> list[str]:
        """所有需要添加/删除的 iptables 规则"""
        return [
            # 上行：打 connmark，让返回包也能被识别
            f"iptables -t mangle -A OUTPUT -m owner --uid-owner {self.app_uid} -j CONNMARK --set-mark {CONNMARK_VALUE}",
            # 上行：导入 nflog
            f"iptables -t mangle -A OUTPUT -m owner --uid-owner {self.app_uid} -j NFLOG --nflog-group {NFLOG_GROUP}",
            # 下行：匹配同一连接的返回包，导入 nflog
            f"iptables -t mangle -A INPUT -m connmark --mark {CONNMARK_VALUE} -j NFLOG --nflog-group {NFLOG_GROUP}",
        ]
    
    def _setup_nflog_rule(self) -> bool:
        """
        Setup iptables NFLOG rule for specific app UID.

        Returns:
            bool: True if rule setup successfully, False otherwise
        """
        if not self.package_name:
            return False

        # Get app UID
        self.app_uid = self._get_app_uid(self.package_name)
        if self.app_uid is None:
            print(f"Failed to get UID for package: {self.package_name}")
            return False

        print(f"Found UID {self.app_uid} for package: {self.package_name}")

        try:
            # Execute all iptables rules
            for rule in self._iptables_rules():
                iptables_cmd = f"shell su -c '{rule}'"
                self._execute_adb_command(iptables_cmd)

            print(f"Setup NFLOG rules for UID {self.app_uid}")
            return True

        except subprocess.TimeoutExpired:
            print("Timeout setting up NFLOG rule")
            return False
        except Exception as e:
            print(f"Error setting up NFLOG rule: {e}")
            return False

    def _cleanup_nflog_rule(self) -> bool:
        """
        Cleanup iptables NFLOG rule for specific app UID.

        Returns:
            bool: True if rule cleanup successful, False otherwise
        """
        if not self.package_name or self.app_uid is None:
            return False

        try:
            # Remove all iptables rules (将 -A 替换为 -D 来删除)
            for rule in self._iptables_rules():
                delete_rule = rule.replace(" -A ", " -D ")
                iptables_cmd = f"shell su -c '{delete_rule}'"
                self._execute_adb_command(iptables_cmd)
               
            print(f"Cleanup NFLOG rules for UID {self.app_uid}")
            return True

        except subprocess.TimeoutExpired:
            print("Timeout cleaning up NFLOG rule")
            return False
        except Exception as e:
            print(f"Error cleaning up NFLOG rule: {e}")
            return False

    def _delete_nflog_rules(self) -> None:
        """
        Delete all existing NFLOG rules for the NFLOG_GROUP.
        Used during cleanup to ensure no rules remain.
        """
        try:
            adb_prefix = self._get_adb_prefix()
            deleted_count = 0

            # Delete NFLOG rules from INPUT and OUTPUT chains
            for chain in ["INPUT", "OUTPUT"]:
                list_cmd = adb_prefix + ["shell", "su", "-c", f"iptables -t mangle -L {chain} -n --line-numbers"]
                result = subprocess.run(
                    list_cmd,
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                for line in result.stdout.split('\n'):
                    if ('--nflog-group' in line and str(NFLOG_GROUP) in line) or ('CONNMARK' in line and "UID" in line):
                        parts = line.split()
                        if parts and parts[0].isdigit():
                            delete_cmd = f"shell su -c 'iptables -t mangle -D {chain} {parts[0]}'"
                            try:
                                self._execute_adb_command(delete_cmd)
                                deleted_count += 1
                            except:
                                pass  # Continue even if deletion fails

            if deleted_count > 0:
                print(f"Cleaned up {deleted_count} NFLOG rule(s)")

        except Exception as e:
            print(f"Error cleaning NFLOG rules: {e}")

    def _stop_all_tcpdump(self) -> None:
        """
        Stop all tcpdump processes running on the device.
        """
        try:
            self._execute_adb_command("shell su -c 'killall -SIGTERM tcpdump'")
            time.sleep(0.5)
        except:
            pass

        try:
            self._execute_adb_command("shell su -c 'killall -SIGKILL tcpdump'")
        except:
            pass

    def start_capture(self) -> bool:
        """
        Start packet capture on device.
        If package_name is provided, will capture traffic for that specific app only.

        Returns:
            bool: True if capture started successfully
        """
        if self._is_capturing:
            print("Capture already in progress")
            return False

        # Stop all existing tcpdump processes
        self._stop_all_tcpdump()

        # Delete existing pcap file if it exists
        self._execute_adb_command(f"shell rm -f {self.device_path}")

         # Clean existing NFLOG rules before setting new ones
        self._delete_nflog_rules()

        if self.package_name:
            # Setup NFLOG rule for specific app
            if self._setup_nflog_rule():
                # Use nflog interface for capture with 1GB file size limit (1 file only)
                tcpdump_cmd = (
                    f"shell su -c 'nohup tcpdump -i nflog:{NFLOG_GROUP} -C 1024 -W 1 {self.capture_filter} -w {self.device_path} "
                    f"> /dev/null 2>&1 &'"
                )
                print(f"Successfully set up NFLOG rule for package: {self.package_name}")
            else:
                print("Failed to setup NFLOG rule, falling back to capture all traffic")
                # Use regular tcpdump for all traffic
                tcpdump_cmd = (
                    f"shell su -c 'nohup tcpdump -i any -C 1024 -W 1 {self.capture_filter} -w {self.device_path} "
                    f"> /dev/null 2>&1 &'"
                )
        else:
            # Capture all traffic with 1GB file size limit (1 file only)
            print("No package specified, capturing all traffic")
            tcpdump_cmd = (
                f"shell su -c 'nohup tcpdump -i any -C 1024 -W 1 {self.capture_filter} -w {self.device_path} "
                f"> /dev/null 2>&1 &'"
            )

        # Start tcpdump in background
        self._execute_adb_command(tcpdump_cmd)
        self._is_capturing = True

        # Wait a moment for tcpdump to start
        time.sleep(0.5)

        print(f"Started packet capture: {self.device_path}")
        if self.package_name:
            print(f"Capturing traffic for package: {self.package_name} (UID: {self.app_uid})")
            print(f"Using NFLOG group: {NFLOG_GROUP}")
        if self.capture_filter:
            print(f"Capture filter: {self.capture_filter}")

        return True

    def stop_capture(self) -> Optional[str]:
        """
        Stop packet capture and move to host, then delete from device.
        Also cleans up NFLOG rules if package_name was specified.

        Returns:
            Optional[str]: Path to the pcap file on host, None otherwise
        """
        if not self._is_capturing:
            print("No capture in progress")
            return None

        # Stop all tcpdump processes
        self._stop_all_tcpdump()

        # Cleanup NFLOG rule if it was set up
        if self.package_name:
            self._cleanup_nflog_rule()

        # Pull and delete pcap file
        pcap_file_path = self._move_pcap_file()

        # Clean up
        self._is_capturing = False
        self.app_uid = None

        print(f"Packet capture stopped")

        return pcap_file_path

    def _move_pcap_file(self) -> Optional[str]:
        """
        Move pcap file from device to host and delete from device.

        Returns:
            Optional[str]: Path to the pcap file on host
        """
        # Create host directory if it doesn't exist
        os.makedirs(self.host_dir, exist_ok=True)

        # Build host file path
        filename = os.path.basename(self.device_path)
        host_filepath = f"{self.host_dir}/{filename}"
        
        # Pull file from device to host
        self._execute_adb_command(f"pull {self.device_path} {host_filepath}")

        if os.path.exists(host_filepath):
            # Delete file from device
            self._execute_adb_command(f"shell rm {self.device_path}")
            print(f"Capture saved to: {host_filepath} (removed from device)")
            return host_filepath
        else:
            print(f"Failed to pull capture file")
            return None

    def _get_adb_prefix(self) -> list:
        """Get ADB command prefix with optional device specifier."""
        if self.device_id:
            return ["adb", "-s", self.device_id]
        return ["adb"]

    def _execute_adb_command(self, command: str, timeout: Optional[int] = None) -> None:
        """
        Execute ADB command with device ID.

        Args:
            command: ADB command to execute (e.g., "shell su -c 'nohup tcpdump ...'")
            timeout: Optional timeout for command
        """
        full_cmd = self._get_adb_prefix()

        # Parse the command string respecting quotes
        # e.g., "shell su -c 'nohup tcpdump -i any'" -> ['shell', 'su', '-c', 'nohup tcpdump -i any']
        parsed_args = shlex.split(command)
        full_cmd.extend(parsed_args)

        subprocess.run(
            full_cmd,
            check=True,
            timeout=timeout,
            capture_output=True,
            shell=False
        )