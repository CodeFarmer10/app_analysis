from __future__ import annotations

import unittest

from phone_agent.adb.traffic import TrafficCapture


class TrafficCaptureTest(unittest.TestCase):
    def test_task_specific_device_path_keeps_expected_host_filename(self) -> None:
        capture = TrafficCapture(
            device_id="device-1",
            host_dir="/tmp/task-1",
            device_path="/sdcard/capture-task-1.pcap",
            host_filename="capture.pcap",
        )

        self.assertEqual(capture.device_path, "/sdcard/capture-task-1.pcap")
        self.assertEqual(capture.host_filename, "capture.pcap")

    def test_package_capture_does_not_fall_back_to_all_interfaces(self) -> None:
        capture = TrafficCapture(device_id="device-1", package_name="com.example.app")

        calls: list[str] = []
        capture._stop_all_tcpdump = lambda: None
        capture._delete_nflog_rules = lambda: None
        capture._setup_nflog_rule = lambda: False
        capture._execute_adb_command = lambda command: calls.append(command)

        self.assertFalse(capture.start_capture())
        self.assertFalse(any("tcpdump -i any" in command for command in calls))
        self.assertFalse(capture._is_capturing)

    def test_package_capture_defaults_to_only_target_uid(self) -> None:
        capture = TrafficCapture(package_name="com.example.app")

        self.assertEqual(capture._normalize_packages(), ["com.example.app"])


if __name__ == "__main__":
    unittest.main()
