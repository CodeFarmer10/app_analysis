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


if __name__ == "__main__":
    unittest.main()
