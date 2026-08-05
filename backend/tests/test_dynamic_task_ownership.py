from __future__ import annotations

import unittest
from unittest.mock import patch

from workers.dynamic_trace import _is_current_task_device_owner, _set_device_online


class DynamicTaskOwnershipTest(unittest.TestCase):
    @patch("workers.dynamic_trace.fetch_one")
    def test_current_owner_is_accepted(self, fetch_one_mock) -> None:
        fetch_one_mock.return_value = {
            "task_status": "dynamic_tracing",
            "task_device_id": "device-1",
            "device_status": "busy",
            "current_task_id": "task-1",
        }

        self.assertTrue(_is_current_task_device_owner("task-1", "device-1"))

    @patch("workers.dynamic_trace.fetch_one")
    def test_stale_task_is_rejected(self, fetch_one_mock) -> None:
        fetch_one_mock.return_value = {
            "task_status": "dynamic_tracing",
            "task_device_id": "device-1",
            "device_status": "busy",
            "current_task_id": "task-2",
        }

        self.assertFalse(_is_current_task_device_owner("task-1", "device-1"))

    @patch("workers.dynamic_trace.execute", return_value=(1, 0))
    def test_current_owner_can_release_device(self, execute_mock) -> None:
        self.assertTrue(_set_device_online("device-1", "task-1"))
        self.assertEqual(execute_mock.call_args.args[1], ("device-1", "task-1"))
        self.assertIn("status = 'busy'", execute_mock.call_args.args[0])

    @patch("workers.dynamic_trace.execute", return_value=(0, 0))
    def test_stale_task_cannot_release_device(self, _execute_mock) -> None:
        with self.assertLogs("workers.dynamic_trace", level="WARNING"):
            self.assertFalse(_set_device_online("device-1", "task-1"))


if __name__ == "__main__":
    unittest.main()
