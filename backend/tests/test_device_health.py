from __future__ import annotations

import unittest
from unittest.mock import patch

from services.device_service import (
    DeviceHealthResult,
    _refresh_device_runtime,
    check_device_health,
)


class DeviceHealthProbeTest(unittest.TestCase):
    def _command_outputs(self, *outputs: str | None):
        return patch("services.device_service._run_command_optional", side_effect=outputs)

    def test_health_probe_requires_shell_marker(self) -> None:
        with self._command_outputs("device", "not-the-marker"):
            result = check_device_health("serial-1")

        self.assertEqual(result.state, "quarantined")
        self.assertIn("shell", result.reason or "")

    def test_health_probe_requires_package_manager(self) -> None:
        with self._command_outputs("device", "__device_health_ok__", None):
            result = check_device_health("serial-1")

        self.assertEqual(result.state, "quarantined")
        self.assertIn("package", result.reason or "")

    def test_health_probe_rejects_less_than_five_gib_available(self) -> None:
        data_free_kib = 5 * 1024 * 1024 - 1
        df_output = (
            "Filesystem 1K-blocks Used Available Use% Mounted on\n"
            f"/dev/fuse 10000000 1 {data_free_kib} 1% /data\n"
        )
        with self._command_outputs(
            "device",
            "__device_health_ok__",
            "package:/system/framework/framework-res.apk",
            df_output,
        ):
            result = check_device_health("serial-1")

        self.assertEqual(result.state, "quarantined")
        self.assertEqual(result.available_kib, data_free_kib)
        self.assertIn("storage", result.reason or "")

    def test_health_probe_accepts_healthy_device(self) -> None:
        data_free_kib = 5 * 1024 * 1024
        df_output = (
            "Filesystem 1K-blocks Used Available Use% Mounted on\n"
            f"/dev/fuse 10000000 1 {data_free_kib} 1% /data\n"
        )
        with self._command_outputs(
            "device",
            "__device_health_ok__",
            "package:/system/framework/framework-res.apk",
            df_output,
        ):
            result = check_device_health("serial-1")

        self.assertEqual(result, DeviceHealthResult("healthy", None, data_free_kib))


class DeviceHeartbeatTest(unittest.TestCase):
    @patch("services.device_service.update_device")
    @patch("services.device_service.check_device_health")
    def test_idle_unhealthy_device_is_quarantined(self, health_mock, update_mock) -> None:
        health_mock.return_value = DeviceHealthResult("quarantined", "shell marker missing", None)
        device = {"id": "device-1", "serial": "serial-1", "status": "online", "current_task_id": None}

        refreshed = _refresh_device_runtime(device)

        self.assertEqual(refreshed["status"], "quarantined")
        self.assertEqual(refreshed["quarantine_reason"], "shell marker missing")
        self.assertIsNotNone(refreshed["quarantined_at"])
        fields = update_mock.call_args.args[1]
        self.assertEqual(fields["status"], "quarantined")
        self.assertEqual(fields["quarantine_reason"], "shell marker missing")

    @patch("services.device_service.update_device")
    @patch("services.device_service.check_device_health")
    def test_transport_offline_device_is_offline(self, health_mock, update_mock) -> None:
        health_mock.return_value = DeviceHealthResult("offline", "adb get-state returned offline", None)
        device = {"id": "device-1", "serial": "serial-1", "status": "online", "current_task_id": None}

        refreshed = _refresh_device_runtime(device)

        self.assertEqual(refreshed["status"], "offline")
        fields = update_mock.call_args.args[1]
        self.assertEqual(fields, {"status": "offline"})

    @patch("services.device_service.update_device")
    @patch("services.device_service.check_device_health")
    def test_quarantined_device_is_not_automatically_recovered(self, health_mock, update_mock) -> None:
        device = {
            "id": "device-1",
            "serial": "serial-1",
            "status": "quarantined",
            "current_task_id": None,
            "quarantine_reason": "previous failure",
        }

        refreshed = _refresh_device_runtime(device)

        self.assertEqual(refreshed["status"], "quarantined")
        health_mock.assert_not_called()
        update_mock.assert_not_called()

    @patch("services.device_service.update_device")
    @patch("services.device_service.check_device_health")
    def test_busy_unhealthy_device_is_not_reassigned_by_heartbeat(self, health_mock, update_mock) -> None:
        health_mock.return_value = DeviceHealthResult("quarantined", "package manager unavailable", None)
        device = {
            "id": "device-1",
            "serial": "serial-1",
            "status": "busy",
            "current_task_id": "task-1",
        }

        refreshed = _refresh_device_runtime(device)

        self.assertEqual(refreshed["status"], "busy")
        self.assertEqual(refreshed["current_task_id"], "task-1")
        update_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
