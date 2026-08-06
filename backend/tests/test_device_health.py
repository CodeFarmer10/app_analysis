from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest.mock import patch

from repositories import device_repo
from services.device_service import (
    DeviceHealthResult,
    _refresh_device_runtime,
    check_device_health,
    create_new_device,
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
    @patch("services.device_service.update_idle_device_snapshot", return_value=1, create=True)
    @patch("services.device_service.check_device_health")
    def test_idle_unhealthy_device_is_quarantined(self, health_mock, update_mock) -> None:
        health_mock.return_value = DeviceHealthResult("quarantined", "shell marker missing", None)
        device = {
            "id": "device-1",
            "serial": "serial-1",
            "status": "online",
            "current_task_id": None,
            "quarantine_task_id": "stale-task",
            "quarantine_package_name": "com.example.stale",
        }

        refreshed = _refresh_device_runtime(device)

        self.assertEqual(refreshed["status"], "quarantined")
        self.assertEqual(refreshed["quarantine_reason"], "shell marker missing")
        self.assertIsNotNone(refreshed["quarantined_at"])
        self.assertEqual(update_mock.call_args.args[:2], ("device-1", "online"))
        fields = update_mock.call_args.args[2]
        self.assertEqual(fields["status"], "quarantined")
        self.assertEqual(fields["quarantine_reason"], "shell marker missing")
        self.assertIsNone(fields["quarantine_task_id"])
        self.assertIsNone(fields["quarantine_package_name"])

    @patch("services.device_service.update_idle_device_snapshot", return_value=1, create=True)
    @patch("services.device_service.check_device_health")
    def test_transport_offline_device_is_offline(self, health_mock, update_mock) -> None:
        health_mock.return_value = DeviceHealthResult("offline", "adb get-state returned offline", None)
        device = {"id": "device-1", "serial": "serial-1", "status": "online", "current_task_id": None}

        refreshed = _refresh_device_runtime(device)

        self.assertEqual(refreshed["status"], "offline")
        fields = update_mock.call_args.args[2]
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
    @patch("services.device_service.update_idle_device_snapshot")
    @patch("services.device_service.check_device_health")
    def test_recovering_device_is_not_probed_or_changed(
        self,
        health_mock,
        update_idle_mock,
        update_mock,
    ) -> None:
        device = {
            "id": "device-1",
            "serial": "serial-1",
            "status": "recovering",
            "current_task_id": None,
            "recovery_started_at": "2026-08-06 10:00:00",
        }

        refreshed = _refresh_device_runtime(device)

        self.assertIs(refreshed, device)
        self.assertEqual(refreshed["status"], "recovering")
        health_mock.assert_not_called()
        update_idle_mock.assert_not_called()
        update_mock.assert_not_called()

    @patch("services.device_service.update_device")
    @patch("services.device_service.update_idle_device_snapshot")
    @patch("services.device_service.check_device_health")
    def test_error_device_is_not_probed_or_changed(
        self,
        health_mock,
        update_idle_mock,
        update_mock,
    ) -> None:
        device = {
            "id": "device-1",
            "serial": "serial-1",
            "status": "error",
            "current_task_id": None,
            "recovery_error": "reboot: timed out",
        }

        refreshed = _refresh_device_runtime(device)

        self.assertIs(refreshed, device)
        self.assertEqual(refreshed["status"], "error")
        health_mock.assert_not_called()
        update_idle_mock.assert_not_called()
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

    @patch("services.device_service.update_idle_device_snapshot", return_value=0, create=True)
    @patch("services.device_service.check_device_health")
    def test_idle_probe_does_not_overwrite_concurrent_allocation(
        self,
        health_mock,
        update_mock,
    ) -> None:
        health_mock.return_value = DeviceHealthResult("quarantined", "shell failed", None)
        snapshot = {
            "id": "device-1",
            "serial": "serial-1",
            "status": "online",
            "current_task_id": None,
        }

        refreshed = _refresh_device_runtime(snapshot)

        self.assertEqual(refreshed["status"], "online")
        self.assertIsNone(refreshed["current_task_id"])
        self.assertEqual(update_mock.call_args.args[:2], ("device-1", "online"))

    @patch("services.device_service.update_idle_device_snapshot", return_value=0)
    @patch("services.device_service.check_device_health")
    def test_idle_healthy_probe_does_not_overwrite_concurrent_allocation(
        self,
        health_mock,
        update_mock,
    ) -> None:
        health_mock.return_value = DeviceHealthResult("healthy", None, 6 * 1024 * 1024)
        snapshot = {
            "id": "device-1",
            "serial": "serial-1",
            "status": "online",
            "current_task_id": None,
            "last_heartbeat_at": None,
        }

        refreshed = _refresh_device_runtime(snapshot)

        self.assertEqual(refreshed["status"], "online")
        self.assertIsNone(refreshed["last_heartbeat_at"])
        self.assertEqual(update_mock.call_args.args[:2], ("device-1", "online"))


class DeviceCreationHealthTest(unittest.TestCase):
    @patch("services.device_service.get_device_detail", return_value={"id": "device-1"})
    @patch("services.device_service.create_device_record")
    @patch(
        "services.device_service._collect_device_info",
        return_value={"model": "Phone", "android_version": "15", "resolution": "1080x2400"},
    )
    @patch("services.device_service.check_device_health")
    @patch("services.device_service._bootstrap_device_tools")
    @patch("services.device_service._ensure_device_reachable")
    @patch("services.device_service.get_device_by_serial", return_value=None)
    def test_low_storage_device_is_created_quarantined(
        self,
        _existing_mock,
        _reachable_mock,
        _bootstrap_mock,
        health_mock,
        _info_mock,
        create_mock,
        _detail_mock,
    ) -> None:
        health_mock.return_value = DeviceHealthResult(
            "quarantined",
            "storage below 5 GiB",
            1024,
        )

        create_new_device("serial-1", "test phone")

        payload = create_mock.call_args.args[0]
        self.assertEqual(payload["status"], "quarantined")
        self.assertEqual(payload["quarantine_reason"], "storage below 5 GiB")
        self.assertIsNotNone(payload["quarantined_at"])
        self.assertIsNone(payload["last_heartbeat_at"])

    def test_creation_maps_healthy_and_offline_states(self) -> None:
        cases = (
            (DeviceHealthResult("healthy", None, 6 * 1024 * 1024), "online", True),
            (DeviceHealthResult("offline", "adb get-state returned offline"), "offline", False),
        )
        for health, expected_status, expects_heartbeat in cases:
            with self.subTest(state=health.state), ExitStack() as stack:
                stack.enter_context(
                    patch("services.device_service.get_device_by_serial", return_value=None)
                )
                stack.enter_context(patch("services.device_service._ensure_device_reachable"))
                stack.enter_context(patch("services.device_service._bootstrap_device_tools"))
                stack.enter_context(
                    patch(
                        "services.device_service._collect_device_info",
                        return_value={
                            "model": "Phone",
                            "android_version": "15",
                            "resolution": "1080x2400",
                        },
                    )
                )
                stack.enter_context(
                    patch("services.device_service.check_device_health", return_value=health)
                )
                create_mock = stack.enter_context(
                    patch("services.device_service.create_device_record")
                )
                stack.enter_context(
                    patch("services.device_service.get_device_detail", return_value={"id": "device-1"})
                )

                create_new_device("serial-1")

                payload = create_mock.call_args.args[0]
                self.assertEqual(payload["status"], expected_status)
                self.assertEqual(payload["last_heartbeat_at"] is not None, expects_heartbeat)
                self.assertIsNone(payload["quarantine_reason"])
                self.assertIsNone(payload["quarantined_at"])


class DeviceRepositoryHeartbeatTest(unittest.TestCase):
    @patch("repositories.device_repo.execute", return_value=(0, 0))
    def test_idle_update_is_guarded_by_snapshot_status_and_empty_owner(self, execute_mock) -> None:
        rows = device_repo.update_idle_device_snapshot(
            "device-1",
            "online",
            {"status": "quarantined"},
        )

        self.assertEqual(rows, 0)
        sql = execute_mock.call_args.args[0]
        self.assertIn("status = %s", sql)
        self.assertIn("current_task_id IS NULL", sql)
        self.assertEqual(execute_mock.call_args.args[1][-2:], ("device-1", "online"))


if __name__ == "__main__":
    unittest.main()
