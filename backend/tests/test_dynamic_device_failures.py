from __future__ import annotations

import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import MagicMock, patch

from services.device_service import DeviceHealthResult
from workers import dynamic_trace


class DynamicDeviceFailureTest(unittest.TestCase):
    def _connection_mocks(self):
        connection = MagicMock()
        cursor = MagicMock()
        connection.cursor.return_value.__enter__.return_value = cursor
        connection.cursor.return_value.__exit__.return_value = False
        return connection, cursor

    def _patch_trace_until_agent(
        self,
        stack: ExitStack,
        result_dir: Path,
    ) -> dict[str, MagicMock]:
        mocks = {
            "install": stack.enter_context(patch("workers.dynamic_trace.install_apk")),
            "run": stack.enter_context(patch("workers.dynamic_trace._run_task_with_log")),
            "health": stack.enter_context(patch("workers.dynamic_trace.check_device_health")),
            "mark_failed": stack.enter_context(patch("workers.dynamic_trace._mark_owned_task_failed")),
            "requeue": stack.enter_context(
                patch("workers.dynamic_trace._quarantine_and_requeue_owned_task", return_value=True)
            ),
            "quarantine": stack.enter_context(
                patch("workers.dynamic_trace._quarantine_owned_device", return_value=True)
            ),
            "release": stack.enter_context(patch("workers.dynamic_trace._set_device_online")),
            "uninstall": stack.enter_context(
                patch("workers.dynamic_trace.uninstall_apk", return_value=(True, "Success"))
            ),
            "accessibility": stack.enter_context(
                patch("workers.dynamic_trace.clear_accessibility_services", return_value=(True, ["ok"]))
            ),
            "local_cleanup": stack.enter_context(patch("workers.dynamic_trace._cleanup_downloaded_apk")),
        }
        stack.enter_context(
            patch("workers.dynamic_trace.get_task_by_id", return_value={"apk_path": "apps/test.apk"})
        )
        stack.enter_context(patch("workers.dynamic_trace._is_current_task_device_owner", return_value=True))
        stack.enter_context(
            patch(
                "workers.dynamic_trace._extract_trace_context",
                return_value=("com.example.app", "apps/test.apk", "serial-1"),
            )
        )
        stack.enter_context(patch("workers.dynamic_trace._prepare_result_dir", return_value=result_dir))
        stack.enter_context(
            patch("workers.dynamic_trace.storage_service.download_to_temp", return_value="/tmp/test.apk")
        )
        stack.enter_context(patch("workers.dynamic_trace._maybe_unpack_packed_app", return_value=None))
        return mocks

    def test_fork_failure_is_device_error(self) -> None:
        self.assertTrue(dynamic_trace.is_device_error_message("shell: fork failed: Resource temporarily unavailable"))

    def test_offline_and_abb_exec_closed_are_device_errors(self) -> None:
        messages = (
            "error: device offline",
            "device unauthorized",
            "adb: failed to run abb_exec. Error: closed",
            "adb: connect error for write: closed",
            "error: device '10.12.187.124:5555' not found",
            "adb install timeout after 300s",
        )
        for message in messages:
            with self.subTest(message=message):
                self.assertTrue(dynamic_trace.is_device_error_message(message))

    def test_invalid_apk_is_not_device_error(self) -> None:
        messages = (
            "Failure [INSTALL_PARSE_FAILED_NOT_APK: Failed to parse APK]",
            "Failure [INSTALL_FAILED_INVALID_APK]",
            "Failure [INSTALL_FAILED_VERSION_DOWNGRADE]",
        )
        for message in messages:
            with self.subTest(message=message):
                self.assertFalse(dynamic_trace.is_device_error_message(message))

    @patch("workers.dynamic_trace.get_connection")
    def test_device_error_requeues_task_and_quarantines_owner(self, get_connection_mock) -> None:
        connection, cursor = self._connection_mocks()
        get_connection_mock.return_value.__enter__.return_value = connection
        cursor.fetchone.side_effect = [
            {"status": "dynamic_tracing", "device_id": "device-1"},
            {"status": "busy", "current_task_id": "task-1"},
        ]
        cursor.execute.return_value = 1

        self.assertTrue(
            dynamic_trace._quarantine_and_requeue_owned_task(
                "task-1", "device-1", "device offline"
            )
        )

        sql = "\n".join(call.args[0] for call in cursor.execute.call_args_list)
        self.assertIn("FOR UPDATE", sql)
        self.assertIn("SET status = 'waiting_device'", sql)
        self.assertIn("device_id = NULL", sql)
        self.assertIn("SET status = 'quarantined'", sql)
        self.assertIn("current_task_id = NULL", sql)
        self.assertIn("quarantined_at = NOW()", sql)
        connection.commit.assert_called_once()

    @patch("workers.dynamic_trace.get_connection")
    def test_stale_worker_cannot_requeue_new_owner(self, get_connection_mock) -> None:
        connection, cursor = self._connection_mocks()
        get_connection_mock.return_value.__enter__.return_value = connection
        cursor.fetchone.return_value = {
            "status": "dynamic_tracing",
            "device_id": "device-2",
        }

        self.assertFalse(
            dynamic_trace._quarantine_and_requeue_owned_task(
                "task-1", "device-1", "device offline"
            )
        )

        executed_sql = [call.args[0] for call in cursor.execute.call_args_list]
        self.assertFalse(any("UPDATE tasks" in sql for sql in executed_sql))
        self.assertFalse(any("UPDATE devices" in sql for sql in executed_sql))
        connection.commit.assert_called_once()

    @patch("workers.dynamic_trace.get_connection")
    def test_partial_quarantine_transition_rolls_back(self, get_connection_mock) -> None:
        connection, cursor = self._connection_mocks()
        get_connection_mock.return_value.__enter__.return_value = connection
        cursor.fetchone.side_effect = [
            {"status": "dynamic_tracing", "device_id": "device-1"},
            {"status": "busy", "current_task_id": "task-1"},
        ]
        cursor.execute.side_effect = [1, 1, 1, 0]

        with self.assertRaises(dynamic_trace.TaskOwnershipLostError):
            dynamic_trace._quarantine_and_requeue_owned_task(
                "task-1", "device-1", "device offline"
            )

        connection.rollback.assert_called_once()
        connection.commit.assert_not_called()

    def test_non_adb_runtime_errors_with_device_phrases_remain_failed(self) -> None:
        messages = (
            "model request failed: connection reset by peer",
            "MinIO upload failed: no space left on device",
        )
        for message in messages:
            with (
                self.subTest(message=message),
                tempfile.TemporaryDirectory() as temp_dir,
                ExitStack() as stack,
            ):
                result_dir = Path(temp_dir) / "result"
                result_dir.mkdir()
                mocks = self._patch_trace_until_agent(stack, result_dir)
                mocks["install"].return_value = (True, "Success")
                mocks["run"].side_effect = RuntimeError(message)

                result = dynamic_trace.trace_task("task-1", "device-1")

                self.assertEqual(result["status"], "dynamic_failed")
                mocks["mark_failed"].assert_called_once()
                mocks["requeue"].assert_not_called()
                mocks["quarantine"].assert_not_called()

    def test_ownership_loss_skips_all_device_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, ExitStack() as stack:
            result_dir = Path(temp_dir) / "result"
            result_dir.mkdir()
            mocks = self._patch_trace_until_agent(stack, result_dir)
            mocks["install"].return_value = (True, "Success")
            mocks["run"].side_effect = dynamic_trace.TaskOwnershipLostError("ownership changed")

            result = dynamic_trace.trace_task("task-1", "device-1")

            self.assertEqual(result["reason"], "device_ownership_mismatch")
            mocks["local_cleanup"].assert_called_once_with("/tmp/test.apk")
            mocks["uninstall"].assert_not_called()
            mocks["accessibility"].assert_not_called()
            mocks["release"].assert_not_called()

    def test_install_policy_errors_requeue_and_quarantine(self) -> None:
        messages = (
            "Failure [INSTALL_FAILED_USER_RESTRICTED: Install canceled by user]",
            "Failure [INSTALL_FAILED_BLOCKED_BY_ADMIN: Installation blocked]",
        )
        for message in messages:
            with (
                self.subTest(message=message),
                tempfile.TemporaryDirectory() as temp_dir,
                ExitStack() as stack,
            ):
                result_dir = Path(temp_dir) / "result"
                result_dir.mkdir()
                mocks = self._patch_trace_until_agent(stack, result_dir)
                mocks["install"].return_value = (False, message)

                result = dynamic_trace.trace_task("task-1", "device-1")

                self.assertEqual(result["status"], "waiting_device")
                mocks["requeue"].assert_called_once()
                mocks["health"].assert_not_called()
                mocks["mark_failed"].assert_not_called()
                mocks["release"].assert_not_called()

    @patch("workers.dynamic_trace._quarantine_owned_device", return_value=True)
    @patch("workers.dynamic_trace.clear_accessibility_services", return_value=(True, ["ok"]))
    @patch("workers.dynamic_trace.uninstall_apk", return_value=(False, "adb uninstall timeout after 120s"))
    def test_uninstall_failure_quarantines_completed_task_device(
        self,
        _uninstall_mock,
        _accessibility_mock,
        quarantine_mock,
    ) -> None:
        isolated = dynamic_trace._cleanup_device_after_trace(
            task_id="task-1",
            device_id="device-1",
            package_name="com.example.app",
            adb_device_id="serial-1",
            app_installed=True,
        )

        self.assertTrue(isolated)
        quarantine_mock.assert_called_once()
        self.assertIn("卸载APK失败", quarantine_mock.call_args.args[2])

    def test_completed_trace_does_not_release_device_after_uninstall_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, ExitStack() as stack:
            result_dir = Path(temp_dir) / "result"
            result_dir.mkdir()
            stack.enter_context(
                patch("workers.dynamic_trace.get_task_by_id", return_value={"apk_path": "apps/test.apk"})
            )
            stack.enter_context(patch("workers.dynamic_trace._is_current_task_device_owner", return_value=True))
            stack.enter_context(
                patch(
                    "workers.dynamic_trace._extract_trace_context",
                    return_value=("com.example.app", "apps/test.apk", "serial-1"),
                )
            )
            stack.enter_context(patch("workers.dynamic_trace._prepare_result_dir", return_value=result_dir))
            stack.enter_context(
                patch("workers.dynamic_trace.storage_service.download_to_temp", return_value="/tmp/test.apk")
            )
            stack.enter_context(patch("workers.dynamic_trace.install_apk", return_value=(True, "Success")))
            stack.enter_context(patch("workers.dynamic_trace._maybe_unpack_packed_app", return_value=None))
            stack.enter_context(patch("workers.dynamic_trace._run_task_with_log", return_value="done"))
            stack.enter_context(patch("workers.dynamic_trace._load_operation_results", return_value=[{}]))
            stack.enter_context(
                patch(
                    "workers.dynamic_trace._parse_operation_results",
                    return_value=([{"action": "点击", "is_success": 1}], [], []),
                )
            )
            stack.enter_context(
                patch("workers.dynamic_trace.run_real_controller_tagging", return_value=({}, 0))
            )
            stack.enter_context(patch("workers.dynamic_trace._upload_trace_files", return_value=(None, None)))
            stack.enter_context(patch("workers.dynamic_trace._persist_trace_results"))
            stack.enter_context(patch("workers.dynamic_trace.generate_report.delay"))
            stack.enter_context(patch("workers.dynamic_trace._cleanup_downloaded_apk"))
            stack.enter_context(
                patch(
                    "workers.dynamic_trace.uninstall_apk",
                    return_value=(False, "adb uninstall timeout after 120s"),
                )
            )
            stack.enter_context(
                patch("workers.dynamic_trace.clear_accessibility_services", return_value=(True, ["ok"]))
            )
            quarantine_mock = stack.enter_context(
                patch("workers.dynamic_trace._quarantine_owned_device", return_value=True)
            )
            release_mock = stack.enter_context(patch("workers.dynamic_trace._set_device_online"))

            result = dynamic_trace.trace_task("task-1", "device-1")

        self.assertEqual(result["status"], "completed")
        quarantine_mock.assert_called_once()
        release_mock.assert_not_called()

    @patch("workers.dynamic_trace._quarantine_owned_device", return_value=True)
    @patch(
        "workers.dynamic_trace.clear_accessibility_services",
        return_value=(False, ["FAIL settings -> error: device offline"]),
    )
    def test_accessibility_device_error_quarantines_device(
        self,
        _accessibility_mock,
        quarantine_mock,
    ) -> None:
        isolated = dynamic_trace._cleanup_device_after_trace(
            task_id="task-1",
            device_id="device-1",
            package_name="com.example.app",
            adb_device_id="serial-1",
            app_installed=False,
        )

        self.assertTrue(isolated)
        quarantine_mock.assert_called_once()

    @patch("workers.dynamic_trace._quarantine_owned_device")
    @patch(
        "workers.dynamic_trace.clear_accessibility_services",
        return_value=(False, ["FAIL settings -> permission denied"]),
    )
    def test_accessibility_app_error_does_not_quarantine_device(
        self,
        _accessibility_mock,
        quarantine_mock,
    ) -> None:
        isolated = dynamic_trace._cleanup_device_after_trace(
            task_id="task-1",
            device_id="device-1",
            package_name="com.example.app",
            adb_device_id="serial-1",
            app_installed=False,
        )

        self.assertFalse(isolated)
        quarantine_mock.assert_not_called()

    @patch("workers.dynamic_trace.get_connection")
    def test_result_persistence_rejects_lost_ownership_before_mutation(
        self,
        get_connection_mock,
    ) -> None:
        connection, cursor = self._connection_mocks()
        get_connection_mock.return_value.__enter__.return_value = connection
        cursor.fetchone.return_value = {
            "status": "waiting_device",
            "device_id": None,
        }

        with self.assertRaises(dynamic_trace.TaskOwnershipLostError):
            dynamic_trace._persist_trace_results(
                task_id="task-1",
                device_id="device-1",
                pcap_path=None,
                run_log_path=None,
                dynamic_rows=[],
                traffic_rows=[],
                frida_rows=[],
            )

        executed_sql = [call.args[0] for call in cursor.execute.call_args_list]
        self.assertFalse(any("DELETE FROM" in sql for sql in executed_sql))
        connection.rollback.assert_called_once()

    @patch("workers.dynamic_trace._set_device_online", return_value=True)
    @patch("workers.dynamic_trace.clear_accessibility_services", return_value=(True, ["ok"]))
    @patch("workers.dynamic_trace._cleanup_downloaded_apk")
    @patch("workers.dynamic_trace.storage_service.download_to_temp", return_value="/tmp/test.apk")
    @patch("workers.dynamic_trace._prepare_result_dir")
    @patch("workers.dynamic_trace._extract_trace_context")
    @patch("workers.dynamic_trace._is_current_task_device_owner", return_value=True)
    @patch("workers.dynamic_trace.get_task_by_id", return_value={"apk_path": "apps/test.apk"})
    def test_no_health_probe_occurs_before_first_install_attempt(
        self,
        _task_mock,
        _owner_mock,
        context_mock,
        result_dir_mock,
        _download_mock,
        _cleanup_apk_mock,
        _accessibility_mock,
        _release_mock,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result_dir_mock.return_value = Path(temp_dir) / "result"
            result_dir_mock.return_value.mkdir()
            context_mock.return_value = ("com.example.app", "apps/test.apk", "serial-1")
            events: list[str] = []

            def install_side_effect(*_args, **_kwargs):
                events.append("install")
                return False, "Failure [INSTALL_FAILED_INVALID_APK]"

            def health_side_effect(_serial):
                events.append("health")
                return DeviceHealthResult("healthy")

            with patch("workers.dynamic_trace.install_apk", side_effect=install_side_effect), patch(
                "workers.dynamic_trace.check_device_health",
                side_effect=health_side_effect,
            ), patch(
                "workers.dynamic_trace._mark_owned_task_failed",
                return_value=True,
            ):
                result = dynamic_trace.trace_task("task-1", "device-1")

        self.assertEqual(events, ["install"])
        self.assertEqual(result["status"], "dynamic_failed")

    @patch("workers.dynamic_trace._set_device_online")
    @patch("workers.dynamic_trace.clear_accessibility_services", return_value=(True, ["ok"]))
    @patch("workers.dynamic_trace._cleanup_downloaded_apk")
    @patch("workers.dynamic_trace.storage_service.download_to_temp", return_value="/tmp/test.apk")
    @patch("workers.dynamic_trace._prepare_result_dir")
    @patch("workers.dynamic_trace._extract_trace_context")
    @patch("workers.dynamic_trace._is_current_task_device_owner", return_value=True)
    @patch("workers.dynamic_trace.get_task_by_id", return_value={"apk_path": "apps/test.apk"})
    @patch("workers.dynamic_trace._quarantine_and_requeue_owned_task", return_value=True)
    def test_opaque_install_failure_probes_health_after_failure(
        self,
        requeue_mock,
        _task_mock,
        _owner_mock,
        context_mock,
        result_dir_mock,
        _download_mock,
        _cleanup_apk_mock,
        _accessibility_mock,
        release_mock,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result_dir_mock.return_value = Path(temp_dir) / "result"
            result_dir_mock.return_value.mkdir()
            context_mock.return_value = ("com.example.app", "apps/test.apk", "serial-1")
            events: list[str] = []

            def install_side_effect(*_args, **_kwargs):
                events.append("install")
                return False, "Performing Streamed Install\nerror: unexpected byte 0x02"

            def health_side_effect(_serial):
                events.append("health")
                return DeviceHealthResult("quarantined", "package manager check failed")

            with patch("workers.dynamic_trace.install_apk", side_effect=install_side_effect), patch(
                "workers.dynamic_trace.check_device_health",
                side_effect=health_side_effect,
            ):
                result = dynamic_trace.trace_task("task-1", "device-1")

        self.assertEqual(events, ["install", "health"])
        self.assertEqual(result["status"], "waiting_device")
        requeue_mock.assert_called_once()
        release_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
