from __future__ import annotations

import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import ANY, MagicMock, patch

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
                "task-1", "device-1", "device offline", "  com.example.badapp  "
            )
        )

        sql = "\n".join(call.args[0] for call in cursor.execute.call_args_list)
        self.assertIn("FOR UPDATE", sql)
        self.assertIn("SET status = 'waiting_device'", sql)
        self.assertIn("device_id = NULL", sql)
        self.assertIn("SET status = 'quarantined'", sql)
        self.assertIn("current_task_id = NULL", sql)
        self.assertIn("quarantined_at = NOW()", sql)
        device_update = next(
            call for call in cursor.execute.call_args_list if "UPDATE devices" in call.args[0]
        )
        self.assertIn("quarantine_task_id = %s", device_update.args[0])
        self.assertIn("quarantine_package_name = %s", device_update.args[0])
        self.assertEqual(
            device_update.args[1],
            ("device offline", "task-1", "com.example.badapp", "device-1", "task-1"),
        )
        connection.commit.assert_called_once()

    @patch("workers.dynamic_trace.execute", return_value=(1, 0))
    def test_owned_device_quarantine_records_task_and_normalized_package(
        self,
        execute_mock,
    ) -> None:
        self.assertTrue(
            dynamic_trace._quarantine_owned_device(
                "task-1", "device-1", "device offline", "  com.example.badapp  "
            )
        )

        sql, params = execute_mock.call_args.args
        self.assertIn("quarantine_task_id = %s", sql)
        self.assertIn("quarantine_package_name = %s", sql)
        self.assertEqual(
            params,
            ("device offline", "task-1", "com.example.badapp", "device-1", "task-1"),
        )

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
            "Plan Model error: resource temporarily unavailable",
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

    def test_runtime_adb_classifier_requires_trusted_context(self) -> None:
        positive_messages = (
            "adb: transport is closing",
            "adb: transport endpoint is not connected",
            "adb: transport error",
            "adb: connection reset by peer",
            "adb: protocol fault (no status)",
            "adb shell timeout after 30s",
            "Phone Agent error: No output from dumpsys window",
            "shell: fork failed: Resource temporarily unavailable",
        )
        negative_messages = (
            "Plan Model error: resource temporarily unavailable",
            "Plan Model error: No output from dumpsys window",
            "MinIO error: resource temporarily unavailable",
            "host worker: fork failed: resource temporarily unavailable",
            "Phone Agent error: Resource temporarily unavailable",
            "Phone Agent error: fork failed: resource temporarily unavailable",
            "No output from dumpsys window",
        )

        for message in positive_messages:
            with self.subTest(message=message):
                self.assertTrue(dynamic_trace.is_runtime_adb_error_message(message))
        for message in negative_messages:
            with self.subTest(message=message):
                self.assertFalse(dynamic_trace.is_runtime_adb_error_message(message))

    def test_plan_model_failed_record_does_not_raise_device_error(self) -> None:
        dynamic_trace._raise_if_operation_device_failure(
            [
                {
                    "successed": False,
                    "message": "Plan Model error: resource temporarily unavailable",
                }
            ]
        )

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
                mocks["requeue"].assert_called_once_with(
                    "task-1", "device-1", ANY, "com.example.app"
                )
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
        quarantine_mock.assert_called_once_with(
            "task-1", "device-1", ANY, "com.example.app"
        )
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
        quarantine_mock.assert_called_once_with(
            "task-1", "device-1", ANY, "com.example.app"
        )

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

    def test_runtime_agent_adb_exception_requeues_device(self) -> None:
        messages = (
            "Phone Agent error: error: device offline",
            "Phone Agent error: shell: fork failed: Resource temporarily unavailable",
            "Phone Agent error: adb: device not found",
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

                self.assertEqual(result["status"], "waiting_device")
                mocks["requeue"].assert_called_once_with(
                    "task-1", "device-1", ANY, "com.example.app"
                )
                mocks["mark_failed"].assert_not_called()

    def test_failed_phone_agent_device_record_requeues_before_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, ExitStack() as stack:
            result_dir = Path(temp_dir) / "result"
            result_dir.mkdir()
            mocks = self._patch_trace_until_agent(stack, result_dir)
            mocks["install"].return_value = (True, "Success")
            mocks["run"].return_value = "done"
            operation_results = [
                {
                    "step_num": 1,
                    "step": "打开应用",
                    "successed": False,
                    "message": "Phone Agent error: adb: failed to run abb_exec. Error: closed",
                }
            ]
            stack.enter_context(
                patch("workers.dynamic_trace._load_operation_results", return_value=operation_results)
            )
            parse_mock = stack.enter_context(patch("workers.dynamic_trace._parse_operation_results"))
            persist_mock = stack.enter_context(patch("workers.dynamic_trace._persist_trace_results"))

            result = dynamic_trace.trace_task("task-1", "device-1")

            self.assertEqual(result["status"], "waiting_device")
            mocks["requeue"].assert_called_once()
            parse_mock.assert_not_called()
            persist_mock.assert_not_called()

    def test_failed_phone_agent_dumpsys_record_requeues(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, ExitStack() as stack:
            result_dir = Path(temp_dir) / "result"
            result_dir.mkdir()
            mocks = self._patch_trace_until_agent(stack, result_dir)
            mocks["install"].return_value = (True, "Success")
            mocks["run"].return_value = "done"
            stack.enter_context(
                patch(
                    "workers.dynamic_trace._load_operation_results",
                    return_value=[
                        {
                            "step_num": 1,
                            "step": "打开应用",
                            "successed": False,
                            "message": "Phone Agent error: No output from dumpsys window",
                        }
                    ],
                )
            )
            persist_mock = stack.enter_context(
                patch("workers.dynamic_trace._persist_trace_results")
            )

            result = dynamic_trace.trace_task("task-1", "device-1")

            self.assertEqual(result["status"], "waiting_device")
            mocks["requeue"].assert_called_once()
            persist_mock.assert_not_called()

    def test_overlapping_attempts_use_distinct_local_and_object_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, patch(
            "workers.dynamic_trace._resolve_result_root",
            return_value=Path(temp_dir),
        ):
            first_dir = dynamic_trace._prepare_result_dir("task-1", "attempt-1")
            marker = first_dir / "run.log"
            marker.write_text("first", encoding="utf-8")
            second_dir = dynamic_trace._prepare_result_dir("task-1", "attempt-2")

            self.assertNotEqual(first_dir, second_dir)
            self.assertTrue(marker.exists())
            self.assertEqual(first_dir, Path(temp_dir) / "task-1" / "attempt-1")
            self.assertEqual(second_dir, Path(temp_dir) / "task-1" / "attempt-2")

            first_namespace = dynamic_trace._attempt_object_namespace("task-1", "attempt-1")
            second_namespace = dynamic_trace._attempt_object_namespace("task-1", "attempt-2")
            with patch(
                "workers.dynamic_trace.storage_service.upload_task_file",
                side_effect=["url-1", "url-2"],
            ) as upload_mock:
                dynamic_trace._upload_result_file(first_namespace, "log", marker)
                second_log = second_dir / "run.log"
                second_log.write_text("second", encoding="utf-8")
                dynamic_trace._upload_result_file(second_namespace, "log", second_log)

            uploaded_namespaces = [call.args[0] for call in upload_mock.call_args_list]
            self.assertEqual(
                uploaded_namespaces,
                ["task-1/attempts/attempt-1", "task-1/attempts/attempt-2"],
            )

    @patch("workers.dynamic_trace.update_static_result_fields")
    @patch(
        "workers.dynamic_trace.unpack_to_archive",
        side_effect=RuntimeError("adb: error: device offline"),
    )
    @patch("workers.dynamic_trace.get_static_result", return_value={"is_packed": True})
    def test_unpack_adb_failure_is_promoted_to_device_error(
        self,
        _static_mock,
        _unpack_mock,
        update_static_mock,
    ) -> None:
        with self.assertRaises(dynamic_trace.DeviceUnavailableError):
            dynamic_trace._maybe_unpack_packed_app(
                task_id="task-1",
                object_namespace="task-1/attempts/attempt-1",
                package_name="com.example.app",
                adb_device_id="serial-1",
                result_dir=Path("/tmp/attempt-1"),
            )

        update_static_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
