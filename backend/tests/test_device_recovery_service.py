from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

from core.config import settings
from services.device_service import DeviceHealthResult
from services.device_recovery_service import (
    RecoveryStepError,
    cleanup_project_temp_files,
    package_exists,
    perform_device_recovery,
    recovery_timeout_budget_seconds,
    remove_residual_package_data,
    remove_residual_package,
    require_device_health,
    require_device_health_stable,
    require_process_command,
    run_adb,
    validate_health_apk,
    verify_apk_round_trip,
    wait_for_device_boot,
)


HEALTH_APK = (
    Path(__file__).resolve().parents[1]
    / "tools"
    / "device_health"
    / "DeviceHealthCheck.apk"
)
HEALTH_PACKAGE = "com.fraudanalysis.devicehealth"


class RecoveryConfigurationTest(unittest.TestCase):
    def test_recovery_defaults_match_worker_contract(self) -> None:
        self.assertEqual(settings.DEVICE_RECOVERY_SCAN_INTERVAL_SECONDS, 60)
        self.assertEqual(settings.DEVICE_RECOVERY_REBOOT_TIMEOUT_SECONDS, 180)
        self.assertEqual(settings.DEVICE_RECOVERY_INSTALL_TIMEOUT_SECONDS, 120)
        self.assertEqual(settings.DEVICE_RECOVERY_UNINSTALL_TIMEOUT_SECONDS, 60)
        self.assertEqual(settings.DEVICE_RECOVERY_DATA_CLEANUP_TIMEOUT_SECONDS, 300)
        self.assertEqual(settings.DEVICE_RECOVERY_STABLE_HEALTH_TIMEOUT_SECONDS, 120)
        self.assertEqual(settings.DEVICE_RECOVERY_STABLE_HEALTH_INTERVAL_SECONDS, 10)
        self.assertEqual(settings.DEVICE_RECOVERY_STALE_SECONDS, 1200)
        self.assertEqual(settings.DEVICE_RECOVERY_MAX_WORKERS, 2)
        self.assertEqual(settings.DEVICE_RECOVERY_APK_PATH, str(HEALTH_APK))
        self.assertEqual(settings.DEVICE_RECOVERY_APK_PACKAGE, HEALTH_PACKAGE)

    def test_worst_case_recovery_command_budget_fits_lifecycle_limits(self) -> None:
        expected_budget = (
            10  # reboot
            + 180  # boot wait, including network connect retries
            + (4 * 10)  # residual and health APK package checks
            + 10  # project-owned temporary file cleanup
            + (2 * 120)  # two stable health windows
            + 10  # process check
            + 60  # optional residual package uninstall
            + 300  # residual package data cleanup
            + 120  # health APK install
            + 60  # health APK uninstall
        )
        budget = recovery_timeout_budget_seconds()

        self.assertEqual(budget, expected_budget)
        self.assertLess(budget, settings.DEVICE_RECOVERY_STALE_SECONDS)
        self.assertLess(budget, 1200)


class RecoveryCommandTest(unittest.TestCase):
    @patch("services.device_recovery_service.subprocess.run")
    def test_run_adb_maps_nonzero_status_to_requested_step(self, command_mock) -> None:
        command_mock.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stdout="", stderr="device offline"
        )

        with self.assertRaises(RecoveryStepError) as raised:
            run_adb("serial-1", ["reboot"], step="reboot")

        self.assertEqual(raised.exception.step, "reboot")
        self.assertIn("device offline", raised.exception.detail)

    @patch("services.device_recovery_service.subprocess.run")
    def test_run_adb_maps_timeout_to_requested_step(self, command_mock) -> None:
        command_mock.side_effect = subprocess.TimeoutExpired(["adb"], 10)

        with self.assertRaises(RecoveryStepError) as raised:
            run_adb("serial-1", ["reboot"], step="reboot")

        self.assertEqual(raised.exception.step, "reboot")
        self.assertIn("timeout", raised.exception.detail.lower())

    @patch("services.device_recovery_service.subprocess.run")
    def test_run_adb_supports_host_level_connect_with_shared_mapping(
        self, command_mock
    ) -> None:
        command_mock.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="connected", stderr=""
        )

        output = run_adb(
            None,
            ["connect", "10.0.0.8:5555"],
            step="wait_boot",
            timeout_seconds=7,
        )

        self.assertEqual(output, "connected")
        self.assertEqual(
            command_mock.call_args.args[0],
            ["adb", "connect", "10.0.0.8:5555"],
        )
        self.assertEqual(command_mock.call_args.kwargs["timeout"], 7)

    @patch("services.device_recovery_service.run_adb")
    @patch("services.device_recovery_service.time.monotonic", return_value=0.0)
    def test_wait_for_boot_skips_connect_for_usb_and_requires_ready_checks(
        self, _monotonic_mock, command_mock
    ) -> None:
        command_mock.side_effect = ["device", "1", "__device_recovery_ok__"]

        wait_for_device_boot("serial-1", timeout_seconds=180)

        self.assertEqual(
            command_mock.call_args_list,
            [
                call(
                    "serial-1",
                    ["get-state"],
                    step="wait_boot",
                    timeout_seconds=180.0,
                ),
                call(
                    "serial-1",
                    ["shell", "getprop", "sys.boot_completed"],
                    step="wait_boot",
                    timeout_seconds=180.0,
                ),
                call(
                    "serial-1",
                    ["shell", "echo", "__device_recovery_ok__"],
                    step="wait_boot",
                    timeout_seconds=180.0,
                ),
            ],
        )

    @patch("services.device_recovery_service.time.sleep")
    @patch("services.device_recovery_service.run_adb")
    @patch("services.device_recovery_service.time.monotonic", return_value=0.0)
    def test_wait_for_boot_connects_network_serial_before_ready_checks(
        self,
        _monotonic_mock,
        command_mock,
        sleep_mock,
    ) -> None:
        command_mock.side_effect = [
            "connected",
            "device",
            "1",
            "__device_recovery_ok__",
        ]

        wait_for_device_boot("10.0.0.8:5555", timeout_seconds=180)

        self.assertEqual(
            command_mock.call_args_list,
            [
                call(
                    None,
                    ["connect", "10.0.0.8:5555"],
                    step="wait_boot",
                    timeout_seconds=180.0,
                ),
                call(
                    "10.0.0.8:5555",
                    ["get-state"],
                    step="wait_boot",
                    timeout_seconds=180.0,
                ),
                call(
                    "10.0.0.8:5555",
                    ["shell", "getprop", "sys.boot_completed"],
                    step="wait_boot",
                    timeout_seconds=180.0,
                ),
                call(
                    "10.0.0.8:5555",
                    ["shell", "echo", "__device_recovery_ok__"],
                    step="wait_boot",
                    timeout_seconds=180.0,
                ),
            ],
        )
        sleep_mock.assert_not_called()

    @patch("services.device_recovery_service.time.sleep")
    @patch("services.device_recovery_service.run_adb")
    @patch("services.device_recovery_service.time.monotonic", return_value=0.0)
    def test_wait_for_boot_retries_failed_network_connect_until_eventual_success(
        self,
        _monotonic_mock,
        command_mock,
        sleep_mock,
    ) -> None:
        command_mock.side_effect = [
            RecoveryStepError("wait_boot", "connection refused"),
            "connected",
            "device",
            "1",
            "__device_recovery_ok__",
        ]

        wait_for_device_boot("10.0.0.8:5555", timeout_seconds=180)

        self.assertEqual(
            command_mock.call_args_list,
            [
                call(
                    None,
                    ["connect", "10.0.0.8:5555"],
                    step="wait_boot",
                    timeout_seconds=180.0,
                ),
                call(
                    None,
                    ["connect", "10.0.0.8:5555"],
                    step="wait_boot",
                    timeout_seconds=180.0,
                ),
                call(
                    "10.0.0.8:5555",
                    ["get-state"],
                    step="wait_boot",
                    timeout_seconds=180.0,
                ),
                call(
                    "10.0.0.8:5555",
                    ["shell", "getprop", "sys.boot_completed"],
                    step="wait_boot",
                    timeout_seconds=180.0,
                ),
                call(
                    "10.0.0.8:5555",
                    ["shell", "echo", "__device_recovery_ok__"],
                    step="wait_boot",
                    timeout_seconds=180.0,
                ),
            ],
        )
        sleep_mock.assert_called_once_with(1)

    @patch("services.device_recovery_service.time.sleep")
    @patch("services.device_recovery_service.time.monotonic", side_effect=[0.0, 0.0, 180.0])
    @patch("services.device_recovery_service.run_adb", return_value="offline")
    def test_wait_for_boot_stops_at_180_second_timeout(
        self,
        command_mock,
        _monotonic_mock,
        sleep_mock,
    ) -> None:
        with self.assertRaises(RecoveryStepError) as raised:
            wait_for_device_boot("serial-1", timeout_seconds=180)

        self.assertEqual(raised.exception.step, "wait_boot")
        self.assertIn("180", raised.exception.detail)
        command_mock.assert_called_once_with(
            "serial-1",
            ["get-state"],
            step="wait_boot",
            timeout_seconds=180.0,
        )
        sleep_mock.assert_not_called()

    @patch("services.device_recovery_service.time.sleep")
    @patch("services.device_recovery_service.time.monotonic", side_effect=[0.0, 179.0, 180.0])
    @patch("services.device_recovery_service.run_adb", return_value="offline")
    def test_wait_for_boot_caps_each_command_to_remaining_deadline(
        self,
        command_mock,
        _monotonic_mock,
        sleep_mock,
    ) -> None:
        with self.assertRaises(RecoveryStepError):
            wait_for_device_boot("serial-1", timeout_seconds=180)

        command_mock.assert_called_once_with(
            "serial-1",
            ["get-state"],
            step="wait_boot",
            timeout_seconds=1.0,
        )
        sleep_mock.assert_not_called()


class RecoveryValidationTest(unittest.TestCase):
    def test_validate_health_apk_accepts_checked_in_artifact(self) -> None:
        validate_health_apk(HEALTH_APK, HEALTH_PACKAGE)

    def test_validate_health_apk_rejects_one_byte_mutation_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            mutated_apk = Path(temp_dir) / HEALTH_APK.name
            mutated_bytes = bytearray(HEALTH_APK.read_bytes())
            mutated_bytes[-1] ^= 0x01
            mutated_apk.write_bytes(mutated_bytes)

            with patch("services.device_recovery_service.APK") as apk_class_mock:
                with self.assertRaises(RecoveryStepError) as raised:
                    validate_health_apk(mutated_apk, HEALTH_PACKAGE)

        self.assertEqual(raised.exception.step, "verify_install")
        self.assertIn("SHA-256", raised.exception.detail)
        apk_class_mock.assert_not_called()

    def test_validate_health_apk_rejects_wrong_package_as_install_verification(self) -> None:
        with self.assertRaises(RecoveryStepError) as raised:
            validate_health_apk(HEALTH_APK, "com.example.wrong")

        self.assertEqual(raised.exception.step, "verify_install")

    @patch("services.device_recovery_service.APK")
    def test_validate_health_apk_rejects_v1_only_artifact(self, apk_class_mock) -> None:
        apk = apk_class_mock.return_value
        apk.get_package.return_value = HEALTH_PACKAGE
        apk.is_signed_v2.return_value = False
        apk.get_permissions.return_value = []
        apk.get_activities.return_value = []
        apk.get_services.return_value = []
        apk.get_receivers.return_value = []
        apk.get_providers.return_value = []
        apk.get_files.return_value = []

        with self.assertRaises(RecoveryStepError) as raised:
            validate_health_apk(HEALTH_APK, HEALTH_PACKAGE)

        self.assertEqual(raised.exception.step, "verify_install")
        self.assertIn("v2", raised.exception.detail)

    @patch("services.device_recovery_service.uninstall_apk", return_value=(True, "Success"))
    @patch("services.device_recovery_service.package_exists", side_effect=[True, False])
    def test_cleanup_removes_only_residual_quarantine_package(
        self,
        package_exists_mock,
        uninstall_mock,
    ) -> None:
        remove_residual_package("serial-1", "  com.example.residual  ")

        self.assertEqual(
            package_exists_mock.call_args_list,
            [
                call("serial-1", "com.example.residual", step="cleanup_app"),
                call("serial-1", "com.example.residual", step="cleanup_app"),
            ],
        )
        uninstall_mock.assert_called_once_with(
            "com.example.residual", device_id="serial-1", timeout=60
        )

    @patch("services.device_recovery_service.uninstall_apk")
    @patch("services.device_recovery_service.package_exists")
    def test_cleanup_does_nothing_without_quarantine_package(
        self,
        package_exists_mock,
        uninstall_mock,
    ) -> None:
        remove_residual_package("serial-1", None)

        package_exists_mock.assert_not_called()
        uninstall_mock.assert_not_called()

    @patch(
        "services.device_recovery_service.uninstall_apk",
        return_value=(False, "device offline"),
    )
    @patch("services.device_recovery_service.package_exists", return_value=True)
    def test_cleanup_failure_has_stable_step(self, _package_exists_mock, _uninstall_mock) -> None:
        with self.assertRaises(RecoveryStepError) as raised:
            remove_residual_package("serial-1", "com.example.residual")

        self.assertEqual(raised.exception.step, "cleanup_app")

    @patch("services.device_recovery_service.uninstall_apk", return_value=(True, "Success"))
    @patch("services.device_recovery_service.package_exists", side_effect=[True, True])
    def test_cleanup_rejects_package_still_present_after_uninstall(
        self,
        _package_exists_mock,
        _uninstall_mock,
    ) -> None:
        with self.assertRaises(RecoveryStepError) as raised:
            remove_residual_package("serial-1", "com.example.residual")

        self.assertEqual(raised.exception.step, "cleanup_app")
        self.assertIn("remains", raised.exception.detail)

    @patch("services.device_recovery_service.run_adb")
    def test_cleanup_removes_only_exact_residual_package_data_directory(
        self, command_mock
    ) -> None:
        remove_residual_package_data("serial-1", "  com.example.residual  ")

        command_mock.assert_called_once_with(
            "serial-1",
            [
                "shell",
                "su",
                "-c",
                "path=/data/media/0/Android/data/com.example.residual; "
                "if [ -e \"$path\" ]; then rm -rf -- \"$path\"; fi; "
                "test ! -e \"$path\"",
            ],
            step="cleanup_app_data",
            timeout_seconds=300,
        )

    @patch("services.device_recovery_service.run_adb")
    def test_cleanup_rejects_unsafe_package_name_without_running_adb(
        self, command_mock
    ) -> None:
        with self.assertRaises(RecoveryStepError) as raised:
            remove_residual_package_data("serial-1", "com.example;rm -rf /")

        self.assertEqual(raised.exception.step, "cleanup_app_data")
        self.assertIn("invalid package name", raised.exception.detail)
        command_mock.assert_not_called()

    @patch("services.device_recovery_service.run_adb")
    def test_cleanup_package_data_does_nothing_without_quarantine_package(
        self, command_mock
    ) -> None:
        remove_residual_package_data("serial-1", None)

        command_mock.assert_not_called()

    @patch("services.device_recovery_service.run_adb")
    def test_cleanup_project_temp_files_removes_only_owned_artifacts(
        self, command_mock
    ) -> None:
        cleanup_project_temp_files("serial-1")

        command_mock.assert_called_once_with(
            "serial-1",
            [
                "shell",
                "rm",
                "-f",
                "/sdcard/tmp.png",
                "/sdcard/capture.pcap",
                "/sdcard/capture-*.pcap",
            ],
            step="cleanup_temp",
        )

    @patch(
        "services.device_recovery_service.run_adb",
        side_effect=RecoveryStepError("cleanup_temp", "read-only file system"),
    )
    def test_cleanup_project_temp_files_propagates_cleanup_failure(
        self, _command_mock
    ) -> None:
        with self.assertRaises(RecoveryStepError) as raised:
            cleanup_project_temp_files("serial-1")

        self.assertEqual(raised.exception.step, "cleanup_temp")

    @patch(
        "services.device_recovery_service.run_adb",
        side_effect=RecoveryStepError("verify_uninstall", "adb exited with status 1"),
    )
    def test_package_exists_treats_empty_status_one_as_absent(self, command_mock) -> None:
        exists = package_exists(
            "serial-1",
            "com.fraudanalysis.devicehealth",
            step="verify_uninstall",
        )

        self.assertFalse(exists)
        command_mock.assert_called_once_with(
            "serial-1",
            ["shell", "cmd", "package", "path", "com.fraudanalysis.devicehealth"],
            step="verify_uninstall",
        )

    @patch("services.device_recovery_service.check_device_health")
    def test_storage_health_reuses_existing_five_gib_probe(self, health_mock) -> None:
        health_mock.return_value = DeviceHealthResult(
            "quarantined", "storage below 5 GiB (1 KiB available)", 1
        )

        with self.assertRaises(RecoveryStepError) as raised:
            require_device_health("serial-1")

        self.assertEqual(raised.exception.step, "storage")
        self.assertIn("5 GiB", raised.exception.detail)
        health_mock.assert_called_once_with("serial-1")

    @patch("services.device_recovery_service.time.sleep")
    @patch(
        "services.device_recovery_service.time.monotonic",
        side_effect=[0.0, 0.0, 10.0, 10.0, 20.0],
    )
    @patch("services.device_recovery_service.check_device_health")
    def test_stable_health_retries_transient_package_and_storage_failures(
        self,
        health_mock,
        _monotonic_mock,
        sleep_mock,
    ) -> None:
        health_mock.side_effect = [
            DeviceHealthResult("quarantined", "package manager check failed", None),
            DeviceHealthResult("quarantined", "storage check failed", None),
            DeviceHealthResult("healthy", None, 221230776),
        ]

        require_device_health_stable(
            "serial-1",
            timeout_seconds=60,
            interval_seconds=10,
        )

        self.assertEqual(health_mock.call_count, 3)
        self.assertEqual(sleep_mock.call_args_list, [call(10), call(10)])

    @patch("services.device_recovery_service.run_adb")
    def test_process_check_rejects_fork_failure_without_counting_processes(
        self, command_mock
    ) -> None:
        command_mock.return_value = (
            "shell: fork failed: Resource temporarily unavailable"
        )

        with self.assertRaises(RecoveryStepError) as raised:
            require_process_command("serial-1")

        self.assertEqual(raised.exception.step, "process")

    @patch("services.device_recovery_service.run_adb", return_value="")
    def test_process_check_rejects_empty_ps_output(self, _command_mock) -> None:
        with self.assertRaises(RecoveryStepError) as raised:
            require_process_command("serial-1")

        self.assertEqual(raised.exception.step, "process")

    @patch("services.device_recovery_service.run_adb", return_value="PID NAME\n1 init")
    def test_process_check_accepts_nonempty_output_without_count_threshold(
        self, command_mock
    ) -> None:
        require_process_command("serial-1")

        command_mock.assert_called_once_with(
            "serial-1", ["shell", "ps", "-A"], step="process"
        )


class RecoveryApkRoundTripTest(unittest.TestCase):
    @patch("services.device_recovery_service.uninstall_apk", return_value=(True, "Success"))
    @patch("services.device_recovery_service.install_apk", return_value=(True, "Success"))
    @patch("services.device_recovery_service.run_adb")
    def test_health_apk_round_trip_checks_cmd_package_transitions(
        self,
        command_mock,
        install_mock,
        uninstall_mock,
    ) -> None:
        command_mock.side_effect = ["package:/data/app/base.apk", ""]

        verify_apk_round_trip("serial-1", HEALTH_APK, HEALTH_PACKAGE)

        install_mock.assert_called_once_with(
            str(HEALTH_APK),
            device_id="serial-1",
            replace_existing=True,
            timeout=120,
        )
        uninstall_mock.assert_called_once_with(
            HEALTH_PACKAGE,
            device_id="serial-1",
            timeout=60,
        )
        self.assertEqual(
            command_mock.call_args_list,
            [
                call(
                    "serial-1",
                    ["shell", "cmd", "package", "path", HEALTH_PACKAGE],
                    step="verify_install",
                ),
                call(
                    "serial-1",
                    ["shell", "cmd", "package", "path", HEALTH_PACKAGE],
                    step="verify_uninstall",
                ),
            ],
        )

    @patch(
        "services.device_recovery_service.install_apk",
        return_value=(False, "INSTALL_FAILED"),
    )
    def test_install_failure_has_stable_step(self, _install_mock) -> None:
        with self.assertRaises(RecoveryStepError) as raised:
            verify_apk_round_trip("serial-1", HEALTH_APK, HEALTH_PACKAGE)

        self.assertEqual(raised.exception.step, "verify_install")

    @patch("services.device_recovery_service.package_exists", return_value=False)
    @patch("services.device_recovery_service.install_apk", return_value=(True, "Success"))
    def test_package_absent_after_install_has_stable_step(
        self, _install_mock, _package_exists_mock
    ) -> None:
        with self.assertRaises(RecoveryStepError) as raised:
            verify_apk_round_trip("serial-1", HEALTH_APK, HEALTH_PACKAGE)

        self.assertEqual(raised.exception.step, "verify_install")

    @patch(
        "services.device_recovery_service.uninstall_apk",
        return_value=(False, "DELETE_FAILED"),
    )
    @patch("services.device_recovery_service.package_exists", return_value=True)
    @patch("services.device_recovery_service.install_apk", return_value=(True, "Success"))
    def test_uninstall_failure_has_stable_step(
        self,
        _install_mock,
        _package_exists_mock,
        _uninstall_mock,
    ) -> None:
        with self.assertRaises(RecoveryStepError) as raised:
            verify_apk_round_trip("serial-1", HEALTH_APK, HEALTH_PACKAGE)

        self.assertEqual(raised.exception.step, "verify_uninstall")

    @patch("services.device_recovery_service.uninstall_apk", return_value=(True, "Success"))
    @patch("services.device_recovery_service.package_exists", side_effect=[True, True])
    @patch("services.device_recovery_service.install_apk", return_value=(True, "Success"))
    def test_package_present_after_uninstall_has_stable_step(
        self,
        _install_mock,
        _package_exists_mock,
        _uninstall_mock,
    ) -> None:
        with self.assertRaises(RecoveryStepError) as raised:
            verify_apk_round_trip("serial-1", HEALTH_APK, HEALTH_PACKAGE)

        self.assertEqual(raised.exception.step, "verify_uninstall")


class PerformDeviceRecoveryTest(unittest.TestCase):
    def test_recovery_executes_only_the_approved_order(self) -> None:
        parent = MagicMock()
        patches = (
            patch("services.device_recovery_service.validate_health_apk"),
            patch("services.device_recovery_service.run_adb"),
            patch("services.device_recovery_service.wait_for_device_boot"),
            patch("services.device_recovery_service.remove_residual_package"),
            patch("services.device_recovery_service.remove_residual_package_data"),
            patch("services.device_recovery_service.cleanup_project_temp_files"),
            patch("services.device_recovery_service.require_device_health_stable"),
            patch("services.device_recovery_service.require_process_command"),
            patch("services.device_recovery_service.verify_apk_round_trip"),
            patch.object(settings, "DEVICE_RECOVERY_APK_PATH", str(HEALTH_APK)),
            patch.object(settings, "DEVICE_RECOVERY_APK_PACKAGE", HEALTH_PACKAGE),
            patch.object(settings, "DEVICE_RECOVERY_REBOOT_TIMEOUT_SECONDS", 180),
        )

        with patches[0] as validate_mock, patches[1] as run_mock, patches[2] as wait_mock, \
            patches[3] as cleanup_mock, patches[4] as data_cleanup_mock, \
            patches[5] as temp_cleanup_mock, patches[6] as health_mock, \
            patches[7] as process_mock, patches[8] as round_trip_mock, \
            patches[9], patches[10], patches[11]:
            parent.attach_mock(validate_mock, "validate")
            parent.attach_mock(run_mock, "run")
            parent.attach_mock(wait_mock, "wait")
            parent.attach_mock(cleanup_mock, "cleanup")
            parent.attach_mock(data_cleanup_mock, "cleanup_data")
            parent.attach_mock(temp_cleanup_mock, "cleanup_temp")
            parent.attach_mock(health_mock, "health")
            parent.attach_mock(process_mock, "process")
            parent.attach_mock(round_trip_mock, "round_trip")

            perform_device_recovery(
                {
                    "serial": "serial-1",
                    "quarantine_package_name": "com.example.residual",
                }
            )

        self.assertEqual(
            parent.mock_calls,
            [
                call.validate(HEALTH_APK, HEALTH_PACKAGE),
                call.run("serial-1", ["reboot"]),
                call.wait("serial-1", timeout_seconds=180),
                call.cleanup("serial-1", "com.example.residual"),
                call.cleanup_data("serial-1", "com.example.residual"),
                call.cleanup_temp("serial-1"),
                call.health("serial-1"),
                call.process("serial-1"),
                call.round_trip("serial-1", HEALTH_APK, HEALTH_PACKAGE),
                call.health("serial-1"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
