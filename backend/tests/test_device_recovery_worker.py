from __future__ import annotations

import signal
import unittest
from concurrent.futures import Future
from pathlib import Path
from threading import Event
from unittest.mock import ANY, MagicMock, call, patch

from services.device_recovery_service import RecoveryStepError
from workers.device_recovery import (
    recover_claimed_device,
    run_recovery_forever,
    run_recovery_scan,
)


ROOT_DIR = Path(__file__).resolve().parents[2]


class DeviceRecoveryScanTest(unittest.TestCase):
    def setUp(self) -> None:
        self.device = {
            "id": "device-1",
            "name": "Recovery Device",
            "serial": "serial-1",
            "status": "quarantined",
            "current_task_id": None,
            "quarantine_reason": "device unavailable",
            "quarantined_at": None,
            "quarantine_task_id": "task-1",
            "quarantine_package_name": "com.example.badapp",
            "recovery_started_at": None,
            "recovery_attempt_id": None,
            "last_recovery_at": None,
            "recovery_error": None,
        }
        self.claimed_device = {
            **self.device,
            "status": "recovering",
            "recovery_attempt_id": "attempt-1",
        }

    @patch("workers.device_recovery.list_quarantined_devices", return_value=[])
    @patch("workers.device_recovery.expire_stale_recoveries", return_value=0)
    def test_scan_expires_stale_recoveries_before_listing_devices(
        self,
        expire_mock,
        list_mock,
    ) -> None:
        calls = []
        expire_mock.side_effect = lambda stale_seconds: calls.append(
            ("expire", stale_seconds)
        )
        list_mock.side_effect = lambda *, limit: calls.append(("list", limit)) or []

        run_recovery_scan(MagicMock(), set())

        self.assertEqual(calls, [("expire", 600), ("list", 2)])

    @patch("workers.device_recovery.list_quarantined_devices", return_value=[])
    @patch("workers.device_recovery.expire_stale_recoveries", return_value=0)
    def test_scan_lists_only_available_thread_slots(
        self,
        _expire_mock,
        list_mock,
    ) -> None:
        unfinished_future = Future()

        run_recovery_scan(MagicMock(), {unfinished_future})

        list_mock.assert_called_once_with(limit=1)

    @patch("workers.device_recovery.list_quarantined_devices")
    @patch("workers.device_recovery.claim_quarantined_device", return_value=None)
    @patch("workers.device_recovery.expire_stale_recoveries", return_value=0)
    def test_claim_failure_is_not_submitted(
        self,
        _expire_mock,
        _claim_mock,
        list_mock,
    ) -> None:
        list_mock.return_value = [self.device]
        executor = MagicMock()

        in_flight = run_recovery_scan(executor, set())

        self.assertEqual(in_flight, set())
        executor.submit.assert_not_called()

    @patch("workers.device_recovery.list_quarantined_devices")
    @patch("workers.device_recovery.claim_quarantined_device")
    @patch("workers.device_recovery.expire_stale_recoveries", return_value=0)
    def test_duplicate_scan_cannot_submit_recovering_device(
        self,
        _expire_mock,
        claim_mock,
        list_mock,
    ) -> None:
        list_mock.return_value = [self.device]
        claim_mock.side_effect = [self.claimed_device, None]
        executor = MagicMock()
        executor.submit.return_value = Future()

        run_recovery_scan(executor, set())
        run_recovery_scan(executor, set())

        self.assertEqual(executor.submit.call_count, 1)
        executor.submit.assert_called_once_with(
            recover_claimed_device,
            self.claimed_device,
        )

    @patch("workers.device_recovery.list_quarantined_devices")
    @patch("workers.device_recovery.expire_stale_recoveries", return_value=0)
    def test_scan_with_no_free_slot_does_not_list_devices(
        self,
        expire_mock,
        list_mock,
    ) -> None:
        in_flight = {Future(), Future()}

        self.assertEqual(run_recovery_scan(MagicMock(), in_flight), in_flight)

        expire_mock.assert_called_once_with(600)
        list_mock.assert_not_called()

    @patch("workers.device_recovery.list_quarantined_devices", return_value=[])
    @patch("workers.device_recovery.expire_stale_recoveries", return_value=0)
    def test_scan_reaps_completed_future_and_logs_its_exception(
        self,
        _expire_mock,
        _list_mock,
    ) -> None:
        failed_future = Future()
        failed_future.set_exception(RuntimeError("database unavailable"))

        with self.assertLogs("workers.device_recovery", level="ERROR") as logs:
            in_flight = run_recovery_scan(MagicMock(), {failed_future})

        self.assertEqual(in_flight, set())
        self.assertIn("database unavailable", "\n".join(logs.output))


class ClaimedDeviceRecoveryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.device = {
            "id": "device-1",
            "serial": "serial-1",
            "status": "recovering",
            "recovery_attempt_id": "attempt-1",
        }

    @patch("workers.device_recovery.complete_device_recovery", return_value=True)
    @patch("workers.device_recovery.perform_device_recovery")
    def test_recovery_success_finalizes_claimed_attempt(
        self,
        perform_mock,
        complete_mock,
    ) -> None:
        recover_claimed_device(self.device)

        perform_mock.assert_called_once_with(self.device)
        complete_mock.assert_called_once_with("device-1", "attempt-1")

    @patch("workers.device_recovery.fail_device_recovery", return_value=True)
    @patch("workers.device_recovery.perform_device_recovery")
    def test_recovery_failure_finalizes_claimed_attempt_with_step(
        self,
        perform_mock,
        fail_mock,
    ) -> None:
        perform_mock.side_effect = RecoveryStepError("wait_boot", "timeout")

        with self.assertLogs("workers.device_recovery", level="ERROR"):
            recover_claimed_device(self.device)

        fail_mock.assert_called_once_with("device-1", "attempt-1", "wait_boot: timeout")

    @patch("workers.device_recovery.fail_device_recovery", return_value=True)
    @patch("workers.device_recovery.perform_device_recovery")
    def test_unexpected_recovery_failure_finalizes_claimed_attempt(
        self,
        perform_mock,
        fail_mock,
    ) -> None:
        perform_mock.side_effect = RuntimeError("unexpected failure")

        with self.assertLogs("workers.device_recovery", level="ERROR"):
            recover_claimed_device(self.device)

        fail_mock.assert_called_once_with(
            "device-1",
            "attempt-1",
            "recovery: unexpected failure",
        )

    @patch("workers.device_recovery.fail_device_recovery")
    @patch("workers.device_recovery.complete_device_recovery", return_value=False)
    @patch("workers.device_recovery.perform_device_recovery")
    def test_stale_success_finalize_is_only_logged(
        self,
        _perform_mock,
        _complete_mock,
        fail_mock,
    ) -> None:
        with self.assertLogs("workers.device_recovery", level="WARNING") as logs:
            recover_claimed_device(self.device)

        fail_mock.assert_not_called()
        self.assertIn("stale recovery ownership", "\n".join(logs.output))

    @patch("workers.device_recovery.fail_device_recovery", return_value=False)
    @patch("workers.device_recovery.perform_device_recovery")
    def test_stale_failure_finalize_is_only_logged(
        self,
        perform_mock,
        _fail_mock,
    ) -> None:
        perform_mock.side_effect = RecoveryStepError("process", "fork failed")

        with self.assertLogs("workers.device_recovery", level="WARNING") as logs:
            recover_claimed_device(self.device)

        self.assertIn("stale recovery ownership", "\n".join(logs.output))


class DeviceRecoveryLoopTest(unittest.TestCase):
    def test_signal_during_handler_registration_is_not_cleared(self) -> None:
        shutdown_event = Event()

        def register_signal(signum, handler) -> None:
            if signum == signal.SIGTERM:
                handler(signum, None)

        def stop_after_unexpected_scan(_executor, _in_flight) -> set[Future]:
            shutdown_event.set()
            return set()

        with (
            patch("workers.device_recovery._shutdown_event", shutdown_event),
            patch("workers.device_recovery.signal.signal", side_effect=register_signal),
            patch("workers.device_recovery.ThreadPoolExecutor"),
            patch(
                "workers.device_recovery.run_recovery_scan",
                side_effect=stop_after_unexpected_scan,
            ) as scan_mock,
            patch("workers.device_recovery.time.monotonic", side_effect=[0.0, 0.0]),
        ):
            run_recovery_forever()

        scan_mock.assert_not_called()

    @patch("workers.device_recovery.signal.signal")
    @patch("workers.device_recovery.time.monotonic", side_effect=[100.0, 105.0])
    @patch("workers.device_recovery.run_recovery_scan", return_value=set())
    @patch("workers.device_recovery.ThreadPoolExecutor")
    @patch("workers.device_recovery._shutdown_event")
    def test_forever_loop_uses_one_executor_and_waits_until_next_scan(
        self,
        shutdown_event,
        executor_factory,
        scan_mock,
        _monotonic_mock,
        signal_mock,
    ) -> None:
        shutdown_event.is_set.side_effect = [False, True]
        executor = executor_factory.return_value.__enter__.return_value

        run_recovery_forever()

        executor_factory.assert_called_once_with(max_workers=2)
        scan_mock.assert_called_once_with(executor, set())
        shutdown_event.wait.assert_called_once_with(55.0)
        self.assertEqual(
            signal_mock.call_args_list,
            [call(signal.SIGTERM, ANY), call(signal.SIGINT, ANY)],
        )
        executor_factory.return_value.__exit__.assert_called_once()

    @patch("workers.device_recovery.signal.signal")
    @patch("workers.device_recovery.time.monotonic", side_effect=[0.0, 1.0, 60.0, 61.0])
    @patch("workers.device_recovery.run_recovery_scan")
    @patch("workers.device_recovery.ThreadPoolExecutor")
    @patch("workers.device_recovery._shutdown_event")
    def test_forever_loop_continues_after_scan_error(
        self,
        shutdown_event,
        executor_factory,
        scan_mock,
        _monotonic_mock,
        _signal_mock,
    ) -> None:
        shutdown_event.is_set.side_effect = [False, False, True]
        scan_mock.side_effect = [RuntimeError("database unavailable"), set()]

        with self.assertLogs("workers.device_recovery", level="ERROR"):
            run_recovery_forever()

        executor = executor_factory.return_value.__enter__.return_value
        self.assertEqual(
            scan_mock.call_args_list,
            [call(executor, set()), call(executor, set())],
        )
        self.assertEqual(shutdown_event.wait.call_args_list, [call(59.0), call(59.0)])


class DeviceRecoveryProcessScriptTest(unittest.TestCase):
    def test_start_script_launches_standalone_recovery_worker(self) -> None:
        start_script = (ROOT_DIR / "start.sh").read_text(encoding="utf-8")

        self.assertIn("start_process device_recovery", start_script)
        self.assertIn("-m workers.device_recovery", start_script)

    def test_stop_script_stops_recovery_before_scheduler(self) -> None:
        stop_script = (ROOT_DIR / "stop.sh").read_text(encoding="utf-8")

        self.assertIn("device_recovery", stop_script)
        self.assertLess(
            stop_script.index("device_recovery"),
            stop_script.index("scheduler"),
        )


if __name__ == "__main__":
    unittest.main()
