from __future__ import annotations

import signal
import subprocess
import tempfile
import unittest
from concurrent.futures import Future
from pathlib import Path
from threading import Event
from unittest.mock import ANY, MagicMock, call, patch

from core.config import settings
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

    @patch("workers.device_recovery.list_quarantined_devices", return_value=[])
    @patch("workers.device_recovery.expire_stale_recoveries", return_value=0)
    def test_scan_caps_high_configured_worker_count(
        self,
        _expire_mock,
        list_mock,
    ) -> None:
        with patch.object(settings, "DEVICE_RECOVERY_MAX_WORKERS", 5):
            run_recovery_scan(MagicMock(), {Future()})

        list_mock.assert_called_once_with(limit=1)

    @patch("workers.device_recovery.list_quarantined_devices", return_value=[])
    @patch("workers.device_recovery.expire_stale_recoveries", return_value=0)
    def test_scan_raises_invalid_low_worker_count_to_one(
        self,
        _expire_mock,
        list_mock,
    ) -> None:
        with patch.object(settings, "DEVICE_RECOVERY_MAX_WORKERS", 0):
            run_recovery_scan(MagicMock(), set())

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
    @patch("workers.device_recovery.complete_device_recovery", return_value=True)
    @patch("workers.device_recovery.perform_device_recovery")
    def test_sigterm_stops_new_scans_and_waits_for_in_flight_finalize(
        self,
        perform_mock,
        complete_mock,
    ) -> None:
        shutdown_event = Event()
        recovery_started = Event()
        release_recovery = Event()
        signal_handlers = {}
        claimed_device = {
            "id": "device-1",
            "serial": "serial-1",
            "status": "recovering",
            "recovery_attempt_id": "attempt-1",
        }

        def register_signal(signum, handler) -> None:
            signal_handlers[signum] = handler

        def perform_recovery(_device) -> None:
            recovery_started.set()
            self.assertTrue(release_recovery.wait(timeout=1))

        def submit_then_stop(executor, _in_flight) -> set[Future]:
            future = executor.submit(recover_claimed_device, claimed_device)
            self.assertTrue(recovery_started.wait(timeout=1))
            signal_handlers[signal.SIGTERM](signal.SIGTERM, None)
            release_recovery.set()
            return {future}

        perform_mock.side_effect = perform_recovery
        with (
            patch("workers.device_recovery._shutdown_event", shutdown_event),
            patch("workers.device_recovery.signal.signal", side_effect=register_signal),
            patch(
                "workers.device_recovery.run_recovery_scan",
                side_effect=submit_then_stop,
            ) as scan_mock,
        ):
            run_recovery_forever()

        scan_mock.assert_called_once()
        perform_mock.assert_called_once_with(claimed_device)
        complete_mock.assert_called_once_with("device-1", "attempt-1")

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
    @patch("workers.device_recovery.time.monotonic", side_effect=[100.0, 100.0])
    @patch("workers.device_recovery.run_recovery_scan", return_value=set())
    @patch("workers.device_recovery.ThreadPoolExecutor")
    @patch("workers.device_recovery._shutdown_event")
    def test_forever_loop_caps_high_configured_executor_count(
        self,
        shutdown_event,
        executor_factory,
        _scan_mock,
        _monotonic_mock,
        _signal_mock,
    ) -> None:
        shutdown_event.is_set.side_effect = [False, True]

        with patch.object(settings, "DEVICE_RECOVERY_MAX_WORKERS", 5):
            run_recovery_forever()

        executor_factory.assert_called_once_with(max_workers=2)

    @patch("workers.device_recovery.perform_device_recovery")
    @patch("workers.device_recovery.list_quarantined_devices", return_value=[])
    @patch("workers.device_recovery.expire_stale_recoveries", return_value=0)
    @patch("workers.device_recovery.signal.signal")
    @patch("workers.device_recovery.time.monotonic", side_effect=[100.0, 100.0])
    @patch("workers.device_recovery.ThreadPoolExecutor")
    @patch("workers.device_recovery._shutdown_event")
    def test_one_cycle_empty_candidate_scan_never_submits_or_calls_adb(
        self,
        shutdown_event,
        executor_factory,
        _monotonic_mock,
        _signal_mock,
        expire_mock,
        list_mock,
        perform_mock,
    ) -> None:
        shutdown_event.is_set.side_effect = [False, True]
        executor = executor_factory.return_value.__enter__.return_value

        run_recovery_forever()

        expire_mock.assert_called_once_with(600)
        list_mock.assert_called_once_with(limit=2)
        executor.submit.assert_not_called()
        perform_mock.assert_not_called()

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
    def _run_stop_service(self, service: str) -> list[str]:
        stop_script = (ROOT_DIR / "stop.sh").read_text(encoding="utf-8")
        entrypoint = 'main "$@"'
        self.assertTrue(stop_script.rstrip().endswith(entrypoint))

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_path = Path(tmp_dir)
            source_path = tmp_path / "stop-functions.sh"
            source_path.write_text(
                stop_script.rsplit(entrypoint, maxsplit=1)[0],
                encoding="utf-8",
            )
            run_dir = tmp_path / "run_logs"
            run_dir.mkdir()
            (run_dir / f"{service}.pid").write_text("4242", encoding="utf-8")
            trace_path = tmp_path / "trace.log"
            shell = r'''
source "$1"
RUN_DIR="$2"
TRACE_PATH="$3"

kill() {
  case "${1:-}" in
    -0) return 0 ;;
    -9) printf 'force\n' >>"${TRACE_PATH}"; return 0 ;;
    *) return 0 ;;
  esac
}

sleep() {
  printf 'sleep:%s\n' "$1" >>"${TRACE_PATH}"
}

stop_service "$4"
'''
            subprocess.run(
                [
                    "bash",
                    "-c",
                    shell,
                    "stop-test",
                    str(source_path),
                    str(run_dir),
                    str(trace_path),
                    service,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            return trace_path.read_text(encoding="utf-8").splitlines()

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

    def test_stop_script_gives_recovery_stale_bound_grace(self) -> None:
        trace = self._run_stop_service("device_recovery")

        self.assertEqual(trace.count("sleep:0.5"), 1200)
        self.assertEqual(trace.count("force"), 1)

    def test_stop_script_keeps_existing_grace_for_other_services(self) -> None:
        trace = self._run_stop_service("scheduler")

        self.assertEqual(trace.count("sleep:0.5"), 20)
        self.assertEqual(trace.count("force"), 1)


if __name__ == "__main__":
    unittest.main()
