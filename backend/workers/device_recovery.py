from __future__ import annotations

import logging
import signal
import time
from concurrent.futures import CancelledError, Future, ThreadPoolExecutor
from threading import Event

from core.config import settings
from repositories.device_recovery_repo import (
    claim_quarantined_device,
    complete_device_recovery,
    expire_stale_recoveries,
    fail_device_recovery,
    list_quarantined_devices,
)
from services.device_recovery_service import RecoveryStepError, perform_device_recovery


logger = logging.getLogger(__name__)
_shutdown_event = Event()


def _log_stale_ownership(
    device_id: str,
    recovery_attempt_id: str,
    outcome: str,
) -> None:
    logger.warning(
        "skip %s recovery finalize because of stale recovery ownership "
        "device_id=%s recovery_attempt_id=%s",
        outcome,
        device_id,
        recovery_attempt_id,
    )


def recover_claimed_device(device: dict) -> None:
    device_id = str(device["id"])
    recovery_attempt_id = str(device["recovery_attempt_id"])

    try:
        perform_device_recovery(device)
    except RecoveryStepError as exc:
        error = str(exc)
        finalized = fail_device_recovery(device_id, recovery_attempt_id, error)
        if not finalized:
            _log_stale_ownership(device_id, recovery_attempt_id, "failed")
            return
        logger.error(
            "device recovery failed device_id=%s recovery_attempt_id=%s error=%s",
            device_id,
            recovery_attempt_id,
            error,
        )
        return
    except Exception as exc:
        error = f"recovery: {str(exc).strip() or exc.__class__.__name__}"
        finalized = fail_device_recovery(device_id, recovery_attempt_id, error)
        if not finalized:
            _log_stale_ownership(device_id, recovery_attempt_id, "failed")
            return
        logger.exception(
            "unexpected device recovery failure device_id=%s recovery_attempt_id=%s",
            device_id,
            recovery_attempt_id,
        )
        return

    finalized = complete_device_recovery(device_id, recovery_attempt_id)
    if not finalized:
        _log_stale_ownership(device_id, recovery_attempt_id, "successful")
        return
    logger.info(
        "device recovery completed device_id=%s recovery_attempt_id=%s",
        device_id,
        recovery_attempt_id,
    )


def _reap_completed_futures(in_flight: set[Future]) -> None:
    completed = {future for future in in_flight if future.done()}
    in_flight.difference_update(completed)
    for future in completed:
        try:
            error = future.exception()
        except CancelledError:
            logger.warning("device recovery future was cancelled")
            continue
        if error is not None:
            logger.error("device recovery future failed: %s", error)


def run_recovery_scan(
    executor: ThreadPoolExecutor,
    in_flight: set[Future],
) -> set[Future]:
    _reap_completed_futures(in_flight)

    expired = expire_stale_recoveries(settings.DEVICE_RECOVERY_STALE_SECONDS)
    if expired:
        logger.warning("expired stale device recoveries count=%s", expired)

    free_slots = settings.DEVICE_RECOVERY_MAX_WORKERS - len(in_flight)
    if free_slots <= 0:
        return in_flight

    candidates = list_quarantined_devices(limit=free_slots)
    for candidate in candidates:
        claimed = claim_quarantined_device(str(candidate["id"]))
        if claimed is None:
            continue
        future = executor.submit(recover_claimed_device, claimed)
        in_flight.add(future)
        logger.info(
            "submitted device recovery device_id=%s recovery_attempt_id=%s",
            claimed["id"],
            claimed["recovery_attempt_id"],
        )

    return in_flight


def _request_shutdown(signum: int, _frame: object) -> None:
    logger.info("device recovery shutdown requested signal=%s", signum)
    _shutdown_event.set()


def run_recovery_forever() -> None:
    _shutdown_event.clear()
    signal.signal(signal.SIGTERM, _request_shutdown)
    signal.signal(signal.SIGINT, _request_shutdown)

    in_flight: set[Future] = set()
    logger.info(
        "device recovery worker started scan_interval=%ss stale_after=%ss max_workers=%s",
        settings.DEVICE_RECOVERY_SCAN_INTERVAL_SECONDS,
        settings.DEVICE_RECOVERY_STALE_SECONDS,
        settings.DEVICE_RECOVERY_MAX_WORKERS,
    )
    with ThreadPoolExecutor(max_workers=settings.DEVICE_RECOVERY_MAX_WORKERS) as executor:
        while not _shutdown_event.is_set():
            scan_started_at = time.monotonic()
            try:
                in_flight = run_recovery_scan(executor, in_flight)
            except Exception:
                logger.exception("device recovery scan failed")

            elapsed = time.monotonic() - scan_started_at
            delay = max(
                0.0,
                settings.DEVICE_RECOVERY_SCAN_INTERVAL_SECONDS - elapsed,
            )
            _shutdown_event.wait(delay)

    logger.info("device recovery worker stopped")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )
    run_recovery_forever()
