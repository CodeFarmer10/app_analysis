from __future__ import annotations

from uuid import uuid4

from core.database import execute, fetch_all, fetch_one


def list_quarantined_devices(limit: int) -> list[dict]:
    """Return idle quarantined devices eligible for one recovery scan."""
    sql = """
        SELECT
            id,
            name,
            serial,
            android_version,
            model,
            resolution,
            status,
            current_task_id,
            last_heartbeat_at,
            quarantine_reason,
            quarantined_at,
            quarantine_task_id,
            quarantine_package_name,
            recovery_started_at,
            recovery_attempt_id,
            last_recovery_at,
            recovery_error,
            created_at
        FROM devices
        WHERE status = 'quarantined'
          AND current_task_id IS NULL
        ORDER BY quarantined_at ASC, id ASC
        LIMIT %s
    """
    return fetch_all(sql, (max(1, int(limit)),))


def claim_quarantined_device(device_id: str) -> dict | None:
    """Atomically move one idle quarantined device into recovery."""
    recovery_attempt_id = str(uuid4())
    sql = """
        UPDATE devices
        SET status = 'recovering',
            recovery_started_at = NOW(),
            recovery_attempt_id = %s,
            recovery_error = NULL
        WHERE id = %s
          AND status = 'quarantined'
          AND current_task_id IS NULL
    """
    rows, _ = execute(sql, (recovery_attempt_id, device_id))
    if rows != 1:
        return None

    return fetch_one(
        """
        SELECT
            id,
            name,
            serial,
            android_version,
            model,
            resolution,
            status,
            current_task_id,
            last_heartbeat_at,
            quarantine_reason,
            quarantined_at,
            quarantine_task_id,
            quarantine_package_name,
            recovery_started_at,
            recovery_attempt_id,
            last_recovery_at,
            recovery_error,
            created_at
        FROM devices
        WHERE id = %s
          AND status = 'recovering'
          AND current_task_id IS NULL
          AND recovery_attempt_id = %s
        LIMIT 1
        """,
        (device_id, recovery_attempt_id),
    )


def complete_device_recovery(device_id: str, recovery_attempt_id: str) -> bool:
    """Publish a fully verified recovery only while this worker owns the lifecycle."""
    sql = """
        UPDATE devices
        SET status = 'online',
            last_heartbeat_at = NOW(),
            quarantine_reason = NULL,
            quarantined_at = NULL,
            quarantine_task_id = NULL,
            quarantine_package_name = NULL,
            recovery_started_at = NULL,
            recovery_attempt_id = NULL,
            last_recovery_at = NOW(),
            recovery_error = NULL
        WHERE id = %s
          AND status = 'recovering'
          AND current_task_id IS NULL
          AND recovery_attempt_id = %s
    """
    rows, _ = execute(sql, (device_id, recovery_attempt_id))
    return rows == 1


def fail_device_recovery(device_id: str, recovery_attempt_id: str, error: str) -> bool:
    """End a claimed recovery in error without discarding isolation evidence."""
    sql = """
        UPDATE devices
        SET status = 'error',
            recovery_started_at = NULL,
            recovery_attempt_id = NULL,
            last_recovery_at = NOW(),
            recovery_error = %s
        WHERE id = %s
          AND status = 'recovering'
          AND current_task_id IS NULL
          AND recovery_attempt_id = %s
    """
    rows, _ = execute(sql, (str(error)[:2000], device_id, recovery_attempt_id))
    return rows == 1


def expire_stale_recoveries(stale_seconds: int) -> int:
    """Mark abandoned recovery executions as errors before the next scan."""
    timeout_seconds = max(1, int(stale_seconds))
    sql = f"""
        UPDATE devices
        SET status = 'error',
            recovery_started_at = NULL,
            recovery_attempt_id = NULL,
            last_recovery_at = NOW(),
            recovery_error = %s
        WHERE status = 'recovering'
          AND current_task_id IS NULL
          AND recovery_started_at < DATE_SUB(NOW(), INTERVAL {timeout_seconds} SECOND)
    """
    rows, _ = execute(
        sql,
        (f"recovery process exceeded {timeout_seconds} seconds",),
    )
    return rows
