from __future__ import annotations

import logging
import time

from core.database import get_connection
from workers.dynamic_trace import trace_task


logger = logging.getLogger(__name__)
SCHEDULER_INTERVAL_SECONDS = 10
STALE_DYNAMIC_TRACE_MINUTES = 30
DEVICE_HEALTH_FRESHNESS_SECONDS = 120


def _recover_stale_dynamic_tracing_tasks() -> int:
    recovered_count = 0
    with get_connection() as conn:
        with conn.cursor() as cursor:
            try:
                conn.begin()
                cursor.execute(
                    """
                    SELECT id, device_id
                    FROM tasks
                    WHERE status = 'dynamic_tracing'
                      AND updated_at < DATE_SUB(NOW(), INTERVAL %s MINUTE)
                    FOR UPDATE
                    """,
                    (STALE_DYNAMIC_TRACE_MINUTES,),
                )
                rows = cursor.fetchall() or []
                for row in rows:
                    task_id = str(row["id"])
                    device_id = str(row["device_id"] or "").strip()
                    recovery_reason = (
                        f"动态任务超时回收：超过{STALE_DYNAMIC_TRACE_MINUTES}分钟未完成，系统自动重新排队"
                    )
                    quarantine_reason = f"{recovery_reason}，设备已隔离"

                    if not device_id:
                        updated_tasks = cursor.execute(
                            """
                            UPDATE tasks
                            SET status = 'waiting_device',
                                device_id = NULL,
                                error_message = %s
                            WHERE id = %s
                              AND status = 'dynamic_tracing'
                              AND device_id IS NULL
                            """,
                            (recovery_reason, task_id),
                        )
                        recovered_count += int(updated_tasks > 0)
                        continue

                    # Lock the device only while it still belongs to this stale task.
                    cursor.execute(
                        """
                        SELECT id
                        FROM devices
                        WHERE id = %s
                          AND status = 'busy'
                          AND current_task_id = %s
                        FOR UPDATE
                        """,
                        (device_id, task_id),
                    )
                    device = cursor.fetchone()
                    if not device:
                        logger.warning(
                            "requeue stale task because device ownership changed "
                            "task_id=%s device_id=%s",
                            task_id,
                            device_id,
                        )
                        updated_tasks = cursor.execute(
                            """
                            UPDATE tasks
                            SET status = 'waiting_device',
                                device_id = NULL,
                                error_message = %s
                            WHERE id = %s
                              AND status = 'dynamic_tracing'
                              AND device_id = %s
                            """,
                            (recovery_reason, task_id, device_id),
                        )
                        recovered_count += int(updated_tasks > 0)
                        continue

                    updated_tasks = cursor.execute(
                        """
                        UPDATE tasks
                        SET status = 'waiting_device',
                            device_id = NULL,
                            error_message = %s
                        WHERE id = %s
                          AND status = 'dynamic_tracing'
                          AND device_id = %s
                        """,
                        (recovery_reason, task_id, device_id),
                    )
                    if updated_tasks == 0:
                        logger.warning(
                            "skip stale device quarantine because task ownership changed "
                            "task_id=%s device_id=%s",
                            task_id,
                            device_id,
                        )
                        continue

                    updated_devices = cursor.execute(
                        """
                        UPDATE devices
                        SET status = 'quarantined',
                            current_task_id = NULL,
                            quarantine_reason = %s,
                            quarantined_at = NOW()
                        WHERE id = %s
                          AND status = 'busy'
                          AND current_task_id = %s
                        """,
                        (quarantine_reason, device_id, task_id),
                    )
                    if updated_devices == 0:
                        raise RuntimeError(
                            "stale task recovery lost device ownership after locking "
                            f"task_id={task_id} device_id={device_id}"
                        )
                    recovered_count += 1

                conn.commit()
            except Exception:
                conn.rollback()
                raise
    return recovered_count


def _allocate_one_task_device_pair() -> tuple[str, str] | None:
    with get_connection() as conn:
        with conn.cursor() as cursor:
            try:
                conn.begin()
                cursor.execute(
                    f"""
                    SELECT id
                    FROM devices
                    WHERE status = 'online'
                      AND current_task_id IS NULL
                      AND last_heartbeat_at >= DATE_SUB(NOW(), INTERVAL {DEVICE_HEALTH_FRESHNESS_SECONDS} SECOND)
                    ORDER BY created_at ASC
                    LIMIT 1
                    FOR UPDATE
                    """
                )
                device = cursor.fetchone()
                if not device:
                    conn.commit()
                    return None

                cursor.execute(
                    """
                    SELECT id
                    FROM tasks
                    WHERE status = 'waiting_device'
                    ORDER BY COALESCE(priority, 1000000) ASC, created_at ASC
                    LIMIT 1
                    FOR UPDATE
                    """
                )
                task = cursor.fetchone()
                if not task:
                    conn.commit()
                    return None

                cursor.execute(
                    """
                    UPDATE devices
                    SET status = 'busy',
                        current_task_id = %s
                    WHERE id = %s
                    """,
                    (task["id"], device["id"]),
                )
                cursor.execute(
                    """
                    UPDATE tasks
                    SET status = 'dynamic_tracing',
                        device_id = %s,
                        error_message = NULL
                    WHERE id = %s
                    """,
                    (device["id"], task["id"]),
                )
                conn.commit()
                return task["id"], device["id"]
            except Exception:
                conn.rollback()
                raise


def _release_pair(task_id: str, device_id: str, reason: str) -> bool:
    with get_connection() as conn:
        with conn.cursor() as cursor:
            try:
                conn.begin()
                cursor.execute(
                    """
                    SELECT status, device_id
                    FROM tasks
                    WHERE id = %s
                    FOR UPDATE
                    """,
                    (task_id,),
                )
                task = cursor.fetchone()
                if not task or str(task.get("status") or "") != "dynamic_tracing" or str(
                    task.get("device_id") or ""
                ) != device_id:
                    conn.rollback()
                    return False

                cursor.execute(
                    """
                    SELECT status, current_task_id
                    FROM devices
                    WHERE id = %s
                    FOR UPDATE
                    """,
                    (device_id,),
                )
                device = cursor.fetchone()
                device_status = str((device or {}).get("status") or "")
                if (
                    not device
                    or device_status not in {"busy", "quarantined"}
                    or str(device.get("current_task_id") or "") != task_id
                ):
                    conn.rollback()
                    return False

                updated_tasks = cursor.execute(
                    """
                    UPDATE tasks
                    SET status = 'waiting_device',
                        device_id = NULL,
                        error_message = %s
                    WHERE id = %s
                      AND status = 'dynamic_tracing'
                      AND device_id = %s
                    """,
                    (reason, task_id, device_id),
                )
                if device_status == "busy":
                    updated_devices = cursor.execute(
                        """
                        UPDATE devices
                        SET status = 'online',
                            current_task_id = NULL
                        WHERE id = %s
                          AND status = 'busy'
                          AND current_task_id = %s
                        """,
                        (device_id, task_id),
                    )
                else:
                    updated_devices = cursor.execute(
                        """
                        UPDATE devices
                        SET current_task_id = NULL
                        WHERE id = %s
                          AND status = 'quarantined'
                          AND current_task_id = %s
                        """,
                        (device_id, task_id),
                    )
                if updated_tasks != 1 or updated_devices != 1:
                    raise RuntimeError(
                        f"dispatch release ownership changed task_id={task_id} device_id={device_id}"
                    )
                conn.commit()
                return True
            except Exception:
                conn.rollback()
                raise


def run_scheduler_forever() -> None:
    logger.info("device scheduler started, poll interval=%ss", SCHEDULER_INTERVAL_SECONDS)
    while True:
        try:
            recovered = _recover_stale_dynamic_tracing_tasks()
            if recovered > 0:
                logger.warning("recovered stale dynamic task-device pairs count=%s", recovered)

            allocated = _allocate_one_task_device_pair()
            if not allocated:
                time.sleep(SCHEDULER_INTERVAL_SECONDS)
                continue

            task_id, device_id = allocated
            logger.info("task allocated task_id=%s device_id=%s", task_id, device_id)
            try:
                trace_task.delay(task_id, device_id)
            except Exception as exc:  # pragma: no cover - runtime dependent
                logger.exception(
                    "dispatch dynamic trace failed task_id=%s device_id=%s",
                    task_id,
                    device_id,
                )
                _release_pair(task_id, device_id, f"动态任务分发失败: {exc}")
        except Exception:  # pragma: no cover - runtime dependent
            logger.exception("scheduler loop error")
            time.sleep(SCHEDULER_INTERVAL_SECONDS)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )
    run_scheduler_forever()
