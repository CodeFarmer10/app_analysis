from __future__ import annotations

import logging
import time

from core.database import get_connection
from workers.dynamic_trace import trace_task


logger = logging.getLogger(__name__)
SCHEDULER_INTERVAL_SECONDS = 10


def _allocate_one_task_device_pair() -> tuple[str, str] | None:
    with get_connection() as conn:
        with conn.cursor() as cursor:
            try:
                conn.begin()
                cursor.execute(
                    """
                    SELECT id
                    FROM tasks
                    WHERE status = 'waiting_device'
                    ORDER BY created_at ASC
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
                    SELECT id
                    FROM devices
                    WHERE status = 'online'
                      AND current_task_id IS NULL
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
                    UPDATE tasks
                    SET status = 'dynamic_tracing',
                        device_id = %s,
                        error_message = NULL
                    WHERE id = %s
                    """,
                    (device["id"], task["id"]),
                )
                cursor.execute(
                    """
                    UPDATE devices
                    SET status = 'busy',
                        current_task_id = %s
                    WHERE id = %s
                    """,
                    (task["id"], device["id"]),
                )
                conn.commit()
                return task["id"], device["id"]
            except Exception:
                conn.rollback()
                raise


def _release_pair(task_id: str, device_id: str, reason: str) -> None:
    with get_connection() as conn:
        with conn.cursor() as cursor:
            try:
                conn.begin()
                cursor.execute(
                    """
                    UPDATE tasks
                    SET status = 'waiting_device',
                        device_id = NULL,
                        error_message = %s
                    WHERE id = %s
                    """,
                    (reason, task_id),
                )
                cursor.execute(
                    """
                    UPDATE devices
                    SET status = 'online',
                        current_task_id = NULL
                    WHERE id = %s
                    """,
                    (device_id,),
                )
                conn.commit()
            except Exception:
                conn.rollback()
                raise


def run_scheduler_forever() -> None:
    logger.info("device scheduler started, poll interval=%ss", SCHEDULER_INTERVAL_SECONDS)
    while True:
        try:
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
