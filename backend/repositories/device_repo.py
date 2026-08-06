from __future__ import annotations

from typing import Any

from core.database import execute, fetch_all, fetch_one


def create_device(data: dict[str, Any]) -> str:
    sql = """
        INSERT INTO devices (
            id,
            name,
            serial,
            android_version,
            model,
            resolution,
            status,
            last_heartbeat_at,
            quarantine_reason,
            quarantined_at,
            quarantine_task_id,
            quarantine_package_name,
            recovery_started_at,
            recovery_attempt_id,
            last_recovery_at,
            recovery_error
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    execute(
        sql,
        (
            data["id"],
            data.get("name"),
            data["serial"],
            data.get("android_version"),
            data.get("model"),
            data.get("resolution"),
            data.get("status", "online"),
            data.get("last_heartbeat_at"),
            data.get("quarantine_reason"),
            data.get("quarantined_at"),
            data.get("quarantine_task_id"),
            data.get("quarantine_package_name"),
            data.get("recovery_started_at"),
            data.get("recovery_attempt_id"),
            data.get("last_recovery_at"),
            data.get("recovery_error"),
        ),
    )
    return data["id"]


def get_device_by_id(device_id: str) -> dict | None:
    sql = """
        SELECT
            d.id,
            d.name,
            d.serial,
            d.android_version,
            d.model,
            d.resolution,
            d.status,
            d.current_task_id,
            d.last_heartbeat_at,
            d.quarantine_reason,
            d.quarantined_at,
            d.quarantine_task_id,
            d.quarantine_package_name,
            d.recovery_started_at,
            d.recovery_attempt_id,
            d.last_recovery_at,
            d.recovery_error,
            d.created_at,
            t.status AS current_task_status,
            COALESCE(tc.analyzed_app_count_1d, 0) AS analyzed_app_count_1d
        FROM devices d
        LEFT JOIN tasks t ON t.id = d.current_task_id
        LEFT JOIN (
            SELECT
                device_id,
                COUNT(*) AS analyzed_app_count_1d
            FROM tasks
            WHERE device_id IS NOT NULL
              AND status = 'completed'
              AND updated_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)
            GROUP BY device_id
        ) tc ON tc.device_id = d.id
        WHERE d.id = %s
        LIMIT 1
    """
    return fetch_one(sql, (device_id,))


def get_device_by_serial(serial: str) -> dict | None:
    sql = """
        SELECT
            d.id,
            d.name,
            d.serial,
            d.android_version,
            d.model,
            d.resolution,
            d.status,
            d.current_task_id,
            d.last_heartbeat_at,
            d.quarantine_reason,
            d.quarantined_at,
            d.quarantine_task_id,
            d.quarantine_package_name,
            d.recovery_started_at,
            d.recovery_attempt_id,
            d.last_recovery_at,
            d.recovery_error,
            d.created_at,
            t.status AS current_task_status,
            COALESCE(tc.analyzed_app_count_1d, 0) AS analyzed_app_count_1d
        FROM devices d
        LEFT JOIN tasks t ON t.id = d.current_task_id
        LEFT JOIN (
            SELECT
                device_id,
                COUNT(*) AS analyzed_app_count_1d
            FROM tasks
            WHERE device_id IS NOT NULL
              AND status = 'completed'
              AND updated_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)
            GROUP BY device_id
        ) tc ON tc.device_id = d.id
        WHERE d.serial = %s
        LIMIT 1
    """
    return fetch_one(sql, (serial,))


def list_devices() -> list[dict]:
    sql = """
        SELECT
            d.id,
            d.name,
            d.serial,
            d.android_version,
            d.model,
            d.resolution,
            d.status,
            d.current_task_id,
            d.last_heartbeat_at,
            d.quarantine_reason,
            d.quarantined_at,
            d.quarantine_task_id,
            d.quarantine_package_name,
            d.recovery_started_at,
            d.recovery_attempt_id,
            d.last_recovery_at,
            d.recovery_error,
            d.created_at,
            t.status AS current_task_status,
            COALESCE(tc.analyzed_app_count_1d, 0) AS analyzed_app_count_1d
        FROM devices d
        LEFT JOIN tasks t ON t.id = d.current_task_id
        LEFT JOIN (
            SELECT
                device_id,
                COUNT(*) AS analyzed_app_count_1d
            FROM tasks
            WHERE device_id IS NOT NULL
              AND status = 'completed'
              AND updated_at >= DATE_SUB(NOW(), INTERVAL 1 DAY)
            GROUP BY device_id
        ) tc ON tc.device_id = d.id
        ORDER BY d.created_at DESC
    """
    return fetch_all(sql)


def update_device(device_id: str, fields: dict[str, Any]) -> int:
    if not fields:
        return 0

    set_fragments: list[str] = []
    values: list[Any] = []
    for key, value in fields.items():
        set_fragments.append(f"{key} = %s")
        values.append(value)

    sql = f"""
        UPDATE devices
        SET {", ".join(set_fragments)}
        WHERE id = %s
    """
    values.append(device_id)
    rows, _ = execute(sql, tuple(values))
    return rows


def update_idle_device_snapshot(
    device_id: str,
    expected_status: str,
    fields: dict[str, Any],
) -> int:
    """Update an idle device only if its status/ownership still match the probe snapshot."""
    if not fields:
        return 0

    set_fragments: list[str] = []
    values: list[Any] = []
    for key, value in fields.items():
        set_fragments.append(f"{key} = %s")
        values.append(value)

    sql = f"""
        UPDATE devices
        SET {", ".join(set_fragments)}
        WHERE id = %s
          AND status = %s
          AND current_task_id IS NULL
    """
    values.extend((device_id, expected_status))
    rows, _ = execute(sql, tuple(values))
    return rows


def delete_device(device_id: str) -> int:
    sql = "DELETE FROM devices WHERE id = %s"
    rows, _ = execute(sql, (device_id,))
    return rows


def get_available_devices() -> list[dict]:
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
        WHERE status = 'online'
          AND current_task_id IS NULL
        ORDER BY created_at ASC
    """
    return fetch_all(sql)


def count_in_progress_tasks(device_id: str) -> int:
    sql = """
        SELECT COUNT(*) AS total
        FROM tasks
        WHERE device_id = %s
          AND status IN ('dynamic_tracing')
    """
    row = fetch_one(sql, (device_id,))
    return int(row["total"]) if row else 0
