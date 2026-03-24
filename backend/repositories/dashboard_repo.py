from __future__ import annotations

from datetime import date, datetime, time, timedelta

from core.database import fetch_all, fetch_one


def get_stats() -> dict:
    sql = """
        SELECT
            (SELECT COUNT(*) FROM tasks) AS total_tasks,
            (SELECT COUNT(*) FROM tasks WHERE DATE(created_at) = CURDATE()) AS today_submitted,
            (
                SELECT COUNT(*)
                FROM tasks
                WHERE status = 'completed'
                  AND DATE(updated_at) = CURDATE()
            ) AS today_completed,
            (
                SELECT COUNT(*)
                FROM tasks
                WHERE status IN ('downloading', 'static_analyzing', 'waiting_device', 'dynamic_tracing')
            ) AS analyzing_tasks,
            (SELECT COUNT(*) FROM devices WHERE status = 'online') AS online_devices,
            (SELECT COUNT(*) FROM tasks WHERE status = 'completed') AS completed_tasks
    """
    row = fetch_one(sql) or {}
    total_tasks = int(row.get("total_tasks") or 0)
    completed_tasks = int(row.get("completed_tasks") or 0)
    success_rate = round((completed_tasks / total_tasks) * 100, 2) if total_tasks > 0 else 0.0
    return {
        "total_tasks": total_tasks,
        "today_submitted": int(row.get("today_submitted") or 0),
        "today_completed": int(row.get("today_completed") or 0),
        "analyzing_tasks": int(row.get("analyzing_tasks") or 0),
        "online_devices": int(row.get("online_devices") or 0),
        "success_rate": success_rate,
    }


def get_trend(days: int) -> list[dict]:
    normalized_days = max(1, days)
    today = date.today()
    start_date = today - timedelta(days=normalized_days - 1)
    end_date = today + timedelta(days=1)
    start_time = datetime.combine(start_date, time.min)
    end_time = datetime.combine(end_date, time.min)

    submit_sql = """
        SELECT DATE(created_at) AS day, COUNT(*) AS total
        FROM tasks
        WHERE created_at >= %s
          AND created_at < %s
        GROUP BY DATE(created_at)
    """
    completed_sql = """
        SELECT DATE(updated_at) AS day, COUNT(*) AS total
        FROM tasks
        WHERE status = 'completed'
          AND updated_at >= %s
          AND updated_at < %s
        GROUP BY DATE(updated_at)
    """

    submit_rows = fetch_all(submit_sql, (start_time, end_time))
    completed_rows = fetch_all(completed_sql, (start_time, end_time))

    submit_map = {str(row["day"]): int(row["total"]) for row in submit_rows}
    completed_map = {str(row["day"]): int(row["total"]) for row in completed_rows}

    trend: list[dict] = []
    current = start_date
    while current <= today:
        key = current.isoformat()
        trend.append(
            {
                "date": key,
                "submitted": submit_map.get(key, 0),
                "completed": completed_map.get(key, 0),
            }
        )
        current += timedelta(days=1)
    return trend
