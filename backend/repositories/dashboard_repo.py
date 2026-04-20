from __future__ import annotations

from datetime import date, datetime, time, timedelta

from core.database import fetch_all, fetch_one


def _task_owner_filter(owner_user_id: str | None) -> tuple[str, list]:
    normalized = str(owner_user_id or "").strip()
    if not normalized:
        return "", []
    return " AND user_id = %s", [normalized]


def get_stats(owner_user_id: str | None = None) -> dict:
    task_owner_sql, task_owner_params = _task_owner_filter(owner_user_id)
    sql = """
        SELECT
            (SELECT COUNT(*) FROM tasks WHERE 1 = 1 {task_owner_sql}) AS total_tasks,
            (
                SELECT COUNT(*)
                FROM tasks
                WHERE DATE(created_at) = CURDATE()
                {task_owner_sql}
            ) AS today_submitted,
            (
                SELECT COUNT(*)
                FROM tasks
                WHERE status = 'completed'
                  AND DATE(updated_at) = CURDATE()
                  {task_owner_sql}
            ) AS today_completed,
            (
                SELECT COUNT(*)
                FROM tasks
                WHERE status IN ('downloading', 'static_analyzing', 'waiting_device', 'dynamic_tracing')
                  {task_owner_sql}
            ) AS analyzing_tasks,
            (SELECT COUNT(*) FROM devices WHERE status = 'online') AS online_devices,
            (
                SELECT COUNT(*)
                FROM tasks
                WHERE status = 'completed'
                {task_owner_sql}
            ) AS completed_tasks
    """
    formatted_sql = sql.format(task_owner_sql=task_owner_sql)
    params = tuple(task_owner_params * 5)
    row = fetch_one(formatted_sql, params) or {}
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


def get_trend(days: int, owner_user_id: str | None = None) -> list[dict]:
    normalized_days = max(1, days)
    today = date.today()
    start_date = today - timedelta(days=normalized_days - 1)
    end_date = today + timedelta(days=1)
    start_time = datetime.combine(start_date, time.min)
    end_time = datetime.combine(end_date, time.min)
    task_owner_sql, task_owner_params = _task_owner_filter(owner_user_id)

    submit_sql = """
        SELECT DATE(created_at) AS day, COUNT(*) AS total
        FROM tasks
        WHERE created_at >= %s
          AND created_at < %s
          {task_owner_sql}
        GROUP BY DATE(created_at)
    """.format(task_owner_sql=task_owner_sql)
    completed_sql = """
        SELECT DATE(updated_at) AS day, COUNT(*) AS total
        FROM tasks
        WHERE status = 'completed'
          AND updated_at >= %s
          AND updated_at < %s
          {task_owner_sql}
        GROUP BY DATE(updated_at)
    """.format(task_owner_sql=task_owner_sql)

    submit_params = tuple([start_time, end_time, *task_owner_params])
    completed_params = tuple([start_time, end_time, *task_owner_params])
    submit_rows = fetch_all(submit_sql, submit_params)
    completed_rows = fetch_all(completed_sql, completed_params)

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
