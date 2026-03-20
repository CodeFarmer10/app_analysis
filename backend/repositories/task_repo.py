from __future__ import annotations

from typing import Any

from core.database import execute, fetch_all, fetch_one


def create_task(data: dict[str, Any]) -> str:
    sql = """
        INSERT INTO tasks (
            id,
            source_type,
            source_name,
            user_id,
            status,
            file_md5,
            file_size,
            apk_path,
            error_message,
            device_id
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    execute(
        sql,
        (
            data["id"],
            data["source_type"],
            data["source_name"],
            data.get("user_id"),
            data["status"],
            data.get("file_md5"),
            data.get("file_size"),
            data.get("apk_path"),
            data.get("error_message"),
            data.get("device_id"),
        ),
    )
    return data["id"]


def get_task_by_id(task_id: str) -> dict | None:
    sql = """
        SELECT
            id,
            source_type,
            source_name,
            user_id,
            file_md5,
            file_size,
            status,
            error_message,
            apk_path,
            pcap_path,
            report_path,
            run_log_path,
            device_id,
            created_at,
            updated_at
        FROM tasks
        WHERE id = %s
        LIMIT 1
    """
    return fetch_one(sql, (task_id,))


def get_task_by_md5(md5: str) -> dict | None:
    sql = """
        SELECT
            id,
            source_type,
            source_name,
            user_id,
            file_md5,
            file_size,
            status,
            error_message,
            apk_path,
            pcap_path,
            report_path,
            run_log_path,
            device_id,
            created_at,
            updated_at
        FROM tasks
        WHERE file_md5 = %s
        ORDER BY created_at DESC
        LIMIT 1
    """
    return fetch_one(sql, (md5,))


def update_task(task_id: str, fields: dict[str, Any]) -> int:
    if not fields:
        return 0

    set_fragments: list[str] = []
    values: list[Any] = []
    for key, value in fields.items():
        set_fragments.append(f"{key} = %s")
        values.append(value)

    sql = f"""
        UPDATE tasks
        SET {", ".join(set_fragments)}
        WHERE id = %s
    """
    values.append(task_id)
    rows, _ = execute(sql, tuple(values))
    return rows


def list_tasks(filters: dict[str, Any], page: int, size: int) -> tuple[list[dict], int]:
    where_clauses = ["1 = 1"]
    params: list[Any] = []

    md5 = filters.get("md5")
    if md5:
        where_clauses.append("t.file_md5 LIKE %s")
        params.append(f"%{md5}%")

    name = filters.get("name")
    if name:
        where_clauses.append(
            "(sr.app_name LIKE %s OR t.source_name LIKE %s)"
        )
        params.extend([f"%{name}%", f"%{name}%"])

    package_name = filters.get("package")
    if package_name:
        where_clauses.append("sr.package_name LIKE %s")
        params.append(f"%{package_name}%")

    status = filters.get("status")
    if status:
        where_clauses.append("t.status = %s")
        params.append(status)

    start = filters.get("start")
    if start:
        where_clauses.append("t.created_at >= %s")
        params.append(start)

    end = filters.get("end")
    if end:
        where_clauses.append("t.created_at <= %s")
        params.append(end)

    where_sql = " AND ".join(where_clauses)

    total_sql = f"""
        SELECT COUNT(*) AS total
        FROM tasks t
        LEFT JOIN static_results sr ON sr.task_id = t.id
        WHERE {where_sql}
    """
    total_row = fetch_one(total_sql, tuple(params))
    total = int(total_row["total"]) if total_row else 0

    offset = (page - 1) * size
    list_sql = f"""
        SELECT
            t.id,
            t.source_type,
            t.source_name,
            sr.app_name,
            sr.package_name,
            t.file_md5,
            t.status,
            t.device_id,
            t.created_at,
            t.updated_at
        FROM tasks t
        LEFT JOIN static_results sr ON sr.task_id = t.id
        WHERE {where_sql}
        ORDER BY t.created_at DESC
        LIMIT %s OFFSET %s
    """
    items = fetch_all(list_sql, tuple([*params, size, offset]))
    return items, total


def get_static_result(task_id: str) -> dict | None:
    sql = """
        SELECT
            task_id,
            app_name,
            package_name,
            version_name,
            version_code,
            icon_path,
            cert_md5,
            cert_sha1,
            cert_sha256,
            permissions,
            activities,
            services,
            providers,
            so_files
        FROM static_results
        WHERE task_id = %s
        LIMIT 1
    """
    return fetch_one(sql, (task_id,))


def list_dynamic_results(task_id: str) -> list[dict]:
    sql = """
        SELECT
            id,
            task_id,
            seq,
            action,
            action_result,
            action_time,
            screenshot_before,
            screenshot_after,
            is_success
        FROM dynamic_results
        WHERE task_id = %s
        ORDER BY seq ASC
    """
    return fetch_all(sql, (task_id,))


def list_traffic_logs(task_id: str) -> list[dict]:
    sql = """
        SELECT
            id,
            task_id,
            seq,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            domain,
            url,
            resolved_ip
        FROM traffic_logs
        WHERE task_id = %s
        ORDER BY seq ASC
    """
    return fetch_all(sql, (task_id,))
