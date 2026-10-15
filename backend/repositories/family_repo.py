from __future__ import annotations

from core.database import fetch_all, fetch_one


def _model_filters(keyword: str | None, fraud_type: str | None) -> tuple[str, list[str]]:
    clauses = ["m.status = 1"]
    params: list[str] = []
    if keyword:
        clauses.append("(m.model_name LIKE %s OR m.family_description LIKE %s)")
        params.extend([f"%{keyword}%", f"%{keyword}%"])
    if fraud_type:
        clauses.append("m.model_type_name = %s")
        params.append(fraud_type)
    return " AND ".join(clauses), params


def _task_join(owner_user_id: str | None) -> tuple[str, list[str]]:
    if owner_user_id is None:
        return "LEFT JOIN tasks t ON t.id = sr.task_id", []
    return "LEFT JOIN tasks t ON t.id = sr.task_id AND t.user_id = %s", [owner_user_id]


def list_families(
    owner_user_id: str | None,
    keyword: str | None,
    fraud_type: str | None,
    page: int,
    size: int,
) -> tuple[list[dict], int]:
    where_sql, filter_params = _model_filters(keyword, fraud_type)
    total_row = fetch_one(f"SELECT COUNT(*) AS total FROM models m WHERE {where_sql}", tuple(filter_params))
    task_join, join_params = _task_join(owner_user_id)
    items = fetch_all(
        f"""
        SELECT m.model_id AS id, m.model_id AS modelId, m.model_name AS name,
               m.family_description AS description, m.model_type_name AS type,
               COUNT(t.id) AS count, MAX(t.created_at) AS latestTaskAt
        FROM models m
        LEFT JOIN static_results sr ON sr.model_id = m.model_id
        {task_join}
        WHERE {where_sql}
        GROUP BY m.model_id, m.model_name, m.family_description,
                 m.model_type_name, m.created_at
        ORDER BY COUNT(t.id) DESC, latestTaskAt DESC, m.created_at DESC, m.model_id DESC
        LIMIT %s OFFSET %s
        """,
        tuple([*join_params, *filter_params, size, (page - 1) * size]),
    )
    return items, int(total_row["total"]) if total_row else 0


def get_family(model_id: str, owner_user_id: str | None) -> dict | None:
    task_join, join_params = _task_join(owner_user_id)
    return fetch_one(
        f"""
        SELECT m.model_id AS id, m.model_id AS modelId, m.model_name AS name,
               m.family_description AS description, m.model_type_name AS type,
               COUNT(t.id) AS count, MAX(t.created_at) AS latestTaskAt
        FROM models m
        LEFT JOIN static_results sr ON sr.model_id = m.model_id
        {task_join}
        WHERE m.model_id = %s AND m.status = 1
        GROUP BY m.model_id, m.model_name, m.family_description, m.model_type_name
        """,
        tuple([*join_params, model_id]),
    )


def list_family_members(
    model_id: str, owner_user_id: str | None, page: int, size: int
) -> tuple[list[dict], int]:
    owner_clause = " AND t.user_id = %s" if owner_user_id is not None else ""
    params = [model_id, *([owner_user_id] if owner_user_id is not None else [])]
    total_row = fetch_one(
        f"""
        SELECT COUNT(*) AS total
        FROM static_results sr JOIN tasks t ON t.id = sr.task_id
        WHERE sr.model_id = %s{owner_clause}
        """,
        tuple(params),
    )
    items = fetch_all(
        f"""
        SELECT t.id, t.task_description, t.priority, t.source_type, t.source_name,
               sr.app_name, sr.package_name, sr.icon_path, sr.model_type_name,
               t.file_md5, t.status, t.apk_path, t.report_path, t.pcap_path,
               t.device_id, d.serial AS device_serial, t.created_at, t.updated_at
        FROM static_results sr
        JOIN tasks t ON t.id = sr.task_id
        LEFT JOIN devices d ON d.id = t.device_id
        WHERE sr.model_id = %s{owner_clause}
        ORDER BY t.created_at DESC, t.id DESC
        LIMIT %s OFFSET %s
        """,
        tuple([*params, size, (page - 1) * size]),
    )
    return items, int(total_row["total"]) if total_row else 0


def list_family_types() -> list[str]:
    rows = fetch_all(
        "SELECT DISTINCT model_type_name FROM models WHERE status = 1 ORDER BY model_type_name"
    )
    return [row["model_type_name"] for row in rows]
