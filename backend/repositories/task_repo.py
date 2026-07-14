from __future__ import annotations

import json
from typing import Any

from core.database import execute, fetch_all, fetch_one
from repositories.sdk_repo import get_sdk_findings


def create_task(data: dict[str, Any]) -> str:
    sql = """
        INSERT INTO tasks (
            id,
            batch_id,
            task_description,
            priority,
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
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """
    execute(
        sql,
        (
            data["id"],
            data.get("batch_id"),
            data.get("task_description"),
            int(data.get("priority", 1)),
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
            t.id,
            t.batch_id,
            t.task_description,
            t.priority,
            t.source_type,
            t.source_name,
            t.user_id,
            t.file_md5,
            t.file_size,
            t.status,
            t.error_message,
            t.apk_path,
            t.pcap_path,
            t.report_path,
            t.run_log_path,
            t.device_id,
            d.serial AS device_serial,
            t.created_at,
            t.updated_at
        FROM tasks t
        LEFT JOIN devices d ON d.id = t.device_id
        WHERE t.id = %s
        LIMIT 1
    """
    return fetch_one(sql, (task_id,))


def get_task_by_md5(md5: str) -> dict | None:
    sql = """
        SELECT
            id,
            batch_id,
            task_description,
            priority,
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

    task_description = filters.get("task_description")
    if task_description:
        where_clauses.append("t.task_description LIKE %s")
        params.append(f"%{task_description}%")

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

    owner_user_id = filters.get("owner_user_id")
    if owner_user_id:
        where_clauses.append("t.user_id = %s")
        params.append(owner_user_id)

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
            t.batch_id,
            t.task_description,
            t.priority,
            t.source_type,
            t.source_name,
            sr.app_name,
            sr.package_name,
            sr.icon_path,
            t.file_md5,
            t.status,
            t.apk_path,
            t.report_path,
            t.pcap_path,
            t.device_id,
            d.serial AS device_serial,
            t.created_at,
            t.updated_at
        FROM tasks t
        LEFT JOIN static_results sr ON sr.task_id = t.id
        LEFT JOIN devices d ON d.id = t.device_id
        WHERE {where_sql}
        ORDER BY t.created_at DESC, t.id DESC
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
            cert_info,
            permissions,
            activities,
            services,
            providers,
            receivers,
            so_files,
            component_string,
            component_md5,
            framework_name,
            framework_matches,
            is_packed,
            packer_vendor,
            packer_vendors,
            packer_details,
            is_obfuscated,
            obfuscation_vendor,
            obfuscation_vendors,
            obfuscator_details,
            protection_detect_error,
            unpack_archive_path,
            unpack_error,
            source_phones,
            source_emails,
            source_urls
        FROM static_results
        WHERE task_id = %s
        LIMIT 1
    """
    row = fetch_one(sql, (task_id,))
    if not row:
        return None

    for field in (
        "cert_info",
        "permissions",
        "activities",
        "services",
        "providers",
        "receivers",
        "so_files",
        "packer_vendors",
        "packer_details",
        "obfuscation_vendors",
        "obfuscator_details",
        "framework_matches",
        "source_phones",
        "source_emails",
        "source_urls",
    ):
        value = row.get(field)
        if isinstance(value, str):
            try:
                row[field] = json.loads(value)
            except json.JSONDecodeError:
                row[field] = value
    row["sdk_findings"] = get_sdk_findings(task_id)
    return row


def upsert_static_result(task_id: str, data: dict[str, Any]) -> int:
    sql = """
        INSERT INTO static_results (
            task_id,
            app_name,
            package_name,
            version_name,
            version_code,
            icon_path,
            cert_md5,
            cert_sha1,
            cert_sha256,
            cert_info,
            permissions,
            activities,
            services,
            providers,
            receivers,
            so_files,
            component_string,
            component_md5,
            framework_name,
            framework_matches,
            is_packed,
            packer_vendor,
            packer_vendors,
            packer_details,
            is_obfuscated,
            obfuscation_vendor,
            obfuscation_vendors,
            obfuscator_details,
            protection_detect_error,
            unpack_archive_path,
            unpack_error,
            source_phones,
            source_emails,
            source_urls
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE
            app_name = VALUES(app_name),
            package_name = VALUES(package_name),
            version_name = VALUES(version_name),
            version_code = VALUES(version_code),
            icon_path = VALUES(icon_path),
            cert_md5 = VALUES(cert_md5),
            cert_sha1 = VALUES(cert_sha1),
            cert_sha256 = VALUES(cert_sha256),
            cert_info = VALUES(cert_info),
            permissions = VALUES(permissions),
            activities = VALUES(activities),
            services = VALUES(services),
            providers = VALUES(providers),
            receivers = VALUES(receivers),
            so_files = VALUES(so_files),
            component_string = VALUES(component_string),
            component_md5 = VALUES(component_md5),
            framework_name = VALUES(framework_name),
            framework_matches = VALUES(framework_matches),
            is_packed = VALUES(is_packed),
            packer_vendor = VALUES(packer_vendor),
            packer_vendors = VALUES(packer_vendors),
            packer_details = VALUES(packer_details),
            is_obfuscated = VALUES(is_obfuscated),
            obfuscation_vendor = VALUES(obfuscation_vendor),
            obfuscation_vendors = VALUES(obfuscation_vendors),
            obfuscator_details = VALUES(obfuscator_details),
            protection_detect_error = VALUES(protection_detect_error),
            source_phones = VALUES(source_phones),
            source_emails = VALUES(source_emails),
            source_urls = VALUES(source_urls)
    """
    rows, _ = execute(
        sql,
        (
            task_id,
            data.get("app_name"),
            data.get("package_name"),
            data.get("version_name"),
            data.get("version_code"),
            data.get("icon_path"),
            data.get("cert_md5"),
            data.get("cert_sha1"),
            data.get("cert_sha256"),
            json.dumps(data.get("cert_info"), ensure_ascii=False) if data.get("cert_info") is not None else None,
            json.dumps(data.get("permissions") or [], ensure_ascii=False),
            json.dumps(data.get("activities") or [], ensure_ascii=False),
            json.dumps(data.get("services") or [], ensure_ascii=False),
            json.dumps(data.get("providers") or [], ensure_ascii=False),
            json.dumps(data.get("receivers") or [], ensure_ascii=False),
            json.dumps(data.get("so_files") or [], ensure_ascii=False),
            data.get("component_string"),
            data.get("component_md5"),
            data.get("framework_name"),
            json.dumps(data.get("framework_matches") or [], ensure_ascii=False),
            1 if data.get("is_packed") else 0,
            data.get("packer_vendor"),
            json.dumps(data.get("packer_vendors") or [], ensure_ascii=False),
            json.dumps(data.get("packer_details") or [], ensure_ascii=False),
            1 if data.get("is_obfuscated") else 0,
            data.get("obfuscation_vendor"),
            json.dumps(data.get("obfuscation_vendors") or [], ensure_ascii=False),
            json.dumps(data.get("obfuscator_details") or [], ensure_ascii=False),
            data.get("protection_detect_error"),
            data.get("unpack_archive_path"),
            data.get("unpack_error"),
            json.dumps(data.get("source_phones") or [], ensure_ascii=False),
            json.dumps(data.get("source_emails") or [], ensure_ascii=False),
            json.dumps(data.get("source_urls") or [], ensure_ascii=False),
        ),
    )
    return rows


def update_static_result_fields(task_id: str, fields: dict[str, Any]) -> int:
    if not fields:
        return 0

    json_fields = {
        "permissions",
        "activities",
        "services",
        "providers",
        "receivers",
        "so_files",
        "packer_vendors",
        "packer_details",
        "obfuscation_vendors",
        "obfuscator_details",
        "framework_matches",
        "source_phones",
        "source_emails",
        "source_urls",
    }
    set_fragments: list[str] = []
    values: list[Any] = []
    for key, value in fields.items():
        set_fragments.append(f"{key} = %s")
        if key in json_fields:
            values.append(json.dumps(value or [], ensure_ascii=False))
        elif key in {"is_packed", "is_obfuscated"}:
            values.append(1 if value else 0)
        else:
            values.append(value)

    sql = f"""
        UPDATE static_results
        SET {", ".join(set_fragments)}
        WHERE task_id = %s
    """
    values.append(task_id)
    rows, _ = execute(sql, tuple(values))
    return rows


def get_dynamic_results(task_id: str, page: int, size: int) -> tuple[list[dict], int]:
    offset = (max(page, 1) - 1) * max(size, 1)
    total_sql = "SELECT COUNT(*) AS total FROM dynamic_results WHERE task_id = %s"
    total_row = fetch_one(total_sql, (task_id,))
    total = int(total_row["total"]) if total_row else 0

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
        LIMIT %s OFFSET %s
    """
    items = fetch_all(sql, (task_id, max(size, 1), offset))
    return items, total


def get_traffic_logs(task_id: str, page: int, size: int) -> tuple[list[dict], int]:
    offset = (max(page, 1) - 1) * max(size, 1)
    total_sql = "SELECT COUNT(*) AS total FROM traffic_logs WHERE task_id = %s"
    total_row = fetch_one(total_sql, (task_id,))
    total = int(total_row["total"]) if total_row else 0

    sql = """
        SELECT
            id,
            task_id,
            dynamic_result_id,
            seq,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            domain,
            url,
            resolved_ip,
            ip_country,
            is_up,
            is_real_controller
        FROM traffic_logs
        WHERE task_id = %s
        ORDER BY seq ASC
        LIMIT %s OFFSET %s
    """
    items = fetch_all(sql, (task_id, max(size, 1), offset))
    return items, total


def get_traffic_logs_by_seqs(task_id: str, seqs: list[int]) -> list[dict]:
    normalized_seqs = sorted({int(seq) for seq in seqs if isinstance(seq, int) and seq >= 0})
    if not normalized_seqs:
        return []

    placeholders = ",".join(["%s"] * len(normalized_seqs))
    sql = f"""
        SELECT
            id,
            task_id,
            dynamic_result_id,
            seq,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            domain,
            url,
            resolved_ip,
            ip_country,
            is_up,
            is_real_controller
        FROM traffic_logs
        WHERE task_id = %s
          AND seq IN ({placeholders})
        ORDER BY seq ASC, id ASC
    """
    return fetch_all(sql, (task_id, *normalized_seqs))


def get_traffic_logs_by_dynamic_result_ids(task_id: str, dynamic_result_ids: list[str]) -> list[dict]:
    normalized_ids = sorted({str(item).strip() for item in dynamic_result_ids if str(item).strip()})
    if not normalized_ids:
        return []

    placeholders = ",".join(["%s"] * len(normalized_ids))
    sql = f"""
        SELECT
            id,
            task_id,
            dynamic_result_id,
            seq,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            domain,
            url,
            resolved_ip,
            ip_country,
            is_up,
            is_real_controller
        FROM traffic_logs
        WHERE task_id = %s
          AND dynamic_result_id IN ({placeholders})
        ORDER BY seq ASC, id ASC
    """
    return fetch_all(sql, (task_id, *normalized_ids))


def get_dynamic_result_by_seq(task_id: str, seq: int) -> dict | None:
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
          AND seq = %s
        LIMIT 1
    """
    return fetch_one(sql, (task_id, seq))


def list_dynamic_results(task_id: str) -> list[dict]:
    items, _ = get_dynamic_results(task_id, page=1, size=10_000)
    return items


def list_traffic_logs(task_id: str) -> list[dict]:
    items, _ = get_traffic_logs(task_id, page=1, size=50_000)
    return items
