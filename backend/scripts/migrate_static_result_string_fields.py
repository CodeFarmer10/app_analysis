from __future__ import annotations

import json
import sys
from datetime import datetime

from core.database import execute, fetch_all, fetch_one, get_connection


TARGET_TABLE = "static_results"
STRING_FIELDS = [
    ("dcloud_appids", "dcloud_tech_type"),
    ("dcloud_pages", "dcloud_appids"),
    ("dcloud_api_routes", "dcloud_pages"),
    ("flutter_library_uris", "flutter_primary_entry_uri"),
    ("flutter_primary_package_classes", "flutter_library_uris"),
]
TRACKED_COLUMNS = [
    "so_files",
    "so_libraries",
    "component_string",
    "component_str",
    "components",
    "dcloud_appids",
    "dcloud_pages",
    "dcloud_api_routes",
    "flutter_library_uris",
    "flutter_primary_package_classes",
]


def qident(name: str) -> str:
    return "`" + name.replace("`", "``") + "`"


def column_exists(name: str) -> bool:
    row = fetch_one(
        """
        SELECT COUNT(*) AS c
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = %s
          AND column_name = %s
        """,
        (TARGET_TABLE, name),
    )
    return bool(row and int(row["c"]))


def column_info() -> list[dict]:
    return fetch_all(
        """
        SELECT column_name, data_type, column_type, ordinal_position
        FROM information_schema.columns
        WHERE table_schema = DATABASE()
          AND table_name = %s
          AND column_name IN ({})
        ORDER BY ordinal_position
        """.format(",".join(["%s"] * len(TRACKED_COLUMNS))),
        (TARGET_TABLE, *TRACKED_COLUMNS),
    )


def print_columns(label: str) -> None:
    print(label)
    for column in column_info():
        print(
            "{}\t{}\t{}\t{}".format(
                column["ordinal_position"],
                column["column_name"],
                column["data_type"],
                column["column_type"],
            )
        )


def add_column_if_missing(name: str, definition: str, after: str) -> None:
    if not column_exists(name):
        execute(
            f"ALTER TABLE {qident(TARGET_TABLE)} "
            f"ADD COLUMN {qident(name)} {definition} AFTER {qident(after)}"
        )
        print(f"added column {name}")


def drop_column_if_exists(name: str) -> None:
    if column_exists(name):
        execute(f"ALTER TABLE {qident(TARGET_TABLE)} DROP COLUMN {qident(name)}")
        print(f"dropped column {name}")


def update_column_values(name: str, rows: list[tuple[str | None, str]]) -> int:
    if not rows:
        return 0
    sql = f"UPDATE {qident(TARGET_TABLE)} SET {qident(name)} = %s WHERE task_id = %s"
    with get_connection() as conn:
        with conn.cursor() as cursor:
            cursor.executemany(sql, rows)
        conn.commit()
    return len(rows)


def comma_string(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, (list, tuple, set)):
        items = [str(item).strip() for item in value]
        return ",".join(item for item in items if item)
    if not isinstance(value, str):
        return str(value)

    text = value.strip()
    if not text:
        return ""
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return value
    if parsed is None:
        return None
    if isinstance(parsed, list):
        items = [str(item).strip() for item in parsed]
        return ",".join(item for item in items if item)
    return str(parsed)


def normalize_jsonish_column(name: str) -> None:
    rows = fetch_all(
        f"""
        SELECT task_id, {qident(name)} AS value
        FROM {qident(TARGET_TABLE)}
        WHERE {qident(name)} IS NOT NULL
        """
    )
    changed = 0
    updates: list[tuple[str | None, str]] = []
    for row in rows:
        normalized = comma_string(row.get("value"))
        if normalized != row.get("value"):
            updates.append((normalized, row["task_id"]))
            changed += 1
    update_column_values(name, updates)
    print(f"normalized {name} changed={changed}")


def migrate_from_json_source(dst: str, src: str) -> None:
    rows = fetch_all(
        f"""
        SELECT task_id, {qident(src)} AS value
        FROM {qident(TARGET_TABLE)}
        WHERE ({qident(dst)} IS NULL OR {qident(dst)} = '') AND {qident(src)} IS NOT NULL
        """
    )
    changed = 0
    updates: list[tuple[str | None, str]] = []
    for row in rows:
        updates.append((comma_string(row.get("value")), row["task_id"]))
        changed += 1
    update_column_values(dst, updates)
    print(f"migrated {src} -> {dst} changed={changed}")


def create_backup() -> str:
    backup_name = "static_results_field_migration_backup_" + datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_columns = ["task_id"] + [name for name in TRACKED_COLUMNS if column_exists(name)]
    execute(
        "CREATE TABLE {} AS SELECT {} FROM {}".format(
            qident(backup_name),
            ", ".join(qident(column) for column in backup_columns),
            qident(TARGET_TABLE),
        )
    )
    backup_count = fetch_one(f"SELECT COUNT(*) AS c FROM {qident(backup_name)}")
    print("backup_table={} rows={}".format(backup_name, backup_count["c"] if backup_count else 0))
    return backup_name


def print_summary() -> None:
    summary = fetch_one(
        """
        SELECT
          COUNT(*) AS total_rows,
          SUM(so_libraries IS NOT NULL AND so_libraries <> '') AS so_libraries_nonempty,
          SUM(components IS NOT NULL AND components <> '') AS components_nonempty,
          SUM(dcloud_appids IS NOT NULL AND dcloud_appids <> '') AS dcloud_appids_nonempty,
          SUM(dcloud_pages IS NOT NULL AND dcloud_pages <> '') AS dcloud_pages_nonempty,
          SUM(dcloud_api_routes IS NOT NULL AND dcloud_api_routes <> '') AS dcloud_api_routes_nonempty,
          SUM(flutter_library_uris IS NOT NULL AND flutter_library_uris <> '') AS flutter_library_uris_nonempty,
          SUM(flutter_primary_package_classes IS NOT NULL AND flutter_primary_package_classes <> '') AS flutter_primary_package_classes_nonempty
        FROM static_results
        """
    )
    print(f"summary={summary}")


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    print_columns("before")
    create_backup()

    add_column_if_missing("so_libraries", "LONGTEXT NULL", "receivers")
    if column_exists("so_files"):
        migrate_from_json_source("so_libraries", "so_files")
        drop_column_if_exists("so_files")

    add_column_if_missing("components", "LONGTEXT NULL", "so_libraries")
    for old_component_column in ("component_string", "component_str"):
        if column_exists(old_component_column):
            execute(
                f"""
                UPDATE {qident(TARGET_TABLE)}
                SET components = COALESCE(components, {qident(old_component_column)})
                WHERE {qident(old_component_column)} IS NOT NULL
                """
            )
            print(f"migrated {old_component_column} -> components")
            drop_column_if_exists(old_component_column)

    for field, after in STRING_FIELDS:
        add_column_if_missing(field, "LONGTEXT NULL", after)
        execute(f"ALTER TABLE {qident(TARGET_TABLE)} MODIFY COLUMN {qident(field)} LONGTEXT NULL")
        normalize_jsonish_column(field)

    print_columns("after")
    print_summary()


if __name__ == "__main__":
    main()
