from __future__ import annotations

import argparse
from typing import Any

from analyzers.model_matcher import find_first_matching_model
from core.database import execute, fetch_all
from repositories.model_repo import get_active_models_ordered
from repositories.task_repo import STATIC_RESULT_FIELDS


MODEL_RESULT_FIELDS = {"model_id", "model_name", "model_type_name"}


def _load_static_results() -> list[dict[str, Any]]:
    select_fields = ", ".join(f"sr.{field}" for field in STATIC_RESULT_FIELDS)
    return fetch_all(
        f"""
        SELECT
            sr.task_id,
            t.file_md5 AS code_md5,
            {select_fields}
        FROM static_results sr
        LEFT JOIN tasks t ON t.id = sr.task_id
        ORDER BY sr.task_id
        """
    )


def _has_changed(row: dict[str, Any], matched: dict[str, Any]) -> bool:
    return any((row.get(field) or None) != (matched.get(field) or None) for field in MODEL_RESULT_FIELDS)


def backfill_model_matches(dry_run: bool = False) -> dict[str, int]:
    models = get_active_models_ordered()
    rows = _load_static_results()
    matched_count = 0
    changed_count = 0

    for row in rows:
        matched = find_first_matching_model(row, models)
        if matched.get("model_id"):
            matched_count += 1
        if not _has_changed(row, matched):
            continue
        changed_count += 1
        if dry_run:
            continue
        execute(
            """
            UPDATE static_results
            SET model_id = %s,
                model_name = %s,
                model_type_name = %s
            WHERE task_id = %s
            """,
            (
                matched.get("model_id"),
                matched.get("model_name"),
                matched.get("model_type_name"),
                row["task_id"],
            ),
        )

    return {
        "total": len(rows),
        "models": len(models),
        "matched": matched_count,
        "changed": changed_count,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Backfill static result model matches.")
    parser.add_argument("--dry-run", action="store_true", help="Only count changes without updating rows.")
    args = parser.parse_args()
    print(backfill_model_matches(dry_run=args.dry_run))


if __name__ == "__main__":
    main()
