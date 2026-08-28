from __future__ import annotations

import argparse
from typing import Any

from analyzers.model_matcher import find_first_matching_model
from core.database import execute, fetch_all
from repositories.model_repo import get_active_models_ordered
from repositories.task_repo import STATIC_RESULT_FIELDS


def _load_missing_static_results() -> list[dict[str, Any]]:
    select_fields = ", ".join(f"sr.{field}" for field in STATIC_RESULT_FIELDS)
    return fetch_all(
        f"""
        SELECT
            sr.task_id,
            t.file_md5 AS code_md5,
            {select_fields}
        FROM static_results sr
        LEFT JOIN tasks t ON t.id = sr.task_id
        WHERE sr.model_id IS NULL OR sr.model_id = ''
        ORDER BY sr.task_id
        """
    )


def backfill_missing_model_matches(dry_run: bool = False) -> dict[str, int]:
    models = get_active_models_ordered()
    rows = _load_missing_static_results()
    matched_count = 0
    updated_count = 0

    for row in rows:
        matched = find_first_matching_model(row, models)
        if not matched.get("model_id"):
            continue

        matched_count += 1
        if dry_run:
            continue

        affected, _ = execute(
            """
            UPDATE static_results
            SET model_id = %s,
                model_name = %s,
                model_type_name = %s
            WHERE task_id = %s
              AND (model_id IS NULL OR model_id = '')
            """,
            (
                matched.get("model_id"),
                matched.get("model_name"),
                matched.get("model_type_name"),
                row["task_id"],
            ),
        )
        updated_count += affected

    return {
        "missing_total": len(rows),
        "models": len(models),
        "matched": matched_count,
        "updated": updated_count,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Backfill model matches only for static_results missing model_id.")
    parser.add_argument("--dry-run", action="store_true", help="Only count matches without updating rows.")
    args = parser.parse_args()
    print(backfill_missing_model_matches(dry_run=args.dry_run))


if __name__ == "__main__":
    main()
