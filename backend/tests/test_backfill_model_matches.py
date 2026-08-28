from __future__ import annotations

import unittest
from unittest.mock import patch

from scripts import backfill_model_matches


class BackfillModelMatchesTest(unittest.TestCase):
    def test_backfill_uses_code_md5_and_clears_unmatched_rows(self) -> None:
        rows = [
            {
                "task_id": "task-hit",
                "code_md5": "dedb1369e3f64726e3c0ccf8bf0ac285",
                "model_id": None,
                "model_name": None,
                "model_type_name": None,
            },
            {
                "task_id": "task-miss",
                "code_md5": "missing",
                "model_id": "old",
                "model_name": "旧模型",
                "model_type_name": "旧类型",
            },
        ]
        models = [
            {
                "model_id": "new",
                "model_name": "新模型",
                "model_type_name": "诈骗类型",
                "model_expression": "codeMd5=='dedb1369e3f64726e3c0ccf8bf0ac285'",
            }
        ]
        updates: list[tuple] = []

        with (
            patch.object(backfill_model_matches, "_load_static_results", return_value=rows),
            patch.object(backfill_model_matches, "get_active_models_ordered", return_value=models),
            patch.object(backfill_model_matches, "execute", side_effect=lambda _sql, params: updates.append(params)),
        ):
            result = backfill_model_matches.backfill_model_matches()

        self.assertEqual(result, {"total": 2, "models": 1, "matched": 1, "changed": 2})
        self.assertEqual(
            updates,
            [
                ("new", "新模型", "诈骗类型", "task-hit"),
                (None, None, None, "task-miss"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
