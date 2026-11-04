from __future__ import annotations

import unittest
from unittest.mock import patch

from repositories import family_recommendation_repo


class FakeCursor:
    def __init__(self, matched_task_id: str | None = None) -> None:
        self.matched_task_id = matched_task_id
        self.queries: list[str] = []
        self.rowcount = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, _params):
        self.queries.append(sql.strip())
        if "UPDATE static_results" in sql:
            self.rowcount = 5
        else:
            self.rowcount = 1

    def fetchone(self):
        return {
            "id": "candidate-1",
            "status": "pending",
            "rule_expression": "jaccard_sim(flutter_aot_opcode_4grams,'a,b,c')>0.8",
        }

    def fetchall(self):
        return [{
            "task_id": f"task-{number}",
            "model_id": "other-model" if self.matched_task_id == f"task-{number}" else None,
            "file_md5": f"{number:032x}",
            "flutter_aot_opcode_4grams": "a,b,c",
        } for number in range(5)]


class FakeConnection:
    def __init__(self, matched_task_id: str | None = None) -> None:
        self.fake_cursor = FakeCursor(matched_task_id)
        self.committed = False
        self.rolled_back = False

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def cursor(self):
        return self.fake_cursor

    def commit(self):
        self.committed = True

    def rollback(self):
        self.rolled_back = True


class FamilyRecommendationRepositoryTest(unittest.TestCase):
    def test_load_unmatched_ga_apps_parameterizes_description_prefix(self):
        with patch.object(family_recommendation_repo, "fetch_all", return_value=[]) as fetch_all:
            family_recommendation_repo.load_unmatched_ga_apps()

        sql = fetch_all.call_args.args[0]
        self.assertIn("t.task_description LIKE %s", sql)
        self.assertEqual(fetch_all.call_args.args[1:], (("ga%",),))

    def test_save_candidate_links_static_results_without_detail_table(self):
        candidate = {
            "id": "candidate-1", "batch_id": "batch-1", "family_key": "key-1",
            "framework_name": "Flutter", "cluster_strategy": "flutter_aot_complete_link",
            "cluster_stage": "aot_opcode_4grams", "member_count": 5,
            "representative_task_id": "task-0", "min_pair_similarity": 0.91,
            "fingerprints_json": '["a"]', "rule_expression": "rule",
            "model_name": "家族甲", "family_description": "共性",
            "model_type_code": "1003", "model_type_name": "虚假投资",
            "confidence": 0.9, "status": "pending", "failure_reason": None,
        }

        class SaveCursor(FakeCursor):
            def fetchone(self):
                return {"id": "candidate-1", "status": "pending"}

            def fetchall(self):
                return [{
                    "task_id": f"task-{number}", "model_id": None,
                    "task_description": "ga_陕西",
                    "family_recommendation_id": None, "old_status": None,
                } for number in range(5)]

        connection = FakeConnection()
        connection.fake_cursor = SaveCursor()
        with patch.object(family_recommendation_repo, "get_connection", return_value=connection):
            saved = family_recommendation_repo.save_candidate(candidate, [f"task-{number}" for number in range(5)])

        self.assertEqual(saved, "candidate-1")
        self.assertTrue(connection.committed)
        self.assertIn(
            "UPDATE static_results SET family_recommendation_id=%s",
            "\n".join(connection.fake_cursor.queries),
        )

    def test_approve_creates_model_and_links_exact_candidate_tasks_in_one_transaction(self):
        connection = FakeConnection()
        with patch.object(family_recommendation_repo, "get_connection", return_value=connection):
            model_id = family_recommendation_repo.approve_candidate(
                "candidate-1", "admin-1", "家族甲", "共性", "1003", "虚假投资"
            )

        self.assertEqual(len(model_id), 36)
        self.assertTrue(connection.committed)
        self.assertFalse(connection.rolled_back)
        sql = "\n".join(connection.fake_cursor.queries)
        self.assertIn("INSERT INTO models", sql)
        self.assertIn("WHERE family_recommendation_id=%s AND model_id IS NULL", sql)
        self.assertIn("status='approved'", sql)

    def test_approve_rolls_back_when_a_member_has_another_model(self):
        connection = FakeConnection(matched_task_id="task-2")
        with patch.object(family_recommendation_repo, "get_connection", return_value=connection):
            with self.assertRaises(family_recommendation_repo.RecommendationConflict):
                family_recommendation_repo.approve_candidate(
                    "candidate-1", "admin-1", "家族甲", "共性", "1003", "虚假投资"
                )

        self.assertTrue(connection.rolled_back)
        self.assertFalse(connection.committed)
        self.assertNotIn("INSERT INTO models", "\n".join(connection.fake_cursor.queries))


if __name__ == "__main__":
    unittest.main()
