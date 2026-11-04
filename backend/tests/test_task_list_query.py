import sys
import unittest
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from repositories.task_repo import list_tasks


class TaskListQueryTest(unittest.TestCase):
    def test_page_refresh_can_skip_total_count(self):
        with patch("repositories.task_repo.fetch_one") as count, patch(
            "repositories.task_repo.fetch_all", return_value=[]
        ):
            self.assertEqual(list_tasks({}, 1, 20, include_total=False), ([], None))
        count.assert_not_called()

    def test_unfiltered_count_skips_static_results_and_joins_only_page(self):
        with patch("repositories.task_repo.fetch_one", return_value={"total": 42}) as count, patch(
            "repositories.task_repo.fetch_all", return_value=[]
        ) as rows:
            self.assertEqual(list_tasks({"owner_user_id": "user-1"}, 2, 20), ([], 42))

        count_sql, count_params = count.call_args.args
        list_sql, list_params = rows.call_args.args
        self.assertNotIn("static_results", count_sql)
        self.assertEqual(count_params, ("user-1",))
        self.assertIn("LIMIT %s OFFSET %s", list_sql)
        self.assertIn("JOIN tasks t ON t.id = page.id", list_sql)
        self.assertIn("LEFT JOIN static_results sr ON sr.task_id = t.id", list_sql)
        self.assertEqual(list_params, ("user-1", 20, 20))

    def test_app_search_keeps_static_result_join_before_pagination(self):
        with patch("repositories.task_repo.fetch_one", return_value={"total": 1}) as count, patch(
            "repositories.task_repo.fetch_all", return_value=[]
        ) as rows:
            list_tasks({"package": "example"}, 1, 20)

        count_sql, count_params = count.call_args.args
        list_sql, list_params = rows.call_args.args
        self.assertIn("LEFT JOIN static_results sr ON sr.task_id = t.id", count_sql)
        self.assertEqual(count_params, ("%example%",))
        self.assertIn("sr.package_name LIKE %s", list_sql)
        self.assertEqual(list_params, ("%example%", 20, 0))


if __name__ == "__main__":
    unittest.main()
