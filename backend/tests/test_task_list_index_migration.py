import unittest
from pathlib import Path


MIGRATION = Path(__file__).resolve().parents[1] / "migrations" / "v3_task_list_indexes.sql"


class TaskListIndexMigrationTest(unittest.TestCase):
    def test_composite_indexes_cover_owner_status_and_recent_order(self):
        sql = MIGRATION.read_text(encoding="utf-8")
        self.assertIn("(user_id, created_at, id)", sql)
        self.assertIn("(user_id, status, created_at, id)", sql)
        self.assertIn("(status, created_at, id)", sql)
        self.assertIn("information_schema.statistics", sql)


if __name__ == "__main__":
    unittest.main()
