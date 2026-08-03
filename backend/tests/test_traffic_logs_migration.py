from __future__ import annotations

import re
import unittest
from pathlib import Path


MIGRATION_PATH = Path(__file__).resolve().parents[1] / "migrations" / "v1_init.sql"


class TrafficLogsMigrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sql = MIGRATION_PATH.read_text(encoding="utf-8")

    def test_base_table_defines_database_generated_created_at(self) -> None:
        table_match = re.search(
            r"CREATE TABLE IF NOT EXISTS traffic_logs \(.*?\n\) ENGINE=InnoDB",
            self.sql,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(table_match)
        self.assertIn(
            "created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP",
            table_match.group(0),
        )

    def test_existing_table_upgrade_is_idempotently_guarded(self) -> None:
        self.assertIn("SET @traffic_logs_created_at_col := (", self.sql)
        self.assertIn("column_name = 'created_at'", self.sql)
        self.assertIn(
            "ALTER TABLE traffic_logs ADD COLUMN created_at DATETIME NOT NULL "
            "DEFAULT CURRENT_TIMESTAMP",
            self.sql,
        )


if __name__ == "__main__":
    unittest.main()
