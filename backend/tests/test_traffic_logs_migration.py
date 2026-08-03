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
        created_at_marker = "-- Backward-compatible traffic_logs creation timestamp."
        real_controller_marker = (
            "-- Backward-compatible traffic_logs real-controller tagging column."
        )
        block_match = re.search(
            re.escape(created_at_marker) + r"\n(.*?)(?=\n-- Backward-compatible )",
            self.sql,
            flags=re.DOTALL,
        )
        self.assertIsNotNone(block_match)
        created_at_block = block_match.group(1)

        for fragment in (
            "SET @traffic_logs_created_at_col := (",
            "FROM information_schema.columns",
            "table_name = 'traffic_logs'",
            "column_name = 'created_at'",
            "SET @sql_traffic_logs_created_at_col := IF(",
            "ALTER TABLE traffic_logs ADD COLUMN created_at DATETIME NOT NULL "
            "DEFAULT CURRENT_TIMESTAMP AFTER is_real_controller",
            "'SELECT 1'",
            "PREPARE stmt_traffic_logs_created_at_col FROM @sql_traffic_logs_created_at_col",
            "EXECUTE stmt_traffic_logs_created_at_col",
            "DEALLOCATE PREPARE stmt_traffic_logs_created_at_col",
        ):
            self.assertIn(fragment, created_at_block)

        self.assertLess(
            self.sql.index(real_controller_marker),
            self.sql.index(created_at_marker),
        )


if __name__ == "__main__":
    unittest.main()
