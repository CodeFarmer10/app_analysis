from __future__ import annotations

import re
import unittest
from pathlib import Path


MIGRATION_SQL = Path(__file__).resolve().parents[1] / "migrations" / "v1_init.sql"


class ModelMigrationTest(unittest.TestCase):
    def test_models_table_schema_is_declared(self) -> None:
        sql = MIGRATION_SQL.read_text(encoding="utf-8")

        self.assertIn("CREATE TABLE IF NOT EXISTS models", sql)
        for column in (
            "model_id VARCHAR(36) PRIMARY KEY",
            "model_name VARCHAR(255) NOT NULL",
            "model_type_code VARCHAR(64) NOT NULL",
            "model_type_name VARCHAR(128) NOT NULL",
            "model_expression LONGTEXT NOT NULL",
            "status TINYINT(1) NOT NULL DEFAULT 1",
            "created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP",
        ):
            with self.subTest(column=column):
                self.assertIn(column, sql)

        self.assertRegex(sql, re.compile(r"KEY idx_models_type_code \(model_type_code\)"))
        self.assertRegex(sql, re.compile(r"KEY idx_models_status \(status\)"))
        self.assertRegex(sql, re.compile(r"KEY idx_models_created_at \(created_at\)"))

    def test_models_status_column_has_idempotent_upgrade_sql(self) -> None:
        sql = MIGRATION_SQL.read_text(encoding="utf-8")

        self.assertIn("column_name = 'status'", sql)
        self.assertIn("ALTER TABLE models ADD COLUMN status TINYINT(1) NOT NULL DEFAULT 1", sql)
        self.assertIn("ALTER TABLE models ADD KEY idx_models_status (status)", sql)

    def test_static_results_model_columns_have_idempotent_upgrade_sql(self) -> None:
        sql = MIGRATION_SQL.read_text(encoding="utf-8")

        self.assertIn("model_id VARCHAR(36) NULL", sql)
        self.assertIn("model_name VARCHAR(255) NULL", sql)
        self.assertIn("model_type_name VARCHAR(128) NULL", sql)
        self.assertIn("column_name = 'model_id'", sql)
        self.assertIn("column_name = 'model_name'", sql)
        self.assertIn("column_name = 'model_type_name'", sql)
        self.assertIn("ALTER TABLE static_results ADD COLUMN model_id VARCHAR(36) NULL", sql)
        self.assertIn("ALTER TABLE static_results ADD COLUMN model_name VARCHAR(255) NULL", sql)
        self.assertIn("ALTER TABLE static_results ADD COLUMN model_type_name VARCHAR(128) NULL", sql)

    def test_static_results_flutter_aot_feature_columns_have_idempotent_upgrade_sql(self) -> None:
        sql = MIGRATION_SQL.read_text(encoding="utf-8")

        self.assertIn("column_name = 'flutter_aot_opcode_4grams'", sql)
        self.assertIn("column_name = 'flutter_string_features'", sql)
        self.assertIn("column_name = 'flutter_primary_remote_service_urls'", sql)
        self.assertIn("column_name = 'flutter_primary_remote_service_domains'", sql)
        self.assertIn("ALTER TABLE static_results ADD COLUMN flutter_aot_opcode_4grams LONGTEXT NULL", sql)
        self.assertIn("ALTER TABLE static_results ADD COLUMN flutter_string_features JSON NULL", sql)
        self.assertIn("ALTER TABLE static_results ADD COLUMN flutter_primary_remote_service_urls JSON NULL", sql)
        self.assertIn("ALTER TABLE static_results ADD COLUMN flutter_primary_remote_service_domains JSON NULL", sql)
        self.assertIn("ALTER TABLE static_results MODIFY COLUMN flutter_aot_opcode_4grams LONGTEXT NULL", sql)
        removed_fields = [
            "flutter_" + "remote_" + suffix
            for suffix in ("service_urls", "service_domains")
        ]
        for field in removed_fields:
            with self.subTest(field=field):
                self.assertNotIn(field, sql)


if __name__ == "__main__":
    unittest.main()
