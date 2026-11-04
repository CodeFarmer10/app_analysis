from __future__ import annotations

import unittest
from pathlib import Path


class FamilyRecommendationMigrationTest(unittest.TestCase):
    def test_summary_table_and_static_result_link_are_idempotent(self):
        migration_dir = Path(__file__).resolve().parents[1] / "migrations"
        for filename in ("v1_init.sql", "v2_family_recommendations.sql"):
            sql = (migration_dir / filename).read_text(encoding="utf-8")
            with self.subTest(filename=filename):
                self.assertIn("CREATE TABLE IF NOT EXISTS family_recommendations", sql)
                self.assertIn("UNIQUE KEY uk_family_recommendations_key (family_key)", sql)
                self.assertIn("column_name = 'family_recommendation_id'", sql)
                self.assertIn("ALTER TABLE static_results ADD COLUMN family_recommendation_id VARCHAR(36) NULL", sql)
                self.assertIn("ALTER TABLE static_results ADD KEY idx_static_results_family_recommendation_id", sql)
                self.assertNotIn("CREATE TABLE IF NOT EXISTS family_recommendation_details", sql)


if __name__ == "__main__":
    unittest.main()
