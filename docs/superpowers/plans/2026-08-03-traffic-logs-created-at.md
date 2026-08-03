# Traffic Logs Created Time Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a MySQL-generated `created_at` timestamp to the `traffic_logs` table without changing application queries or writes.

**Architecture:** Keep the change entirely in the idempotent SQL migration. The base table definition covers new databases, while an information-schema guarded `ALTER TABLE` upgrades existing databases safely.

**Tech Stack:** MySQL 8 SQL, Python `unittest`

## Global Constraints

- Define `created_at` as `DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP`.
- Do not modify traffic-log inserts, repository queries, APIs, reports, or frontend components.
- Existing rows may receive the migration execution time because their original insertion time is unavailable.

---

### Task 1: Add the traffic-log creation timestamp migration

**Files:**
- Create: `backend/tests/test_traffic_logs_migration.py`
- Modify: `backend/migrations/v1_init.sql:136`
- Modify: `backend/migrations/v1_init.sql:289`

**Interfaces:**
- Consumes: MySQL `CURRENT_TIMESTAMP` and `information_schema.columns`.
- Produces: `traffic_logs.created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP` for new and existing databases.

- [ ] **Step 1: Write the failing migration tests**

```python
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
            r"CREATE TABLE IF NOT EXISTS traffic_logs \\(.*?\\n\\) ENGINE=InnoDB",
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
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run: `cd backend && ./.venv/bin/python -m unittest tests.test_traffic_logs_migration -v`

Expected: both tests fail because `traffic_logs.created_at` and its compatibility migration do not exist.

- [ ] **Step 3: Add the base column and guarded compatibility migration**

Add this column to the `CREATE TABLE IF NOT EXISTS traffic_logs` definition after `is_real_controller`:

```sql
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
```

Add this compatibility block before the existing traffic-log IP-country upgrade:

```sql
-- Backward-compatible traffic_logs creation timestamp.
SET @traffic_logs_created_at_col := (
  SELECT COUNT(*)
  FROM information_schema.columns
  WHERE table_schema = DATABASE()
    AND table_name = 'traffic_logs'
    AND column_name = 'created_at'
);
SET @sql_traffic_logs_created_at_col := IF(
  @traffic_logs_created_at_col = 0,
  'ALTER TABLE traffic_logs ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP AFTER is_real_controller',
  'SELECT 1'
);
PREPARE stmt_traffic_logs_created_at_col FROM @sql_traffic_logs_created_at_col;
EXECUTE stmt_traffic_logs_created_at_col;
DEALLOCATE PREPARE stmt_traffic_logs_created_at_col;
```

- [ ] **Step 4: Run focused and regression tests**

Run: `cd backend && ./.venv/bin/python -m unittest tests.test_traffic_logs_migration -v`

Expected: 2 tests pass.

Run: `cd backend && ./.venv/bin/python -m unittest discover -s tests -p 'test_*.py'`

Expected: all backend tests pass.

- [ ] **Step 5: Check the diff and commit**

Run: `git diff --check`

Expected: no output.

```bash
git add backend/migrations/v1_init.sql backend/tests/test_traffic_logs_migration.py
git commit -m "feat: add traffic log creation timestamp"
```
