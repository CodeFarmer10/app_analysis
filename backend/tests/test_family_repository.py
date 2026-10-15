from __future__ import annotations

import sqlite3
import unittest
from unittest.mock import patch

from repositories import family_repo


class FamilyRepositoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.executescript(
            """
            CREATE TABLE models (
                model_id TEXT PRIMARY KEY, model_name TEXT, family_description TEXT,
                model_type_name TEXT, model_expression TEXT, status INTEGER, created_at TEXT
            );
            CREATE TABLE tasks (
                id TEXT PRIMARY KEY, user_id TEXT, file_md5 TEXT, status TEXT,
                source_type TEXT, source_name TEXT, task_description TEXT,
                priority INTEGER, apk_path TEXT, report_path TEXT, pcap_path TEXT,
                device_id TEXT, created_at TEXT, updated_at TEXT
            );
            CREATE TABLE static_results (
                task_id TEXT PRIMARY KEY, model_id TEXT, model_type_name TEXT,
                app_name TEXT, package_name TEXT, icon_path TEXT
            );
            CREATE TABLE devices (id TEXT PRIMARY KEY, serial TEXT);
            INSERT INTO models VALUES
              ('a', '甲家族', '真实简介', '虚假投资', 'very large rule', 1, '2026-01-01'),
              ('b', '乙家族', NULL, '色情', 'rule', 1, '2026-01-02'),
              ('c', '空家族', NULL, '虚假投资', 'rule', 1, '2026-01-03'),
              ('hidden', '停用家族', NULL, '色情', 'rule', 0, '2026-01-04');
            INSERT INTO tasks VALUES
              ('task-old', 'alice', 'aaa', 'completed', 'upload', 'a.apk', '', 1, NULL, NULL, NULL, NULL, '2026-02-01', '2026-02-01'),
              ('task-new', 'alice', 'bbb', 'completed', 'upload', 'b.apk', '', 1, NULL, NULL, NULL, NULL, '2026-03-01', '2026-03-01'),
              ('task-other', 'bob', 'ccc', 'completed', 'upload', 'c.apk', '', 1, NULL, NULL, NULL, NULL, '2026-04-01', '2026-04-01'),
              ('task-b', 'alice', 'ddd', 'completed', 'upload', 'd.apk', '', 1, NULL, NULL, NULL, NULL, '2026-01-15', '2026-01-15');
            INSERT INTO static_results VALUES
              ('task-old', 'a', '虚假投资', '甲旧', 'p.old', NULL),
              ('task-new', 'a', '虚假投资', '甲新', 'p.new', NULL),
              ('task-other', 'a', '虚假投资', '外部任务', 'p.other', NULL),
              ('task-b', 'b', '色情', '乙应用', 'p.b', NULL);
            """
        )
        self.fetch_all_patch = patch.object(family_repo, "fetch_all", side_effect=self.fetch_all)
        self.fetch_one_patch = patch.object(family_repo, "fetch_one", side_effect=self.fetch_one)
        self.fetch_all_patch.start()
        self.fetch_one_patch.start()

    def tearDown(self) -> None:
        self.fetch_all_patch.stop()
        self.fetch_one_patch.stop()
        self.db.close()

    def fetch_all(self, sql: str, params=()) -> list[dict]:
        return [dict(row) for row in self.db.execute(sql.replace("%s", "?"), params).fetchall()]

    def fetch_one(self, sql: str, params=()) -> dict | None:
        row = self.db.execute(sql.replace("%s", "?"), params).fetchone()
        return dict(row) if row else None

    def test_list_uses_real_model_links_and_scopes_counts_to_owner(self) -> None:
        items, total = family_repo.list_families(owner_user_id="alice", keyword=None, fraud_type=None, page=1, size=2)

        self.assertEqual(total, 3)
        self.assertEqual([item["id"] for item in items], ["a", "b"])
        self.assertEqual(items[0]["count"], 2)
        self.assertEqual(items[0]["latestTaskAt"], "2026-03-01")
        self.assertEqual(items[0]["description"], "真实简介")
        self.assertNotIn("model_expression", items[0])
        self.assertEqual(items[1]["count"], 1)

        admin_items, _ = family_repo.list_families(owner_user_id=None, keyword="甲", fraud_type="虚假投资", page=1, size=9)
        self.assertEqual([(item["id"], item["count"]) for item in admin_items], [("a", 3)])

    def test_detail_and_member_pages_never_expose_another_users_task(self) -> None:
        family = family_repo.get_family("a", owner_user_id="alice")
        first, total = family_repo.list_family_members("a", owner_user_id="alice", page=1, size=1)
        second, _ = family_repo.list_family_members("a", owner_user_id="alice", page=2, size=1)

        self.assertEqual((family["count"], family["latestTaskAt"]), (2, "2026-03-01"))
        self.assertEqual(total, 2)
        self.assertEqual([first[0]["id"], second[0]["id"]], ["task-new", "task-old"])
        self.assertIsNone(family_repo.get_family("hidden", owner_user_id=None))

    def test_list_orders_by_associated_task_count_before_recent_time(self) -> None:
        self.db.executescript(
            """
            INSERT INTO tasks (id, user_id, created_at) VALUES
              ('task-b-old-1', 'alice', '2026-01-10'),
              ('task-b-old-2', 'alice', '2026-01-11');
            INSERT INTO static_results (task_id, model_id) VALUES
              ('task-b-old-1', 'b'), ('task-b-old-2', 'b');
            """
        )

        items, total = family_repo.list_families(
            owner_user_id="alice", keyword=None, fraud_type=None, page=1, size=2
        )

        self.assertEqual(total, 3)
        self.assertEqual([(item["id"], item["count"]) for item in items], [("b", 3), ("a", 2)])


if __name__ == "__main__":
    unittest.main()
