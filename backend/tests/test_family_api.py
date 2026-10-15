from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from core.security import get_current_user
from main import app
from repositories import family_repo


class FamilyApiTest(unittest.TestCase):
    def setUp(self) -> None:
        app.dependency_overrides[get_current_user] = lambda: {"id": "alice", "role": "analyst"}
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        app.dependency_overrides.clear()

    def test_list_returns_only_owner_scoped_counts(self) -> None:
        def fake_list(owner_user_id, keyword, fraud_type, page, size):
            if owner_user_id != "alice":
                return [{"id": "a", "count": 99}], 1
            return [{"id": "a", "name": "甲家族", "description": None,
                     "type": "虚假投资", "count": 2, "latestTaskAt": "2026-03-01"}], 1

        with patch.object(family_repo, "list_families", side_effect=fake_list):
            response = self.client.get("/api/families?page=1&size=9")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["data"]["items"][0]["count"], 2)
        self.assertEqual(response.json()["data"]["total"], 1)

    def test_detail_returns_404_for_missing_model(self) -> None:
        with patch.object(family_repo, "get_family", return_value=None):
            response = self.client.get("/api/families/missing")

        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.json()["message"], "家族不存在")

    def test_members_reuse_real_task_ids(self) -> None:
        with (
            patch.object(family_repo, "get_family", return_value={"id": "a", "name": "甲家族"}),
            patch.object(family_repo, "list_family_members", return_value=([{
                "id": "task-real", "app_name": "甲应用", "file_md5": "abc",
                "model_type_name": "虚假投资", "icon_path": None,
                "apk_path": None, "report_path": None, "pcap_path": None,
            }], 1)),
        ):
            response = self.client.get("/api/families/a/members?page=1&size=20")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["data"]["items"][0]["id"], "task-real")
        self.assertEqual(response.json()["data"]["items"][0]["can_download_apk"], False)
        self.assertNotIn("apk_path", response.json()["data"]["items"][0])
        self.assertEqual(response.json()["data"]["total"], 1)


if __name__ == "__main__":
    unittest.main()
