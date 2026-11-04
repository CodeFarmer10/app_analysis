from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from core.security import get_current_user
from main import app
from repositories import family_recommendation_repo


class FamilyRecommendationApiTest(unittest.TestCase):
    def setUp(self) -> None:
        app.dependency_overrides[get_current_user] = lambda: {"id": "admin-1", "role": "admin"}
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        app.dependency_overrides.clear()

    def test_list_and_detail_use_recommendation_routes(self) -> None:
        with (
            patch.object(family_recommendation_repo, "list_candidates", return_value=([{"id": "rec-1"}], 1)),
            patch.object(family_recommendation_repo, "get_candidate", return_value={"id": "rec-1", "rule": "x"}),
        ):
            listing = self.client.get("/api/families/recommendations")
            detail = self.client.get("/api/families/recommendations/rec-1")

        self.assertEqual(listing.status_code, 200)
        self.assertEqual(listing.json()["data"]["items"][0]["id"], "rec-1")
        self.assertEqual(detail.json()["data"]["rule"], "x")

    def test_approval_binds_model_to_candidate(self) -> None:
        with patch.object(family_recommendation_repo, "approve_candidate", return_value="model-1") as approve:
            response = self.client.post("/api/families/recommendations/rec-1/approve", json={
                "name": "家族甲", "description": "共性", "type_code": "1003",
            })

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["data"]["modelId"], "model-1")
        approve.assert_called_once_with("rec-1", "admin-1", "家族甲", "共性", "1003", "虚假投资")

    def test_non_admin_cannot_generate_or_approve(self) -> None:
        app.dependency_overrides[get_current_user] = lambda: {"id": "user-1", "role": "user"}
        self.assertEqual(self.client.post("/api/families/recommendations/generate").status_code, 403)
        self.assertEqual(self.client.post("/api/families/recommendations/rec-1/approve", json={
            "name": "家族甲", "type_code": "1003",
        }).status_code, 403)
        self.assertEqual(self.client.post("/api/families/recommendations/rec-1/reject").status_code, 403)

    def test普通用户可以读取推荐列表详情和成员(self) -> None:
        app.dependency_overrides[get_current_user] = lambda: {"id": "user-1", "role": "user"}
        with (
            patch.object(family_recommendation_repo, "list_candidates", return_value=([{"id": "rec-1"}], 1)),
            patch.object(family_recommendation_repo, "get_candidate", return_value={"id": "rec-1", "rule": "x"}),
            patch.object(family_recommendation_repo, "list_candidate_members", return_value=([{"id": "task-1"}], 1)),
        ):
            listing = self.client.get("/api/families/recommendations")
            detail = self.client.get("/api/families/recommendations/rec-1")
            members = self.client.get("/api/families/recommendations/rec-1/members")

        self.assertEqual(listing.status_code, 200)
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(members.status_code, 200)
        self.assertEqual(members.json()["data"]["items"][0]["id"], "task-1")


if __name__ == "__main__":
    unittest.main()
