from __future__ import annotations

import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from core.security import create_access_token
from main import app


class PublicTaskSubmissionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        app.dependency_overrides.clear()

    def test_upload_accepts_request_without_token_as_anonymous(self) -> None:
        with patch("api.tasks.create_upload_tasks", return_value=("batch-1", [])) as create:
            response = self.client.post(
                "/api/tasks/upload",
                files={"files": ("sample.apk", b"apk", "application/vnd.android.package-archive")},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["data"]["batch_id"], "batch-1")
        self.assertIsNone(create.call_args.args[1])

    def test_url_accepts_request_without_token_as_anonymous(self) -> None:
        item = {"url": "https://example.com/sample.apk", "success": True, "task_id": "task-2", "status": "downloading"}
        with patch("api.tasks.create_url_tasks", return_value=("batch-2", [item])) as create:
            response = self.client.post(
                "/api/tasks/url", json={"urls": ["https://example.com/sample.apk"]}
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["data"], {"batch_id": "batch-2", "items": [item], "total": 1})
        self.assertIsNone(create.call_args.args[1])

    def test_url_keeps_owner_when_valid_token_is_supplied(self) -> None:
        token = create_access_token("user-1")
        with (
            patch("core.security.get_user_by_id", return_value={"id": "user-1", "role": "user"}),
            patch("api.tasks.create_url_tasks", return_value=("batch-3", [])) as create,
        ):
            response = self.client.post(
                "/api/tasks/url",
                headers={"Authorization": f"Bearer {token}"},
                json={"urls": ["https://example.com/sample.apk"]},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["data"]["batch_id"], "batch-3")
        self.assertEqual(create.call_args.args[1], "user-1")
