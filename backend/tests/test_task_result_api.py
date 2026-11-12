from __future__ import annotations

import unittest
from datetime import datetime
from unittest.mock import patch

from fastapi.testclient import TestClient

from main import app
from repositories.task_repo import list_real_controller_traffic


class TaskResultApiTest(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(app)

    def tearDown(self) -> None:
        self.client.close()
        app.dependency_overrides.clear()

    def test_pending_task_has_null_result_without_token(self) -> None:
        with (
            patch("services.task_service.get_task_by_id", return_value={"id": "task-1", "status": "static_analyzing"}),
            patch("services.task_service.get_static_result") as static_result,
        ):
            response = self.client.get("/api/tasks/task-1/result")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["data"], {"status": "static_analyzing", "result": None})
        static_result.assert_not_called()

    def test_completed_task_returns_analysis_fields_without_token(self) -> None:
        task = {
            "id": "task-1", "status": "completed", "apk_path": "apk-object",
            "report_path": "report-object", "file_size": 12345,
            "file_md5": "a" * 32, "updated_at": datetime(2026, 11, 11, 12, 30),
        }
        static = {
            "app_name": "示例APP", "package_name": "com.example.app",
            "version_name": "1.2", "model_type_name": "虚假投资",
            "icon_path": "icon-object", "framework_name": "Flutter",
        }
        traffic = [
            {"domain": "c2.example", "src_ip": "192.168.1.2", "dst_ip": "8.8.8.8",
             "resolved_ip": "8.8.8.8", "src_port": 50000, "dst_port": 443, "is_up": 1},
            {"domain": "c2.example", "src_ip": "192.168.1.2", "dst_ip": "8.8.8.8",
             "resolved_ip": "8.8.8.8", "src_port": 50001, "dst_port": 443, "is_up": 1},
        ]
        with (
            patch("services.task_service.get_task_by_id", return_value=task),
            patch("services.task_service.get_static_result", return_value=static),
            patch("services.task_service.list_real_controller_traffic", return_value=traffic),
            patch("services.task_service.storage_service.get_download_url", side_effect=lambda value: f"https://files.example/{value}"),
        ):
            response = self.client.get("/api/tasks/task-1/result")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["data"], {
            "status": "completed",
            "result": {
                "appName": "示例APP", "downloadUrl": "https://files.example/apk-object",
                "size": 12345, "md5": "a" * 32, "packageName": "com.example.app",
                "version": "1.2", "controlList": [{"controlDomain": "c2.example", "controlIp": "8.8.8.8", "controlPort": 443}],
                "fraudType": "虚假投资", "analyseDate": "2026-11-11T12:30:00",
                "icon": "https://files.example/icon-object",
                "report": "https://files.example/report-object", "framework": "Flutter",
            },
        })

    def test_completed_task_keeps_missing_findings_explicit(self) -> None:
        with (
            patch("services.task_service.get_task_by_id", return_value={"id": "task-1", "status": "completed"}),
            patch("services.task_service.get_static_result", return_value={}),
            patch("services.task_service.list_real_controller_traffic", return_value=[]),
        ):
            response = self.client.get("/api/tasks/task-1/result")

        self.assertEqual(response.status_code, 200)
        result = response.json()["data"]["result"]
        self.assertNotIn("controlDomain", result)
        self.assertNotIn("controlIp", result)
        self.assertNotIn("controlPort", result)
        self.assertIsNone(result["fraudType"])
        self.assertIsNone(result["report"])
        self.assertEqual(result["controlList"], [])

    def test_missing_task_returns_404(self) -> None:
        with patch("services.task_service.get_task_by_id", return_value=None):
            response = self.client.get("/api/tasks/unknown/result")
        self.assertEqual(response.status_code, 404)

    def test_controller_query_includes_traffic_and_ecapture(self) -> None:
        with patch("repositories.task_repo.fetch_all", return_value=[]) as fetch:
            list_real_controller_traffic("task-1")

        sql = fetch.call_args.args[0]
        self.assertIn("FROM traffic_logs", sql)
        self.assertIn("FROM ecapture_logs", sql)
        self.assertEqual(sql.count("is_real_controller = 1"), 2)
        self.assertEqual(fetch.call_args.args[1], ("task-1", "task-1"))
