from __future__ import annotations

import unittest

from schemas.task import TaskListResponse


class TaskSchemaTest(unittest.TestCase):
    def test_task_list_response_keeps_md5_and_model_type(self) -> None:
        response = TaskListResponse(
            items=[
                {
                    "id": "task-1",
                    "source_type": "apk_upload",
                    "source_name": "sample.apk",
                    "file_md5": "0123456789abcdef0123456789abcdef",
                    "model_type_name": "虚假投资",
                    "status": "completed",
                }
            ],
            total=1,
            page=1,
            size=20,
        ).model_dump()

        item = response["items"][0]
        self.assertEqual(item["file_md5"], "0123456789abcdef0123456789abcdef")
        self.assertEqual(item["model_type_name"], "虚假投资")


if __name__ == "__main__":
    unittest.main()
