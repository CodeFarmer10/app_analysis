from __future__ import annotations

import unittest

from repositories.task_repo import (
    JSON_STATIC_RESULT_FIELDS,
    STATIC_RESULT_FIELDS,
    _serialize_static_value,
)


class TaskRepositoryStaticFieldsTest(unittest.TestCase):
    def test_renamed_static_storage_fields(self) -> None:
        self.assertIn("so_libraries", STATIC_RESULT_FIELDS)
        self.assertIn("components", STATIC_RESULT_FIELDS)
        self.assertIn("model_id", STATIC_RESULT_FIELDS)
        self.assertIn("model_name", STATIC_RESULT_FIELDS)
        self.assertIn("model_type_name", STATIC_RESULT_FIELDS)
        self.assertNotIn("so_files", STATIC_RESULT_FIELDS)
        self.assertNotIn("component_string", STATIC_RESULT_FIELDS)
        self.assertNotIn("so_libraries", JSON_STATIC_RESULT_FIELDS)
        self.assertNotIn("so_files", JSON_STATIC_RESULT_FIELDS)

    def test_multi_value_fields_are_stored_as_comma_separated_strings(self) -> None:
        expected_fields = {
            "so_libraries": ["lib/arm64-v8a/liba.so", "lib/armeabi-v7a/libb.so"],
            "dcloud_appids": ["appid-a", "appid-b"],
            "dcloud_pages": ["pages/index/index", "pages/login/login"],
            "dcloud_api_routes": ["/api/a", "/api/b"],
            "flutter_library_uris": ["package:a/main.dart", "package:b/feature.dart"],
            "flutter_primary_package_classes": ["AClass", "BClass"],
        }

        for field, raw_value in expected_fields.items():
            with self.subTest(field=field):
                self.assertNotIn(field, JSON_STATIC_RESULT_FIELDS)
                self.assertEqual(_serialize_static_value(field, raw_value), ",".join(raw_value))

    def test_missing_so_libraries_preserves_null(self) -> None:
        self.assertIsNone(_serialize_static_value("so_libraries", None))


if __name__ == "__main__":
    unittest.main()
