from __future__ import annotations

import json
import unittest

from repositories.sdk_repo import flatten_sdk_finding, sdk_row_to_finding


class SdkRepositoryTest(unittest.TestCase):
    def test_flatten_sdk_finding_only_uses_first_array_items(self) -> None:
        finding = {
            "sdk_id": "example_sdk",
            "sdk_name": "Example SDK",
            "sdk_type": "测试",
            "vendor": "Example",
            "matched_package_prefixes": ["com.example.first", "com.example.second"],
            "recognition_evidence": [
                {"source_file": "classes.dex", "evidence": "first recognition"},
                {"source_file": "classes2.dex", "evidence": "second recognition"},
            ],
            "credentials": [
                {
                    "param_name": "app_id",
                    "value": "first-value",
                    "occurrences": [
                        {
                            "source_file": "sources/First.java",
                            "line": 12,
                            "evidence": "first credential evidence",
                        },
                        {
                            "source_file": "sources/Second.java",
                            "line": 24,
                            "evidence": "second credential evidence",
                        },
                    ],
                },
                {
                    "param_name": "app_key",
                    "value": "second-value",
                    "occurrences": [],
                },
            ],
        }

        row = flatten_sdk_finding("task-001", finding)

        self.assertEqual(row["package_prefix"], "com.example.first")
        self.assertEqual(row["source_file"], "classes.dex")
        self.assertEqual(row["evidence"], "first recognition")
        self.assertEqual(row["param_name"], "app_id")
        self.assertEqual(row["param_value"], "first-value")
        self.assertEqual(row["credential_source_file"], "sources/First.java")
        self.assertEqual(row["credential_line"], 12)
        self.assertEqual(row["credential_evidence"], "first credential evidence")
        self.assertEqual(row["raw_finding"], finding)

    def test_raw_finding_is_preferred_for_full_traceability(self) -> None:
        raw_finding = {
            "sdk_id": "example_sdk",
            "sdk_name": "Example SDK",
            "sdk_type": "测试",
            "vendor": "Example",
            "matched_package_prefixes": ["com.example.first", "com.example.second"],
            "recognition_evidence": [
                {"source_file": "classes.dex", "evidence": "first"},
                {"source_file": "classes2.dex", "evidence": "second"},
            ],
            "credentials": [
                {"param_name": "app_id", "value": "app-001", "occurrences": []},
                {"param_name": "app_key", "value": "key-002", "occurrences": []},
            ],
        }

        finding = sdk_row_to_finding(
            {
                "sdk_id": "flattened_fallback",
                "raw_finding": json.dumps(raw_finding, ensure_ascii=False),
            }
        )

        self.assertEqual(finding, raw_finding)
        self.assertEqual(len(finding["recognition_evidence"]), 2)
        self.assertEqual(len(finding["credentials"]), 2)

    def test_sdk_row_round_trip_builds_single_item_arrays(self) -> None:
        row = {
            "sdk_id": "example_sdk",
            "sdk_name": "Example SDK",
            "sdk_type": "测试",
            "vendor": "Example",
            "package_prefix": "com.example",
            "source_file": "classes.dex",
            "evidence": "package match",
            "param_name": "app_id",
            "param_value": "app-001",
            "credential_source_file": "sources/App.java",
            "credential_line": 9,
            "credential_evidence": "init app-001",
        }

        finding = sdk_row_to_finding(row)

        self.assertEqual(finding["matched_package_prefixes"], ["com.example"])
        self.assertEqual(
            finding["recognition_evidence"],
            [{"source_file": "classes.dex", "evidence": "package match"}],
        )
        self.assertEqual(len(finding["credentials"]), 1)
        credential = finding["credentials"][0]
        self.assertEqual((credential["param_name"], credential["value"]), ("app_id", "app-001"))
        self.assertEqual(
            credential["occurrences"],
            [
                {
                    "source_file": "sources/App.java",
                    "line": 9,
                    "evidence": "init app-001",
                }
            ],
        )

    def test_empty_nested_arrays_are_stored_as_null_columns(self) -> None:
        row = flatten_sdk_finding(
            "task-002",
            {
                "sdk_id": "empty_sdk",
                "sdk_name": "Empty SDK",
                "sdk_type": "测试",
                "vendor": "Example",
                "matched_package_prefixes": [],
                "recognition_evidence": [],
                "credentials": [],
            },
        )

        self.assertIsNone(row["package_prefix"])
        self.assertIsNone(row["source_file"])
        self.assertIsNone(row["evidence"])
        self.assertIsNone(row["param_name"])
        self.assertIsNone(row["param_value"])
        self.assertIsNone(row["credential_source_file"])
        self.assertIsNone(row["credential_line"])
        self.assertIsNone(row["credential_evidence"])


if __name__ == "__main__":
    unittest.main()
