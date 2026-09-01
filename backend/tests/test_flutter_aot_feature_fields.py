from __future__ import annotations

import unittest
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from analyzers.flutter_aot_features import classify_flutter_raw_strings


class FlutterAotFeatureFieldsTest(unittest.TestCase):
    def test_classifies_strings_and_filters_framework_url_domains(self) -> None:
        categorized = classify_flutter_raw_strings(
            [
                "https://api.flutter.dev/flutter/widgets/Widget-class.html",
                "https://flutter.dev/docs/release/breaking-changes/network-policy-ios-android",
                "https://dart.dev/guides",
                "https://api.example.com/v1/login",
                "https://notarealurl",
                "http://localhost:8080/debug",
                "/api/user/login",
                "package:flutter/src/widgets/framework.dart",
                "package:my_app/main.dart",
                "登录成功",
                "deviceId",
                "access_token",
            ]
        )

        self.assertEqual(categorized["url"], ["https://api.example.com/v1/login"])
        self.assertEqual(categorized["api_route"], ["/api/user/login"])
        self.assertEqual(categorized["library_uri_like"], ["package:my_app/main.dart"])
        self.assertEqual(categorized["chinese_text"], ["登录成功"])
        self.assertEqual(categorized["business_string"]["camelCase"], ["deviceId"])
        self.assertEqual(categorized["business_string"]["structured_key"], ["access_token"])
        flattened = str(categorized)
        self.assertNotIn("flutter.dev", flattened)
        self.assertNotIn("dart.dev", flattened)
        self.assertNotIn("package:flutter", flattened)


if __name__ == "__main__":
    unittest.main()
