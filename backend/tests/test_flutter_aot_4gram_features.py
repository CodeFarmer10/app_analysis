import unittest
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from scripts.extract_unmatched_flutter_aot_4gram_features import (
    classify_strings,
    connected_similarity_families,
    jaccard_above_threshold,
    opcode_4gram_hashes,
)


class FlutterAot4GramFeaturesTest(unittest.TestCase):
    def test_classifies_raw_strings_and_filters_flutter_public_noise(self):
        categorized = classify_strings(
            [
                "https://api.example.com/v1/login",
                "/api/user/login",
                "package:dio/src/options.dart",
                "package:flutter/src/widgets/framework.dart",
                "登录成功",
                "deviceId",
                "access_token",
                "controller",
                "plain",
            ]
        )

        self.assertEqual(categorized["url"], ["https://api.example.com/v1/login"])
        self.assertEqual(categorized["api_route"], ["/api/user/login"])
        self.assertEqual(categorized["library_uri_like"], ["package:dio/src/options.dart"])
        self.assertEqual(categorized["chinese_text"], ["登录成功"])
        self.assertEqual(categorized["business_string"]["camelCase"], ["deviceId"])
        self.assertEqual(categorized["business_string"]["structured_key"], ["access_token"])
        flattened = str(categorized)
        self.assertNotIn("package:flutter/src/widgets/framework.dart", flattened)
        self.assertNotIn("controller", flattened)

    def test_opcode_4gram_hashes_are_unique_and_order_sensitive(self):
        first = opcode_4gram_hashes(["ldr", "add", "cmp", "b.eq", "ret", "ret"])
        second = opcode_4gram_hashes(["add", "ldr", "cmp", "b.eq", "ret", "ret"])

        self.assertEqual(len(first), 3)
        self.assertNotEqual(first, second)

    def test_connected_similarity_families_uses_transitive_edges_above_threshold(self):
        sets = {
            "a": {1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
            "b": {1, 2, 3, 4, 5, 6, 7, 8, 9},
            "c": {1, 2, 3, 4, 5, 6, 7, 8},
            "d": {100, 200, 300},
        }

        families, pairs = connected_similarity_families(sets, threshold=0.8)

        self.assertEqual(families, [["a", "b", "c"]])
        self.assertEqual(
            {frozenset((item["left"], item["right"])) for item in pairs},
            {frozenset(("a", "b")), frozenset(("b", "c"))},
        )

    def test_threshold_jaccard_is_strict_and_filters_size_ratio(self):
        self.assertIsNone(jaccard_above_threshold(set(range(9)), set(range(10)), 0.9))
        self.assertIsNone(jaccard_above_threshold(set(range(10)), set(range(12)), 0.9))
        self.assertAlmostEqual(jaccard_above_threshold(set(range(10)), set(range(9)), 0.8), 0.9)


if __name__ == "__main__":
    unittest.main()
