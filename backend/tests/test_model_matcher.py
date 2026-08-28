from __future__ import annotations

import unittest

from analyzers.model_matcher import evaluate_model_expression, find_first_matching_model


class ModelMatcherTest(unittest.TestCase):
    def test_content_include_requires_all_values_and_supports_percent_wildcards(self) -> None:
        static_result = {
            "dcloud_pages": "pages/base/login,pages/base/forgot,pages/user/profile,pages/order/detail",
        }

        self.assertTrue(
            evaluate_model_expression(
                "content_include(dcloudPages,'pages/base/forgot,pages/base/%,%profile,pages/%/detail')",
                static_result,
            )
        )
        self.assertFalse(
            evaluate_model_expression(
                "content_include(dcloudPages,'pages/base/forgot,pages/missing/%')",
                static_result,
            )
        )

    def test_content_include_accepts_missing_closing_quote_before_parenthesis(self) -> None:
        static_result = {
            "components": "com.niming.foo.ui.Main,com.niming.foo.browser.Web,com.niming.foo.share.Share",
        }

        self.assertTrue(
            evaluate_model_expression(
                "content_include(components,'com.niming.%.ui%,com.niming.%.browser%,com.niming.%.share%)",
                static_result,
            )
        )

    def test_content_include_splits_components_on_whitespace(self) -> None:
        static_result = {
            "components": (
                "com.example.voip.VoIPActionsReceiver "
                "com.example.voip.VoIPMediaButtonReceiver "
                "com.example.AppStartReceiver "
                "com.example.AutoMessageHeardReceiver "
                "com.example.CustomTabsCopyReceiver "
                "com.example.PopupReplyReceiver "
                "com.example.ShareBroadcastReceiver "
                "com.example.WearReplyReceiver "
                "com.example.NotificationDismissReceiver"
            ),
        }

        self.assertTrue(
            evaluate_model_expression(
                "content_include(components,'%.voip.VoIPActionsReceiver,%.voip.VoIPMediaButtonReceiver,%.AppStartReceiver,%.AutoMessageHeardReceiver,%.CustomTabsCopyReceiver,%.PopupReplyReceiver,%.ShareBroadcastReceiver,%.WearReplyReceiver,%.NotificationDismissReceiver')",
                static_result,
            )
        )

    def test_keywords_contains_requires_minimum_regex_match_count(self) -> None:
        static_result = {
            "components": "com.a.LoginActivity,com.b.PayActivity,com.c.ProfileActivity",
        }

        self.assertTrue(
            evaluate_model_expression(
                r'keywords_contains(components, "Activity", 3)',
                static_result,
            )
        )
        self.assertFalse(
            evaluate_model_expression(
                r'keywords_contains(components, "Activity", 4)',
                static_result,
            )
        )

    def test_keywords_contains_normalizes_component_whitespace_to_commas_before_regex(self) -> None:
        static_result = {
            "components": "com.alpha.MainActivity com.alpha.ChatActivity com.alpha.PayActivity",
        }

        self.assertTrue(
            evaluate_model_expression(
                r'keywords_contains(components, "MainActivity,com\.alpha\.ChatActivity,com\.alpha\.PayActivity", 1)',
                static_result,
            )
        )

    def test_simple_boolean_expression_supports_and_or_but_not_mixed_logic(self) -> None:
        static_result = {
            "app_name": "澳门娱乐",
            "code_md5": "dedb1369e3f64726e3c0ccf8bf0ac285",
        }

        self.assertTrue(
            evaluate_model_expression(
                r"appName=~/(澳门|威尼斯|葡京|开元|赌场|棋牌|娱乐)/",
                static_result,
            )
        )
        self.assertTrue(
            evaluate_model_expression(
                "codeMd5=='dedb1369e3f64726e3c0ccf8bf0ac285' && appName=='澳门娱乐'",
                static_result,
            )
        )
        with self.assertLogs("analyzers.model_matcher", level="WARNING"):
            self.assertFalse(
                evaluate_model_expression(
                    "codeMd5=='missing' || appName=='澳门娱乐' && appName=='澳门'",
                    static_result,
                )
            )

    def test_find_first_matching_model_returns_first_ordered_match(self) -> None:
        static_result = {"app_name": "有钱花", "code_md5": "dedb1369e3f64726e3c0ccf8bf0ac285"}
        models = [
            {
                "model_id": "newer",
                "model_name": "最新模型",
                "model_type_name": "虚假贷款",
                "model_expression": "appName=='有钱花'",
            },
            {
                "model_id": "older",
                "model_name": "旧模型",
                "model_type_name": "虚假投资",
                "model_expression": "codeMd5=='dedb1369e3f64726e3c0ccf8bf0ac285'",
            },
        ]

        self.assertEqual(
            find_first_matching_model(static_result, models),
            {"model_id": "newer", "model_name": "最新模型", "model_type_name": "虚假贷款"},
        )


if __name__ == "__main__":
    unittest.main()
