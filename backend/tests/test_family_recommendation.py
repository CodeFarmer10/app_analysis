from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from analyzers.model_matcher import evaluate_model_expression
from services.family_cluster_reference import Family
from services.family_clustering import build_apps, cluster_candidates
from services.family_recommendation import ModelMetadata, generate_recommendations, parse_metadata_response
from repositories import family_recommendation_repo


def flutter_row(number: int, grams: range) -> dict:
    return {
        "task_id": f"task-{number}",
        "file_md5": f"{number:032x}",
        "app_name": f"App {number}",
        "package_name": f"example.app{number}",
        "framework_name": "Flutter",
        "flutter_aot_opcode_4grams": ",".join(str(value) for value in grams),
    }


class FamilyClusteringTest(unittest.TestCase):
    def test_metadata_response_accepts_json_code_fence(self) -> None:
        content = '''```json
{"model_name":"聊天家族","confidence":0.8,"evidence_summary":"共同静态特征","fraud_type_code":"1058","fraud_type":"聊天"}
```'''

        metadata = parse_metadata_response(content)

        self.assertEqual(metadata.name, "聊天家族")
        self.assertEqual(metadata.type_code, "1058")

    def test_flutter_complete_link_requires_every_pair_above_point_eight(self) -> None:
        rows = [flutter_row(number, range(10)) for number in range(4)]
        rows += [flutter_row(4, range(9)), flutter_row(5, range(8))]
        apps, _ = build_apps(rows)

        families = cluster_candidates(apps, rows)

        self.assertEqual(len(families), 1)
        self.assertEqual(len(families[0].members), 5)
        self.assertNotIn(5, families[0].members)
        self.assertGreater(families[0].min_pair_similarity, 0.8)
        for member_index in families[0].members:
            self.assertTrue(evaluate_model_expression(families[0].rule_expression, rows[member_index]))

    def test_flutter_four_members_are_not_recommended(self) -> None:
        rows = [flutter_row(number, range(10)) for number in range(4)]
        apps, _ = build_apps(rows)
        self.assertEqual(cluster_candidates(apps, rows), [])

    def test_dcloud_rule_matches_original_vue_page_values(self) -> None:
        pages = [
            "pages/home/index.vue", "pages/login/index.vue", "pages/user/index.vue",
            "pages/order/list.vue", "pages/order/detail.vue",
        ]
        rows = [{
            "task_id": f"dcloud-{number}",
            "file_md5": f"{number + 20:032x}",
            "framework_name": "uni-app/DCloud",
            "app_name": f"DCloud {number}",
            "dcloud_pages": ",".join(pages),
        } for number in range(5)]
        apps, _ = build_apps(rows)

        families = cluster_candidates(apps, rows)

        self.assertEqual(len(families), 1)
        self.assertTrue(all(evaluate_model_expression(families[0].rule_expression, row) for row in rows))

    def test_native_reference_algorithm_produces_matching_rule(self) -> None:
        common = "org.family.core.worker org.family.core.receiver org.family.core.service"
        rows = [{
            "task_id": f"native-{number}",
            "file_md5": f"{number + 100:032x}",
            "framework_name": "原生 (Native Android)",
            "app_name": f"Native {number}",
            "components": f"{common} org.family.unique{number}.entry" if number < 5 else f"org.unrelated{number}.only.worker",
        } for number in range(100)]
        apps, _ = build_apps(rows)

        families = cluster_candidates(apps, rows)

        self.assertEqual(len(families), 1)
        self.assertEqual(len(families[0].members), 5)
        self.assertTrue(all(evaluate_model_expression(families[0].rule_expression, rows[number]) for number in range(5)))

    def test_native_rule_matches_relative_component_names(self) -> None:
        components = (
            ".LoginActivity .emulator.EmuCardActivity "
            ".emulator.EmuHostApduService .reader.ReadCardActivity "
            "androidx.profileinstaller.ProfileInstallReceiver "
            "androidx.startup.InitializationProvider"
        )
        rows = [{
            "task_id": f"relative-{number}",
            "file_md5": f"{number + 200:032x}",
            "framework_name": "原生 (Native Android)",
            "app_name": f"Relative {number}",
            "package_name": "com.relay.nfcbridge",
            "components": components,
        } for number in range(5)]
        apps, _ = build_apps(rows)

        family = Family(
            family_id="relative-family",
            framework_name="原生 (Native Android)",
            strategy="native",
            stage="components",
            members=tuple(range(5)),
            fingerprints=(
                "F:com.relay.nfcbridge.LoginActivity",
                "F:com.relay.nfcbridge.emulator.EmuCardActivity",
                "F:androidx.startup.InitializationProvider",
            ),
        )

        with patch("services.family_clustering.native_components_v2_families", return_value=[family]):
            candidates = cluster_candidates(apps, rows)
        rule = candidates[0].rule_expression

        self.assertTrue(all(evaluate_model_expression(rule, row) for row in rows))

    def test_native_rule_matches_components_below_wildcard_package_head(self) -> None:
        rows = [{
            "task_id": f"head-{number}",
            "file_md5": f"{number + 300:032x}",
            "framework_name": "原生 (Native Android)",
            "app_name": f"Head {number}",
            "package_name": f"example.app{number}",
            "components": (
                "com.windbell.imsdk.contact.activity.ContactDetailActivity "
                "com.windbell.login.activity.LoginActivity"
            ),
        } for number in range(5)]
        apps, _ = build_apps(rows)
        family = Family(
            family_id="head-family",
            framework_name="原生 (Native Android)",
            strategy="native",
            stage="components",
            members=tuple(range(5)),
            fingerprints=("H:com.*.imsdk", "H:com.*.login"),
        )

        with patch("services.family_clustering.native_components_v2_families", return_value=[family]):
            candidates = cluster_candidates(apps, rows)

        self.assertTrue(all(evaluate_model_expression(candidates[0].rule_expression, row) for row in rows))

    def test_generation_keeps_task_ids_for_duplicate_md5(self) -> None:
        rows = [flutter_row(number, range(10)) for number in range(5)]
        duplicate = dict(rows[0], task_id="task-copy")
        rows.insert(1, duplicate)
        saved = []
        metadata = ModelMetadata("同源家族", 0.9, "共有指令结构", "1003", "虚假投资")
        with (
            patch.object(family_recommendation_repo, "load_unmatched_ga_apps", return_value=rows),
            patch.object(family_recommendation_repo, "save_candidate", side_effect=lambda candidate, task_ids: saved.append((candidate, task_ids)) or candidate["id"]),
        ):
            result = generate_recommendations(inferer=lambda family, members: metadata)

        self.assertEqual(result["eligibleApps"], 5)
        self.assertEqual(result["savedCandidates"], 1)
        self.assertEqual(set(saved[0][1]), {f"task-{number}" for number in range(5)} | {"task-copy"})
        self.assertEqual(saved[0][0]["status"], "pending")
        self.assertEqual(len(json.loads(saved[0][0]["fingerprints_json"])), 10)

    def test_failed_inference_retains_candidate_with_error(self) -> None:
        rows = [flutter_row(number, range(10)) for number in range(5)]
        saved = []
        with (
            patch.object(family_recommendation_repo, "load_unmatched_ga_apps", return_value=rows),
            patch.object(family_recommendation_repo, "save_candidate", side_effect=lambda candidate, task_ids: saved.append(candidate) or candidate["id"]),
        ):
            result = generate_recommendations(inferer=lambda family, members: (_ for _ in ()).throw(RuntimeError("LLM unavailable")))

        self.assertEqual(result["inferenceFailed"], 1)
        self.assertEqual(saved[0]["status"], "inference_failed")
        self.assertIn("LLM unavailable", saved[0]["failure_reason"])


if __name__ == "__main__":
    unittest.main()
