from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from analyzers.java_source_index import JavaSourceIndex
from analyzers.sdk_detector import SdkDetectResult, detect_sdks, load_sdk_fingerprints


class SdkDetectorTest(unittest.TestCase):
    def test_default_fingerprints_load(self) -> None:
        fingerprints = load_sdk_fingerprints()
        self.assertEqual(
            [item.sdk_id for item in fingerprints],
            [
                "topon_anythink",
                "bugly",
                "jpush",
                "getui",
                "umeng",
                "dcloud",
                "meiqia",
                "openinstall",
            ],
        )

    def test_topon_extracts_all_named_groups_and_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as jadx_dir:
            Path(input_dir, "classes.dex").write_bytes(b"Lcom/anythink/core/api/ATSDK;")
            source = Path(jadx_dir, "sources", "app", "MainActivity.java")
            source.parent.mkdir(parents=True)
            source.write_text(
                'ATSDK.init(context, "toponAppId123", "toponAppKey456");\n'
                'setPlacementId("ABC123456789");\n',
                encoding="utf-8",
            )

            result = detect_sdks(input_dir, jadx_output_dir=jadx_dir)

        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding["sdk_id"], "topon_anythink")
        credentials = {(item["param_name"], item["value"]): item for item in finding["credentials"]}
        self.assertIn(("app_id", "toponAppId123"), credentials)
        self.assertIn(("app_key", "toponAppKey456"), credentials)
        self.assertIn(("placement_id", "ABC123456789"), credentials)
        app_id_occurrence = credentials[("app_id", "toponAppId123")]["occurrences"][0]
        self.assertEqual(len(credentials[("app_id", "toponAppId123")]["occurrences"]), 1)
        self.assertEqual(app_id_occurrence["source_file"], "sources/app/MainActivity.java")
        self.assertEqual(app_id_occurrence["line"], 1)
        self.assertIn("ATSDK.init", app_id_occurrence["evidence"])
        self.assertEqual(app_id_occurrence["extraction_method"], "java_call")

    def test_topon_resolves_static_final_string_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as jadx_dir:
            Path(input_dir, "classes.dex").write_bytes(b"Lcom/anythink/core/api/ATSDK;")
            caller = Path(jadx_dir, "sources", "j", "c", "a", "b0", "j.java")
            caller.parent.mkdir(parents=True)
            caller.write_text(
                """
package j.c.a.b0;
import com.anythink.core.api.ATSDK;
public class j {
    void init(Context context) {
        ATSDK.init(context, j.c.a.b0.h.a, j.c.a.b0.h.b);
    }
}
""".strip(),
                encoding="utf-8",
            )
            constants = Path(jadx_dir, "sources", "j", "c", "a", "b0", "h.java")
            constants.write_text(
                """
package j.c.a.b0;
public class h {
    public static final String a = "a68ac630fd6ea6";
    public static final String b = "a2409452986628bad21b5cbb44869613e";
}
""".strip(),
                encoding="utf-8",
            )
            unused = Path(jadx_dir, "sources", "unused", "Secrets.java")
            unused.parent.mkdir(parents=True)
            unused.write_text(
                'package unused; public class Secrets { static final String KEY = "unused"; }',
                encoding="utf-8",
            )

            indexed_sources: list[str] = []
            original_index_constants = JavaSourceIndex._index_constants

            def record_indexed_source(index, unit, text):
                indexed_sources.append(unit.source_file)
                return original_index_constants(index, unit, text)

            with patch.object(JavaSourceIndex, "_index_constants", new=record_indexed_source):
                result = detect_sdks(input_dir, jadx_output_dir=jadx_dir)

        finding = result.findings[0]
        credentials = {(item["param_name"], item["value"]): item for item in finding["credentials"]}
        self.assertIn(("app_id", "a68ac630fd6ea6"), credentials)
        self.assertIn(("app_key", "a2409452986628bad21b5cbb44869613e"), credentials)
        occurrence = credentials[("app_id", "a68ac630fd6ea6")]["occurrences"][0]
        self.assertEqual(occurrence["source_file"], "sources/j/c/a/b0/j.java")
        self.assertEqual(occurrence["definition_source_file"], "sources/j/c/a/b0/h.java")
        self.assertEqual(occurrence["definition_line"], 3)
        self.assertIn("static final String a", occurrence["definition_evidence"])
        self.assertIn("sources/j/c/a/b0/j.java", indexed_sources)
        self.assertIn("sources/j/c/a/b0/h.java", indexed_sources)
        self.assertNotIn("sources/unused/Secrets.java", indexed_sources)

    def test_scans_jadx_and_raw_apk_text_sources(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as jadx_dir:
            Path(input_dir, "classes.dex").write_bytes(b"Lcom/tencent/bugly/crashreport/CrashReport;")
            Path(input_dir, "raw-config.txt").write_text(
                'CrashReport.initCrashReport(context, "raw-app-id", false);',
                encoding="utf-8",
            )
            source = Path(jadx_dir, "sources", "app", "App.java")
            source.parent.mkdir(parents=True)
            source.write_text(
                'CrashReport.initCrashReport(context, "jadx-app-id", false);',
                encoding="utf-8",
            )

            result = detect_sdks(input_dir, jadx_output_dir=jadx_dir)

        credentials = {
            (item["param_name"], item["value"])
            for item in result.findings[0]["credentials"]
        }
        self.assertEqual(
            credentials,
            {("app_id", "jadx-app-id"), ("app_id", "raw-app-id")},
        )

    def test_manifest_credentials_for_jpush_and_umeng(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as jadx_dir:
            Path(input_dir, "classes.dex").write_bytes(
                b"Lcn/jpush/android/api/JPushInterface;Lcom/umeng/analytics/MobclickAgent;"
            )
            manifest = Path(jadx_dir, "resources", "AndroidManifest.xml")
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                '<meta-data android:name="JPUSH_APPKEY" android:value="jpush-key-001"/>\n'
                '<meta-data android:name="UMENG_APPKEY" android:value="umeng-key-002"/>\n',
                encoding="utf-8",
            )

            result = detect_sdks(input_dir, jadx_output_dir=jadx_dir)

        findings = {item["sdk_id"]: item for item in result.findings}
        self.assertEqual(set(findings), {"jpush", "umeng"})
        self.assertEqual(findings["jpush"]["credentials"][0]["value"], "jpush-key-001")
        self.assertEqual(findings["umeng"]["credentials"][0]["value"], "umeng-key-002")

    def test_bugly_init_extracts_app_id(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as jadx_dir:
            Path(input_dir, "classes.dex").write_bytes(b"Lcom/tencent/bugly/crashreport/CrashReport;")
            source = Path(jadx_dir, "sources", "app", "App.java")
            source.parent.mkdir(parents=True)
            source.write_text(
                'CrashReport.initCrashReport(context, "bugly-app-id", false);',
                encoding="utf-8",
            )

            result = detect_sdks(input_dir, jadx_output_dir=jadx_dir)

        self.assertEqual(result.findings[0]["sdk_id"], "bugly")
        self.assertEqual(result.findings[0]["credentials"][0]["value"], "bugly-app-id")

    def test_dcloud_extracts_packaged_app_id(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as jadx_dir:
            Path(input_dir, "classes.dex").write_bytes(b"Lio/dcloud/PandoraEntry;")
            control = Path(jadx_dir, "resources", "assets", "data", "dcloud_control.xml")
            control.parent.mkdir(parents=True)
            control.write_text(
                '<msc><apps><app appid="__UNI__A1B2C3D" appver=""/></apps></msc>',
                encoding="utf-8",
            )

            result = detect_sdks(input_dir, jadx_output_dir=jadx_dir)

        finding = result.findings[0]
        self.assertEqual(finding["sdk_id"], "dcloud")
        self.assertEqual(finding["credentials"][0]["param_name"], "app_id")
        self.assertEqual(finding["credentials"][0]["value"], "__UNI__A1B2C3D")
        self.assertEqual(
            finding["credentials"][0]["occurrences"][0]["source_file"],
            "resources/assets/data/dcloud_control.xml",
        )

    def test_meiqia_extracts_app_key(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as jadx_dir:
            Path(input_dir, "classes.dex").write_bytes(b"Lcom/meiqia/core/MQManager;")
            source = Path(jadx_dir, "sources", "app", "App.java")
            source.parent.mkdir(parents=True)
            source.write_text(
                'MQConfig.init(this, "meiqia-app-key", new OnInitCallback() {});\n'
                'new MQIntentBuilder(this).setScheduledAgent("agent-001").build();',
                encoding="utf-8",
            )

            result = detect_sdks(input_dir, jadx_output_dir=jadx_dir)

        finding = result.findings[0]
        self.assertEqual(finding["sdk_id"], "meiqia")
        credentials = {
            (item["param_name"], item["value"]) for item in finding["credentials"]
        }
        self.assertEqual(
            credentials,
            {("app_key", "meiqia-app-key"), ("agent_id", "agent-001")},
        )

    def test_getui_extracts_push_app_id(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as jadx_dir:
            Path(input_dir, "classes.dex").write_bytes(b"Lcom/igexin/sdk/PushManager;")
            manifest = Path(jadx_dir, "resources", "AndroidManifest.xml")
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                '<meta-data android:name="PUSH_APPID" android:value="getui-app-id"/>',
                encoding="utf-8",
            )

            result = detect_sdks(input_dir, jadx_output_dir=jadx_dir)

        finding = result.findings[0]
        self.assertEqual(finding["sdk_id"], "getui")
        self.assertEqual(finding["credentials"][0]["param_name"], "app_id")
        self.assertEqual(finding["credentials"][0]["value"], "getui-app-id")

    def test_openinstall_extracts_fenmiao_app_key(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as jadx_dir:
            Path(input_dir, "classes.dex").write_bytes(b"Lcom/fm/openinstall/OpenInstall;")
            manifest = Path(jadx_dir, "resources", "AndroidManifest.xml")
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                '<meta-data android:name="com.openinstall.APP_KEY" '
                'android:value="openinstall-app-key"/>',
                encoding="utf-8",
            )

            result = detect_sdks(input_dir, jadx_output_dir=jadx_dir)

        finding = result.findings[0]
        self.assertEqual(finding["sdk_id"], "openinstall")
        self.assertEqual(finding["credentials"][0]["param_name"], "app_key")
        self.assertEqual(finding["credentials"][0]["value"], "openinstall-app-key")

    def test_manifest_placeholders_are_not_reported_as_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as jadx_dir:
            Path(input_dir, "classes.dex").write_bytes(
                b"Lcom/igexin/sdk/PushManager;Lcom/fm/openinstall/OpenInstall;"
            )
            manifest = Path(jadx_dir, "resources", "AndroidManifest.xml")
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                '<meta-data android:name="PUSH_APPID" android:value="${GETUI_APPID}"/>\n'
                '<meta-data android:name="com.openinstall.APP_KEY" '
                'android:value="@string/openinstall_app_key"/>',
                encoding="utf-8",
            )

            result = detect_sdks(input_dir, jadx_output_dir=jadx_dir)

        findings = {item["sdk_id"]: item for item in result.findings}
        self.assertEqual(findings["getui"]["credentials"], [])
        self.assertEqual(findings["openinstall"]["credentials"], [])

    def test_parameter_regex_does_not_identify_sdk_without_package_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as jadx_dir:
            Path(input_dir, "classes.dex").write_bytes(b"Lcom/example/Main;")
            source = Path(jadx_dir, "sources", "app", "Main.java")
            source.parent.mkdir(parents=True)
            source.write_text('setPlacementId("ABC123456789");', encoding="utf-8")

            result = detect_sdks(input_dir, jadx_output_dir=jadx_dir)

        self.assertEqual(result.findings, [])

    def test_structured_call_ignores_commented_code(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as jadx_dir:
            Path(input_dir, "classes.dex").write_bytes(b"Lcom/anythink/core/api/ATSDK;")
            source = Path(jadx_dir, "sources", "app", "App.java")
            source.parent.mkdir(parents=True)
            source.write_text(
                """
public class App {
    public static final String APP_ID = "real-but-unused-id";
    // ATSDK.init(context, APP_ID, "commented-key");
}
""".strip(),
                encoding="utf-8",
            )

            result = detect_sdks(input_dir, jadx_output_dir=jadx_dir)

        self.assertEqual(result.findings[0]["credentials"], [])

    def test_package_prefix_requires_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir:
            Path(input_dir, "classes.dex").write_bytes(b"Lcom/umengfake/analytics/FakeAgent;")

            result = detect_sdks(input_dir)

        self.assertEqual(result.findings, [])

    def test_merge_deduplicates_credentials_and_combines_occurrences(self) -> None:
        base = {
            "sdk_id": "bugly",
            "sdk_name": "腾讯 Bugly",
            "sdk_type": "崩溃统计",
            "vendor": "腾讯",
            "matched_package_prefixes": ["com.tencent.bugly"],
            "recognition_evidence": [],
            "credentials": [
                {
                    "param_name": "app_id",
                    "value": "same-id",
                    "occurrences": [{"source_file": "classes.dex", "line": 1, "evidence": "one"}],
                }
            ],
        }
        second = {
            **base,
            "credentials": [
                {
                    "param_name": "app_id",
                    "value": "same-id",
                    "occurrences": [{"source_file": "sources/App.java", "line": 2, "evidence": "two"}],
                }
            ],
        }

        merged = SdkDetectResult([base]).merge(SdkDetectResult([second]))

        credentials = merged.findings[0]["credentials"]
        self.assertEqual(len(credentials), 1)
        self.assertEqual(len(credentials[0]["occurrences"]), 2)

    def test_invalid_fingerprint_regex_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir, "invalid.yaml")
            path.write_text(
                """
- sdk_id: invalid
  sdk_name: Invalid
  sdk_type: Test
  vendor: Test
  package_prefix: [com.example]
  param_regex:
    app_id:
      - '(?P<app_id>'
""".strip(),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "正则无效"):
                load_sdk_fingerprints(path)


if __name__ == "__main__":
    unittest.main()
