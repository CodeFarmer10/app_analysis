from __future__ import annotations

import tempfile
import unittest
import zipfile
from contextlib import contextmanager
from pathlib import Path

from analyzers.framework_detector import detect_framework


ANDROID_NS = "http://schemas.android.com/apk/res/android"


def launcher_manifest(activity_name: str, include_launcher: bool = True, alias_target: str = "") -> bytes:
    intent = ""
    if include_launcher:
        intent = """<intent-filter>
          <action android:name="android.intent.action.MAIN" />
          <category android:name="android.intent.category.LAUNCHER" />
        </intent-filter>"""

    if alias_target:
        component = f"""<activity android:name="{alias_target}" />
        <activity-alias android:name=".LauncherAlias" android:targetActivity="{alias_target}">
          {intent}
        </activity-alias>"""
    else:
        component = f'<activity android:name="{activity_name}">{intent}</activity>'

    return f"""<manifest xmlns:android="{ANDROID_NS}" package="com.example.app">
      <application>{component}</application>
    </manifest>""".encode("utf-8")


@contextmanager
def synthetic_apk(entries):
    with tempfile.TemporaryDirectory() as temp_dir:
        apk_path = Path(temp_dir, "sample.apk")
        items = entries.items() if isinstance(entries, dict) else ((name, b"fixture") for name in entries)
        with zipfile.ZipFile(apk_path, "w") as archive:
            for name, content in items:
                archive.writestr(name, content)
        yield str(apk_path)


class FrameworkDetectorTest(unittest.TestCase):
    def test_flutter_requires_libapp_and_libflutter_in_the_same_abi(self) -> None:
        cases = [
            ["lib/arm64-v8a/libapp.so"],
            ["lib/arm64-v8a/libflutter.so"],
            ["assets/flutter_assets/AssetManifest.json"],
            ["lib/arm64-v8a/libapp.so", "lib/armeabi-v7a/libflutter.so"],
        ]

        for names in cases:
            with self.subTest(names=names), synthetic_apk(names) as apk_path:
                self.assertEqual(detect_framework(apk_path).primary, "原生 (Native Android)")

    def test_flutter_is_confirmed_when_any_abi_contains_both_libraries(self) -> None:
        names = [
            "lib/armeabi-v7a/libapp.so",
            "lib/arm64-v8a/libapp.so",
            "lib/arm64-v8a/libflutter.so",
        ]

        with synthetic_apk(names) as apk_path:
            result = detect_framework(apk_path)

        self.assertEqual(result.primary, "Flutter")
        self.assertEqual(result.matches[0].score, 2)

    def test_dcloud_direct_confirmation_accepts_required_www_resource(self) -> None:
        with synthetic_apk(["assets/apps/__UNI__A/www/index.html"]) as apk_path:
            self.assertEqual(detect_framework(apk_path).primary, "uni-app/DCloud")

    def test_dcloud_weak_evidence_does_not_confirm_without_launcher(self) -> None:
        cases = [
            ["assets/dcloud_control.xml"],
            ["assets/apps/__UNI__A/placeholder.txt"],
            ["lib/arm64-v8a/libweexcore.so"],
            ["classes.dex"],
        ]

        for names in cases:
            with self.subTest(names=names), synthetic_apk(names) as apk_path:
                self.assertEqual(detect_framework(apk_path).primary, "原生 (Native Android)")

    def test_dcloud_joint_confirmation_accepts_known_launcher_with_auxiliary(self) -> None:
        entries = {
            "AndroidManifest.xml": launcher_manifest("io.dcloud.PandoraEntry"),
            "assets/dcloud_control.xml": b"fixture",
        }

        with synthetic_apk(entries) as apk_path:
            result = detect_framework(apk_path)

        self.assertEqual(result.primary, "uni-app/DCloud")
        self.assertEqual(result.matches[0].score, 2)

    def test_dcloud_joint_confirmation_accepts_alias_targeting_known_launcher(self) -> None:
        entries = {
            "AndroidManifest.xml": launcher_manifest("", alias_target="io.dcloud.PandoraEntry"),
            "assets/dcloud_control.xml": b"fixture",
        }

        with synthetic_apk(entries) as apk_path:
            self.assertEqual(detect_framework(apk_path).primary, "uni-app/DCloud")


if __name__ == "__main__":
    unittest.main()
