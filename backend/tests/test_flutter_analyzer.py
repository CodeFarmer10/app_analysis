from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from analyzers.flutter_blutter_runner import run_flutter_blutter
from analyzers.flutter_analyzer import analyze_flutter_asm_dir, resolve_flutter_asm_dir
from workers import static_analysis


class FlutterAnalyzerTest(unittest.TestCase):
    def test_extracts_primary_package_library_uris_and_classes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            asm_dir = Path(temp_dir, "abc123", "asm")
            main = asm_dir / "app" / "main.dart"
            main.parent.mkdir(parents=True)
            main.write_text(
                """
// lib: , url: package:fraud_app/main.dart
class MyRootApp extends StatelessWidget {
  Widget build(BuildContext context) {
    r0 = AllocateMaterialAppStub -> MaterialApp
  }
}
  static void main() {
    r1 = AllocateMyRootAppStub -> MyRootApp
    r2 = runApp()
  }
""".lstrip(),
                encoding="utf-8",
            )
            page = asm_dir / "app" / "pages" / "login.dart"
            page.parent.mkdir(parents=True)
            page.write_text(
                """
// lib: , url: package:fraud_app/pages/login.dart
class LoginPage extends StatefulWidget {
  LoginState createState() {
    r0 = AllocateLoginStateStub -> LoginState
  }
}
class LoginState extends State<LoginPage> {
  Widget build(BuildContext context) {
    final api = "https://api.fraud.example.com/v1/login";
    final domain = "data.fraud.example.net:8443";
    final ip = "10.0.0.8:9000";
  }
}
""".lstrip(),
                encoding="utf-8",
            )
            sdk = asm_dir / "dio.dart"
            sdk.write_text(
                """
// lib: , url: package:dio/src/dio.dart
class Dio {
  static const endpoint = "https://sdk.example.com/collect";
}
""".lstrip(),
                encoding="utf-8",
            )

            result = analyze_flutter_asm_dir(asm_dir).to_static_field()

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["primary_package"], "fraud_app")
        self.assertEqual(result["primary_entry_uri"], "package:fraud_app/main.dart")
        self.assertEqual(result["primary_entry_confidence"], "high")
        self.assertEqual(result["root_widget_class"], "MyRootApp")
        self.assertEqual(
            result["library_uris"],
            ["package:fraud_app/main.dart", "package:fraud_app/pages/login.dart"],
        )
        self.assertEqual(
            result["primary_package_classes"],
            ["LoginPage", "LoginState", "MyRootApp"],
        )
        self.assertEqual(
            result["remote_service_urls"],
            ["https://api.fraud.example.com/v1/login", "https://sdk.example.com/collect"],
        )
        self.assertEqual(
            result["remote_service_domains"],
            ["api.fraud.example.com", "data.fraud.example.net:8443", "sdk.example.com"],
        )
        self.assertEqual(result["primary_remote_service_urls"], ["https://api.fraud.example.com/v1/login"])
        self.assertEqual(result["primary_remote_service_domains"], ["api.fraud.example.com", "data.fraud.example.net:8443"])

    def test_resolves_configured_md5_asm_dir(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            md5 = "0123456789abcdef0123456789abcdef"
            asm_dir = Path(temp_dir, md5, "asm")
            asm_dir.mkdir(parents=True)

            found, candidates = resolve_flutter_asm_dir(md5, [temp_dir])

        self.assertEqual(found, asm_dir)
        self.assertIn(str(asm_dir), candidates)

    def test_runs_blutter_into_md5_output_dir(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            apk_path = root / "sample.apk"
            with zipfile.ZipFile(apk_path, "w") as archive:
                archive.writestr("lib/arm64-v8a/libapp.so", b"app")
                archive.writestr("lib/arm64-v8a/libflutter.so", b"flutter")

            tool_root = root / "tools" / "blutter"
            tool_root.mkdir(parents=True)
            (tool_root / "extract_dart_info.py").write_text(
                """
def extract_dart_info(libapp_file, libflutter_file):
    return "3.10.4", "snapshot", ["compressed-pointers"], "arm64", "android"
""".lstrip(),
                encoding="utf-8",
            )
            (tool_root / "blutter.py").write_text(
                """
import pathlib
import sys

out = pathlib.Path(sys.argv[2])
(out / "asm" / "demo").mkdir(parents=True, exist_ok=True)
(out / "asm" / "demo" / "main.dart").write_text("// lib: , url: package:demo/main.dart\\n", encoding="utf-8")
(out / "pp.txt").write_text("ok", encoding="utf-8")
""".lstrip(),
                encoding="utf-8",
            )
            output_root = root / "outputs"
            md5 = "abcdef0123456789abcdef0123456789"

            result = run_flutter_blutter(
                apk_path,
                md5,
                tool_root=tool_root,
                output_root=output_root,
                timeout_seconds=10,
            )

            self.assertEqual(result.status, "complete")
            self.assertEqual(Path(result.asm_dir), output_root / md5 / "asm")
            self.assertEqual(result.dart_version, "3.10.4")
            self.assertEqual(result.backend_match, "build_required")
            self.assertTrue((output_root / md5 / "asm" / "demo" / "main.dart").is_file())

    def test_uses_nearest_compatible_backend_when_exact_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            apk_path = root / "sample.apk"
            with zipfile.ZipFile(apk_path, "w") as archive:
                archive.writestr("lib/arm64-v8a/libapp.so", b"app")
                archive.writestr("lib/arm64-v8a/libflutter.so", b"flutter")

            tool_root = root / "tools" / "blutter"
            (tool_root / "bin").mkdir(parents=True)
            (tool_root / "bin" / "blutter_dartvm3.12.0_android_arm64").write_text("", encoding="utf-8")
            (tool_root / "bin" / "blutter_dartvm3.8.1_android_arm64").write_text("", encoding="utf-8")
            (tool_root / "extract_dart_info.py").write_text(
                """
def extract_dart_info(libapp_file, libflutter_file):
    return "3.13.0", "snapshot", ["compressed-pointers"], "arm64", "android"
""".lstrip(),
                encoding="utf-8",
            )
            (tool_root / "blutter.py").write_text(
                """
import pathlib
import sys

pathlib.Path(sys.argv[2], "args.txt").write_text("\\n".join(sys.argv[1:]), encoding="utf-8")
out = pathlib.Path(sys.argv[2])
(out / "asm").mkdir(parents=True, exist_ok=True)
(out / "pp.txt").write_text("ok", encoding="utf-8")
""".lstrip(),
                encoding="utf-8",
            )
            output_root = root / "outputs"
            md5 = "abcdef0123456789abcdef0123456789"

            result = run_flutter_blutter(
                apk_path,
                md5,
                tool_root=tool_root,
                output_root=output_root,
                timeout_seconds=10,
            )

            args_text = (output_root / md5 / "args.txt").read_text(encoding="utf-8")
            self.assertEqual(result.status, "complete")
            self.assertEqual(result.backend_match, "compatible")
            self.assertEqual(result.backend_version, "3.12.0")
            self.assertIn("--dart-version\n3.12.0_android_arm64", args_text)

    def test_builds_exact_backend_after_compatible_backend_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            apk_path = root / "sample.apk"
            with zipfile.ZipFile(apk_path, "w") as archive:
                archive.writestr("lib/arm64-v8a/libapp.so", b"app")
                archive.writestr("lib/arm64-v8a/libflutter.so", b"flutter")

            tool_root = root / "tools" / "blutter"
            (tool_root / "bin").mkdir(parents=True)
            (tool_root / "bin" / "blutter_dartvm3.12.0_android_arm64").write_text("", encoding="utf-8")
            (tool_root / "extract_dart_info.py").write_text(
                """
def extract_dart_info(libapp_file, libflutter_file):
    return "3.12.1", "app-snapshot", ["compressed-pointers"], "arm64", "android"
""".lstrip(),
                encoding="utf-8",
            )
            (tool_root / "blutter.py").write_text(
                """
import pathlib
import sys

tool_root = pathlib.Path(__file__).parent
with (tool_root / "calls.txt").open("a", encoding="utf-8") as call_log:
    call_log.write("\\n".join(sys.argv[1:]) + "\\n---\\n")

if "--dart-version" in sys.argv:
    raise SystemExit(7)

out = pathlib.Path(sys.argv[2])
(tool_root / "bin" / "blutter_dartvm3.12.1_android_arm64").write_text("built", encoding="utf-8")
(out / "asm").mkdir(parents=True, exist_ok=True)
(out / "pp.txt").write_text("ok", encoding="utf-8")
""".lstrip(),
                encoding="utf-8",
            )
            output_root = root / "outputs"
            md5 = "abcdef0123456789abcdef0123456789"

            result = run_flutter_blutter(
                apk_path,
                md5,
                tool_root=tool_root,
                output_root=output_root,
                timeout_seconds=10,
            )

            calls = (tool_root / "calls.txt").read_text(encoding="utf-8").split("\n---\n")
            self.assertEqual(result.status, "complete")
            self.assertEqual(result.backend_match, "build_required")
            self.assertEqual(result.backend_version, "3.12.1")
            self.assertNotIn("--dart-version", result.command)
            self.assertIn("--dart-version\n3.12.0_android_arm64", calls[0])
            self.assertNotIn("--dart-version", calls[1])
            self.assertTrue((tool_root / "bin" / "blutter_dartvm3.12.1_android_arm64").is_file())

    def test_static_flutter_extraction_removes_generated_md5_dir(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            apk_path = root / "sample.apk"
            with zipfile.ZipFile(apk_path, "w") as archive:
                archive.writestr("lib/arm64-v8a/libapp.so", b"app")
                archive.writestr("lib/arm64-v8a/libflutter.so", b"flutter")

            tool_root = root / "tools" / "blutter"
            tool_root.mkdir(parents=True)
            (tool_root / "extract_dart_info.py").write_text(
                """
def extract_dart_info(libapp_file, libflutter_file):
    return "3.10.4", "snapshot", ["compressed-pointers"], "arm64", "android"
""".lstrip(),
                encoding="utf-8",
            )
            (tool_root / "blutter.py").write_text(
                """
import pathlib
import sys

out = pathlib.Path(sys.argv[2])
(out / "asm" / "demo").mkdir(parents=True, exist_ok=True)
(out / "asm" / "demo" / "main.dart").write_text(
    '''
// lib: , url: package:demo/main.dart
class DemoApp extends StatelessWidget {
  Widget build(BuildContext context) {
    r0 = AllocateMaterialAppStub -> MaterialApp
  }
}
  static void main() {
    r1 = AllocateDemoAppStub -> DemoApp
    r2 = runApp()
  }
'''.lstrip(),
    encoding="utf-8",
)
(out / "pp.txt").write_text("ok", encoding="utf-8")
""".lstrip(),
                encoding="utf-8",
            )
            output_root = root / "outputs"
            md5 = "abcdef0123456789abcdef0123456789"

            original_tool_root = static_analysis.settings.FLUTTER_BLUTTER_TOOL_ROOT
            original_output_root = static_analysis.settings.FLUTTER_BLUTTER_OUTPUT_ROOT
            original_enabled = static_analysis.settings.FLUTTER_BLUTTER_ENABLED
            static_analysis.settings.FLUTTER_BLUTTER_TOOL_ROOT = str(tool_root)
            static_analysis.settings.FLUTTER_BLUTTER_OUTPUT_ROOT = str(output_root)
            static_analysis.settings.FLUTTER_BLUTTER_ENABLED = True
            try:
                result = static_analysis._extract_flutter_fields(str(apk_path), md5, "Flutter")
            finally:
                static_analysis.settings.FLUTTER_BLUTTER_TOOL_ROOT = original_tool_root
                static_analysis.settings.FLUTTER_BLUTTER_OUTPUT_ROOT = original_output_root
                static_analysis.settings.FLUTTER_BLUTTER_ENABLED = original_enabled

            self.assertEqual(result["flutter_primary_package"], "demo")
            self.assertFalse((output_root / md5).exists())


if __name__ == "__main__":
    unittest.main()
