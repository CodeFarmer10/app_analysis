from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from analyzers.artifact_policy import MAX_TEXT_FILE_BYTES
from analyzers.ioc_extractor import SourceIocCollector, _iter_emails, extract_source_iocs


class IocExtractorTest(unittest.TestCase):
    def test_email_extraction_uses_32_character_windows(self) -> None:
        valid_local = "a" * 32
        valid_domain = f"{'b' * 28}.com"
        invalid_local = "c" * 33
        invalid_domain = f"{'d' * 29}.com"
        content = " ".join(
            [
                "normal.user@example.top",
                f"{valid_local}@{valid_domain}",
                f"{invalid_local}@example.top",
                f"normal.user@{invalid_domain}",
                "bad..local@example.top",
                "normal.user@-bad.top",
                "normal.user@bad..top",
                "normal.user@localhost",
                "percent%user@example.top",
            ]
        )
        collector = SourceIocCollector()
        collector.scan_blob("classes.dex", content.encode("ascii"))

        result = collector.build_result()

        self.assertEqual(
            {item.value for item in result.items["email"]},
            {"normal.user@example.top", f"{valid_local}@{valid_domain}"},
        )

    def test_email_extraction_excludes_percent_local_part(self) -> None:
        collector = SourceIocCollector()
        collector.scan_blob(
            "classes.dex",
            b"valid.user@example.top percent%user@example.top bad%@example.top",
        )

        result = collector.build_result()

        self.assertEqual(
            {item.value for item in result.items["email"]},
            {"valid.user@example.top"},
        )

    def test_email_extraction_skips_long_text_without_at_sign(self) -> None:
        self.assertEqual(list(_iter_emails("a" * 3_400_000)), [])

    def test_large_text_and_media_archive_entries_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            apk_path = Path(temp_dir, "sample.apk")
            with zipfile.ZipFile(apk_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(
                    "assets/large.txt",
                    b"x" * MAX_TEXT_FILE_BYTES + b" skipped.text@example.top",
                )
                archive.writestr(
                    "AndroidManifest.xml",
                    b"x" * MAX_TEXT_FILE_BYTES + b" skipped.manifest@example.top",
                )
                archive.writestr("res/drawable/proof.png", b"skipped.media@example.top")
                archive.writestr(
                    "classes.dex",
                    b"\x00" * (MAX_TEXT_FILE_BYTES + 1) + b" kept.binary@example.top",
                )

            result = extract_source_iocs(str(apk_path), is_packed=True)

        self.assertEqual(
            {item.value for item in result.items["email"]},
            {"kept.binary@example.top"},
        )

    def test_urls_require_valid_host_and_public_ip(self) -> None:
        content = " ".join(
            [
                "http://link",
                "http://localhost/path",
                "http://127.0.0.1/path",
                "http://10.0.0.8/path",
                "http://172.16.1.2/path",
                "http://192.168.1.2/path",
                "http://169.254.1.2/path",
                "http://[::1]/path",
                "https://1.12.12.180.76.7/path",
                "https://fraud-ioc-unit-test-7c91.top/api/v1",
                "https://8.8.8.8/dns-query",
            ]
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            apk_path = Path(temp_dir, "sample.bin")
            apk_path.write_text(content, encoding="ascii")

            result = extract_source_iocs(str(apk_path), is_packed=True)

        self.assertEqual(
            {item.value for item in result.items["url"]},
            {"https://fraud-ioc-unit-test-7c91.top/api/v1", "https://8.8.8.8/dns-query"},
        )

    def test_whitelisted_webrtc_domain_is_filtered(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            apk_path = Path(temp_dir, "libliteavsdk.so")
            apk_path.write_text(
                "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
                encoding="ascii",
            )

            result = extract_source_iocs(str(apk_path), is_packed=True)

        self.assertEqual(result.items["url"], [])


if __name__ == "__main__":
    unittest.main()
