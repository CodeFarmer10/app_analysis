from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from analyzers import source_artifact_scanner
from analyzers.artifact_policy import MAX_TEXT_FILE_BYTES


class SourceArtifactScannerTest(unittest.TestCase):
    def test_jadx_text_files_over_one_megabyte_are_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as jadx_dir:
            sources_root = Path(jadx_dir, "sources")
            small_source = sources_root / "app" / "Small.java"
            large_source = sources_root / "app" / "Large.java"
            large_resource = Path(jadx_dir, "resources", "assets", "large.js")
            small_source.parent.mkdir(parents=True)
            large_resource.parent.mkdir(parents=True)
            small_source.write_text("class Small {}", encoding="utf-8")
            large_source.write_bytes(b"x" * (MAX_TEXT_FILE_BYTES + 1))
            large_resource.write_bytes(b"x" * (MAX_TEXT_FILE_BYTES + 1))

            rows = list(
                source_artifact_scanner._iter_jadx_texts(
                    jadx_dir,
                    sources_root.resolve(),
                )
            )

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "sources/app/Small.java")
        self.assertEqual(rows[0][1], "app/Small.java")
        self.assertTrue(rows[0][3])

    def test_raw_and_jadx_artifacts_are_each_read_once_for_ioc_and_sdk(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as jadx_dir:
            suspicious_url = "https://scanner-unit-test-19f3.top/api"
            Path(input_dir, "classes.dex").write_bytes(
                (
                    "Lcom/tencent/bugly/crashreport/CrashReport;"
                    f" {suspicious_url}"
                ).encode("ascii")
            )
            source = Path(jadx_dir, "sources", "app", "App.java")
            source.parent.mkdir(parents=True)
            source.write_text(
                f'// {suspicious_url}\nCrashReport.initCrashReport(context, "bugly-id", false);',
                encoding="utf-8",
            )

            raw_passes: list[str] = []
            source_reads: list[Path] = []
            original_blob_iterator = source_artifact_scanner.iter_artifact_blobs
            original_source_reader = source_artifact_scanner._read_source_text

            def tracked_blobs(path: str):
                raw_passes.append(path)
                yield from original_blob_iterator(path)

            def tracked_source_read(path: Path) -> str:
                source_reads.append(path)
                return original_source_reader(path)

            with (
                patch.object(source_artifact_scanner, "iter_artifact_blobs", side_effect=tracked_blobs),
                patch.object(source_artifact_scanner, "_read_source_text", side_effect=tracked_source_read),
            ):
                result = source_artifact_scanner.scan_source_artifacts(
                    input_dir,
                    is_packed=False,
                    jadx_output_dir=jadx_dir,
                    jadx_sources_dir=str(Path(jadx_dir, "sources")),
                )

        self.assertEqual(raw_passes, [input_dir])
        self.assertEqual(source_reads, [source.resolve()])
        self.assertEqual(result.iocs.items["url"][0].value, suspicious_url)
        self.assertEqual(result.iocs.items["url"][0].sources, ["app/App.java"])
        self.assertEqual(result.sdks.findings[0]["sdk_id"], "bugly")
        self.assertEqual(result.sdks.findings[0]["credentials"][0]["value"], "bugly-id")


if __name__ == "__main__":
    unittest.main()
