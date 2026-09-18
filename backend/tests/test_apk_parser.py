from __future__ import annotations

import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from analyzers import apk_parser


NO_INDEX = 0xFFFFFFFF
ANDROID_NS = "http://schemas.android.com/apk/res/android"


def _string_pool(strings: list[str]) -> bytes:
    encoded: list[bytes] = []
    offsets: list[int] = []
    cursor = 0
    for item in strings:
        raw = item.encode("utf-16le")
        value = struct.pack("<H", len(item)) + raw + b"\x00\x00"
        offsets.append(cursor)
        encoded.append(value)
        cursor += len(value)

    header_size = 28
    strings_start = header_size + 4 * len(strings)
    body = b"".join(struct.pack("<I", item) for item in offsets) + b"".join(encoded)
    size = header_size + len(body)
    header = struct.pack(
        "<HHIIIIII",
        0x0001,
        header_size,
        size,
        len(strings),
        0,
        0,
        strings_start,
        0,
    )
    return header + body


def _start_element(tag_idx: int, attrs: list[tuple[int, int, int]]) -> bytes:
    attr_start = 20
    attr_size = 20
    header_size = 16
    ext = struct.pack(
        "<IIHHHHHH",
        NO_INDEX,
        tag_idx,
        attr_start,
        attr_size,
        len(attrs),
        0,
        0,
        0,
    )
    attr_bytes = b"".join(
        struct.pack("<IIIHBBI", namespace_idx, name_idx, value_idx, 8, 0, 0x03, value_idx)
        for namespace_idx, name_idx, value_idx in attrs
    )
    size = header_size + len(ext) + len(attr_bytes)
    header = struct.pack("<HHI", 0x0102, header_size, size) + struct.pack("<II", 0, 0)
    return header + ext + attr_bytes


def _fixture_manifest() -> bytes:
    strings = [
        ANDROID_NS,
        "manifest",
        "package",
        "com.example.app",
        "activity",
        "service",
        "receiver",
        "provider",
        "name",
        ".MainActivity",
        "SyncService",
        "com.other.PushReceiver",
        ".DataProvider",
    ]
    chunks = [
        _string_pool(strings),
        _start_element(1, [(NO_INDEX, 2, 3)]),
        _start_element(4, [(0, 8, 9)]),
        _start_element(5, [(0, 8, 10)]),
        _start_element(6, [(0, 8, 11)]),
        _start_element(7, [(0, 8, 12)]),
    ]
    body = b"".join(chunks)
    return struct.pack("<HHI", 0x0003, 8, 8 + len(body)) + body


class ApkParserTest(unittest.TestCase):
    def test_tolerant_axml_fallback_extracts_components(self) -> None:
        with self.subTest("synthetic obfuscated axml"), tempfile.TemporaryDirectory() as temp_dir:
            apk_path = Path(temp_dir) / "sample.apk"
            with zipfile.ZipFile(apk_path, "w") as archive:
                archive.writestr("AndroidManifest.xml", _fixture_manifest())

            result = apk_parser._parse_manifest_with_tolerant_axml(str(apk_path), None)

            self.assertEqual(result["package_name"], "com.example.app")
            self.assertEqual(
                result["activities"],
                [{"name": "com.example.app.MainActivity", "is_launcher": False}],
            )
            self.assertEqual(result["services"], ["com.example.app.SyncService"])
            self.assertEqual(result["_receivers"], ["com.other.PushReceiver"])
            self.assertEqual(result["providers"], ["com.example.app.DataProvider"])

    def test_parse_apk_uses_tolerant_axml_when_standard_parsers_have_no_components(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            apk_path = Path(temp_dir) / "sample.apk"
            with zipfile.ZipFile(apk_path, "w") as archive:
                archive.writestr("AndroidManifest.xml", _fixture_manifest())

            original_detect = apk_parser._detect_build_tool
            original_certs = apk_parser._extract_certificate_digests
            original_androguard = apk_parser._parse_with_androguard
            try:
                apk_parser._detect_build_tool = lambda _tool_name: None
                apk_parser._extract_certificate_digests = lambda *_args, **_kwargs: {}
                apk_parser._parse_with_androguard = lambda _path: (_ for _ in ()).throw(RuntimeError("boom"))

                result = apk_parser.parse_apk(str(apk_path))
            finally:
                apk_parser._detect_build_tool = original_detect
                apk_parser._extract_certificate_digests = original_certs
                apk_parser._parse_with_androguard = original_androguard

            self.assertEqual(result["package_name"], "com.example.app")
            self.assertEqual(result["app_name"], "com.example.app")
            self.assertEqual(result["activities"][0]["name"], "com.example.app.MainActivity")
            self.assertEqual(result["services"], ["com.example.app.SyncService"])
            self.assertIn(".MainActivity", result["component_string"])
            self.assertIn(".SyncService", result["component_string"])

    def test_parse_apk_tries_tolerant_axml_before_androguard_for_missing_components(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            apk_path = Path(temp_dir) / "sample.apk"
            with zipfile.ZipFile(apk_path, "w") as archive:
                archive.writestr("AndroidManifest.xml", _fixture_manifest())

            original_detect = apk_parser._detect_build_tool
            original_aapt2 = apk_parser._parse_with_aapt2
            original_certs = apk_parser._extract_certificate_digests
            original_androguard = apk_parser._parse_with_androguard
            androguard_calls = []
            try:
                apk_parser._detect_build_tool = lambda _tool_name: "/fake/aapt2"
                apk_parser._parse_with_aapt2 = lambda _path, _tool_path: {
                    "app_name": "Example",
                    "package_name": "com.example.app",
                    "permissions": [{"name": "android.permission.INTERNET", "is_dangerous": False}],
                    "activities": [],
                    "services": [],
                    "providers": [],
                    "_receivers": [],
                    "icon_bytes": b"\x89PNG\r\n\x1a\nfixture",
                }
                apk_parser._extract_certificate_digests = lambda *_args, **_kwargs: {}

                def fail_if_androguard_runs(_path):
                    androguard_calls.append(_path)
                    raise AssertionError("androguard should not run")

                apk_parser._parse_with_androguard = fail_if_androguard_runs

                result = apk_parser.parse_apk(str(apk_path))
            finally:
                apk_parser._detect_build_tool = original_detect
                apk_parser._parse_with_aapt2 = original_aapt2
                apk_parser._extract_certificate_digests = original_certs
                apk_parser._parse_with_androguard = original_androguard

            self.assertEqual(androguard_calls, [])
            self.assertEqual(result["activities"][0]["name"], "com.example.app.MainActivity")
            self.assertEqual(result["services"], ["com.example.app.SyncService"])


if __name__ == "__main__":
    unittest.main()
