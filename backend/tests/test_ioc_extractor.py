from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from analyzers.ioc_extractor import extract_source_iocs


class IocExtractorTest(unittest.TestCase):
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
