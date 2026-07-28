from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from analyzers.dcloud_analyzer import analyze_dcloud_apk


class DCloudAnalyzerTest(unittest.TestCase):
    def test_extracts_uni_pages_api_service_urls_and_confusion(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            apk_path = Path(temp_dir, "sample.apk")
            app_config = """
var __uniConfig = {"pages":["pages/index/index","pages/user/profile"],"entryPagePath":"pages/index/index","tabBar":{"list":[{"pagePath":"pages/home/home"}]}};
var __uniRoutes = [{"path":"pages/order/detail"}];
uni.request({url:"https://api.example.com/api/user/login?token=1"});
axios.get("/api/order/list");
const mime = "/image/jpeg";
fetch("https://cdn.jsdelivr.net/npm/vue");
""".strip()
            manifest = '{"plus":{"confusion":{"resources":["app-service.js"]}}}'

            with zipfile.ZipFile(apk_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("assets/apps/__UNI__ABCD/www/app-config-service.js", app_config)
                archive.writestr("assets/apps/__UNI__ABCD/www/manifest.json", manifest)
                archive.writestr("assets/apps/__UNI__ABCD/www/app-confusion.js", "confused")

            result = analyze_dcloud_apk(str(apk_path)).to_static_field()

        self.assertEqual(result["tech_type"], "uni-app")
        self.assertEqual(result["appids"], ["__UNI__ABCD"])
        self.assertEqual(
            result["pages"],
            ["pages/index/index", "pages/user/profile", "pages/home/home", "pages/order/detail"],
        )
        self.assertIn("/api/user/login", result["api_routes"])
        self.assertIn("/api/order/list", result["api_routes"])
        self.assertNotIn("/image/jpeg", result["api_routes"])
        self.assertIn("https://api.example.com/api/user/login", result["remote_service_urls"])
        self.assertNotIn("cdn.jsdelivr.net", result["remote_service_domains"])
        self.assertTrue(result["is_confused"])
        self.assertTrue(result["is_obfuscated"])

    def test_classifies_h5_shell(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            apk_path = Path(temp_dir, "sample.apk")
            with zipfile.ZipFile(apk_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("assets/apps/H5APP/www/index.html", "<html></html>")

            result = analyze_dcloud_apk(str(apk_path)).to_static_field()

        self.assertEqual(result["tech_type"], "h5壳")
        self.assertEqual(result["appids"], ["H5APP"])


if __name__ == "__main__":
    unittest.main()
