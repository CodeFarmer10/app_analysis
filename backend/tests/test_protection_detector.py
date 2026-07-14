from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from protection.detector import ApkidNotFound, run_apkid


class ProtectionDetectorTest(unittest.TestCase):
    def test_run_apkid_prefers_current_virtual_environment_binary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            bin_dir = Path(temp_dir, "bin")
            bin_dir.mkdir()
            python_bin = bin_dir / "python"
            apkid_bin = bin_dir / "apkid"
            python_bin.touch()
            apkid_bin.touch(mode=0o755)
            completed = subprocess.CompletedProcess(
                [],
                0,
                stdout=json.dumps({"files": []}),
                stderr="",
            )

            with patch("protection.detector.sys.executable", str(python_bin)):
                with patch("protection.detector.shutil.which", return_value="/usr/local/bin/apkid"):
                    with patch("protection.detector.os.path.exists", return_value=True):
                        with patch("protection.detector.subprocess.run", return_value=completed) as mocked_run:
                            result = run_apkid("/tmp/sample.apk")

        self.assertEqual(result, {"files": []})
        self.assertEqual(mocked_run.call_args.args[0], [str(apkid_bin), "-j", "/tmp/sample.apk"])

    def test_run_apkid_raises_when_no_executable_exists(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            python_bin = Path(temp_dir, "bin", "python")
            with patch("protection.detector.sys.executable", str(python_bin)):
                with patch("protection.detector.shutil.which", return_value=None):
                    with patch("protection.detector.os.path.exists", return_value=True):
                        with self.assertRaisesRegex(ApkidNotFound, "可执行文件"):
                            run_apkid("/tmp/sample.apk")


if __name__ == "__main__":
    unittest.main()
