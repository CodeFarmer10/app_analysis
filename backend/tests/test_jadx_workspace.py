from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from analyzers.jadx_workspace import open_jadx_workspace


class JadxWorkspaceTest(unittest.TestCase):
    def test_nonzero_exit_keeps_usable_partial_output(self) -> None:
        def fake_run(command, **_kwargs):
            output_dir = Path(command[command.index("-d") + 1])
            source = output_dir / "sources" / "app" / "App.java"
            source.parent.mkdir(parents=True)
            source.write_text("public class App {}", encoding="utf-8")
            return subprocess.CompletedProcess(command, 3, stdout="", stderr="21 errors")

        with tempfile.NamedTemporaryFile(suffix=".apk") as apk_file:
            with patch("analyzers.jadx_workspace.shutil.which", return_value="/usr/bin/jadx"):
                with patch("analyzers.jadx_workspace.subprocess.run", side_effect=fake_run):
                    with self.assertLogs("analyzers.jadx_workspace", level="WARNING") as captured:
                        with open_jadx_workspace(apk_file.name) as workspace:
                            self.assertEqual(workspace.return_code, 3)
                            self.assertIn("21 errors", workspace.warning or "")
                            self.assertTrue(Path(workspace.sources_dir, "app", "App.java").is_file())

        self.assertIn("部分反编译成功", "\n".join(captured.output))

    def test_nonzero_exit_without_output_raises(self) -> None:
        completed = subprocess.CompletedProcess(["jadx"], 1, stdout="", stderr="invalid apk")
        with tempfile.NamedTemporaryFile(suffix=".apk") as apk_file:
            with patch("analyzers.jadx_workspace.shutil.which", return_value="/usr/bin/jadx"):
                with patch("analyzers.jadx_workspace.subprocess.run", return_value=completed):
                    with self.assertRaisesRegex(RuntimeError, "invalid apk"):
                        with open_jadx_workspace(apk_file.name):
                            pass


if __name__ == "__main__":
    unittest.main()
