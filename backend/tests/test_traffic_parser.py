from __future__ import annotations

import unittest
from unittest.mock import patch

from phone_agent.traffic_parser import TrafficParser


class TrafficParserTsharkCheckTest(unittest.TestCase):
    def test_tshark_check_uses_path_lookup_without_version_probe(self) -> None:
        parser = TrafficParser("tshark")

        with (
            patch("phone_agent.traffic_parser.shutil.which", return_value="/usr/bin/tshark") as which_mock,
            patch("phone_agent.traffic_parser.subprocess.run") as run_mock,
        ):
            self.assertTrue(parser._check_tshark())

        which_mock.assert_called_once_with("tshark")
        run_mock.assert_not_called()

    def test_tshark_check_distinguishes_missing_binary(self) -> None:
        parser = TrafficParser("missing-tshark")

        with patch("phone_agent.traffic_parser.shutil.which", return_value=None):
            with self.assertRaises(RuntimeError) as raised:
                list(parser.parse_pcap_stream("/tmp/capture.pcap"))

        self.assertIn("tshark executable not found", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
