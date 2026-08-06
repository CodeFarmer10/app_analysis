from __future__ import annotations

import unittest
from pathlib import Path

from androguard.core.apk import APK


HEALTH_APK = (
    Path(__file__).resolve().parents[1]
    / "tools"
    / "device_health"
    / "DeviceHealthCheck.apk"
)


class DeviceHealthApkTest(unittest.TestCase):
    def test_health_apk_is_minimal_and_has_expected_package(self) -> None:
        apk = APK(str(HEALTH_APK))

        self.assertEqual(apk.get_package(), "com.fraudanalysis.devicehealth")
        self.assertTrue(apk.is_signed_v2())
        self.assertEqual(apk.get_permissions(), [])
        self.assertEqual(apk.get_activities(), [])
        self.assertEqual(apk.get_services(), [])
        self.assertEqual(apk.get_receivers(), [])
        self.assertEqual(apk.get_providers(), [])
        self.assertFalse(any(name.endswith(".dex") for name in apk.get_files()))


if __name__ == "__main__":
    unittest.main()
