from __future__ import annotations

import unittest
from unittest.mock import patch

from repositories import device_repo
from schemas.device import DeviceItem


class DeviceRecoveryRepositoryTest(unittest.TestCase):
    @patch("repositories.device_recovery_repo.fetch_one")
    @patch("repositories.device_recovery_repo.execute", return_value=(1, 0))
    def test_claim_requires_idle_quarantined_device(self, execute_mock, fetch_one_mock) -> None:
        from repositories.device_recovery_repo import claim_quarantined_device

        fetch_one_mock.return_value = {"id": "device-1", "status": "recovering"}

        claimed = claim_quarantined_device("device-1")

        self.assertEqual(claimed, {"id": "device-1", "status": "recovering"})
        sql = execute_mock.call_args.args[0]
        self.assertIn("status = 'quarantined'", sql)
        self.assertIn("current_task_id IS NULL", sql)
        self.assertIn("status = 'recovering'", sql)
        self.assertIn("recovery_started_at = NOW()", sql)
        self.assertEqual(execute_mock.call_args.args[1], ("device-1",))
        self.assertEqual(fetch_one_mock.call_args.args[1], ("device-1",))

    @patch("repositories.device_recovery_repo.fetch_one")
    @patch("repositories.device_recovery_repo.execute", return_value=(0, 0))
    def test_claim_returns_none_unless_exactly_one_row_is_claimed(
        self,
        execute_mock,
        fetch_one_mock,
    ) -> None:
        from repositories.device_recovery_repo import claim_quarantined_device

        self.assertIsNone(claim_quarantined_device("device-1"))
        fetch_one_mock.assert_not_called()
        execute_mock.assert_called_once()

    @patch("repositories.device_recovery_repo.execute", return_value=(1, 0))
    def test_success_requires_recovering_and_clears_isolation(self, execute_mock) -> None:
        from repositories.device_recovery_repo import complete_device_recovery

        self.assertTrue(complete_device_recovery("device-1"))

        sql = execute_mock.call_args.args[0]
        self.assertIn("status = 'online'", sql)
        self.assertIn("status = 'recovering'", sql)
        self.assertIn("quarantine_reason = NULL", sql)
        self.assertIn("quarantined_at = NULL", sql)
        self.assertIn("quarantine_task_id = NULL", sql)
        self.assertIn("quarantine_package_name = NULL", sql)
        self.assertIn("recovery_started_at = NULL", sql)
        self.assertIn("recovery_error = NULL", sql)
        self.assertIn("last_recovery_at = NOW()", sql)
        self.assertIn("last_heartbeat_at = NOW()", sql)
        self.assertEqual(execute_mock.call_args.args[1], ("device-1",))

    @patch("repositories.device_recovery_repo.execute", return_value=(1, 0))
    def test_failure_requires_recovering_and_sets_error(self, execute_mock) -> None:
        from repositories.device_recovery_repo import fail_device_recovery

        self.assertTrue(fail_device_recovery("device-1", "reboot: timeout"))

        sql = execute_mock.call_args.args[0]
        self.assertIn("status = 'error'", sql)
        self.assertIn("status = 'recovering'", sql)
        self.assertIn("recovery_started_at = NULL", sql)
        self.assertIn("last_recovery_at = NOW()", sql)
        self.assertEqual(execute_mock.call_args.args[1], ("reboot: timeout", "device-1"))

    @patch("repositories.device_recovery_repo.execute", return_value=(2, 0))
    def test_stale_recovering_device_becomes_error(self, execute_mock) -> None:
        from repositories.device_recovery_repo import expire_stale_recoveries

        self.assertEqual(expire_stale_recoveries(600), 2)

        sql = execute_mock.call_args.args[0]
        self.assertIn("status = 'recovering'", sql)
        self.assertIn("status = 'error'", sql)
        self.assertIn("INTERVAL 600 SECOND", sql)
        self.assertIn("recovery process exceeded 600 seconds", execute_mock.call_args.args[1][0])

    @patch("repositories.device_recovery_repo.execute", return_value=(1, 0))
    def test_failure_error_is_clipped_to_2000_characters(self, execute_mock) -> None:
        from repositories.device_recovery_repo import fail_device_recovery

        fail_device_recovery("device-1", "x" * 2001)

        self.assertEqual(len(execute_mock.call_args.args[1][0]), 2000)

    @patch("repositories.device_recovery_repo.fetch_all", return_value=[])
    def test_list_only_returns_idle_quarantined_devices(self, fetch_all_mock) -> None:
        from repositories.device_recovery_repo import list_quarantined_devices

        self.assertEqual(list_quarantined_devices(2), [])

        sql = fetch_all_mock.call_args.args[0]
        self.assertIn("status = 'quarantined'", sql)
        self.assertIn("current_task_id IS NULL", sql)
        self.assertEqual(fetch_all_mock.call_args.args[1], (2,))


class DeviceProjectionRecoveryFieldsTest(unittest.TestCase):
    RECOVERY_FIELDS = (
        "quarantine_task_id",
        "quarantine_package_name",
        "recovery_started_at",
        "last_recovery_at",
        "recovery_error",
    )

    def test_device_item_exposes_recovery_fields(self) -> None:
        fields = DeviceItem.model_fields
        for field in self.RECOVERY_FIELDS:
            self.assertIn(field, fields)

    @patch("repositories.device_repo.fetch_one", return_value=None)
    def test_device_detail_projections_include_recovery_fields(self, fetch_one_mock) -> None:
        device_repo.get_device_by_id("device-1")
        by_id_sql = fetch_one_mock.call_args.args[0]
        device_repo.get_device_by_serial("serial-1")
        by_serial_sql = fetch_one_mock.call_args.args[0]

        for sql in (by_id_sql, by_serial_sql):
            for field in self.RECOVERY_FIELDS:
                self.assertIn(f"d.{field}", sql)

    @patch("repositories.device_repo.fetch_all", return_value=[])
    def test_device_list_projections_include_recovery_fields(self, fetch_all_mock) -> None:
        device_repo.list_devices()
        list_sql = fetch_all_mock.call_args.args[0]
        device_repo.get_available_devices()
        available_sql = fetch_all_mock.call_args.args[0]

        for field in self.RECOVERY_FIELDS:
            self.assertIn(field, list_sql)
            self.assertIn(field, available_sql)

    @patch("repositories.device_repo.execute", return_value=(1, 0))
    def test_new_device_initializes_recovery_fields(self, execute_mock) -> None:
        device_repo.create_device({"id": "device-1", "serial": "serial-1"})

        sql = execute_mock.call_args.args[0]
        for field in self.RECOVERY_FIELDS:
            self.assertIn(field, sql)
        self.assertEqual(execute_mock.call_args.args[1][-5:], (None, None, None, None, None))


if __name__ == "__main__":
    unittest.main()
