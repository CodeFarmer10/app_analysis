from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from workers.scheduler import (
    STALE_DYNAMIC_TRACE_MINUTES,
    _allocate_one_task_device_pair,
    _recover_stale_dynamic_tracing_tasks,
    _release_pair,
)


class SchedulerDeviceHealthTest(unittest.TestCase):
    def _connection_mocks(self):
        connection = MagicMock()
        cursor = MagicMock()
        connection.cursor.return_value.__enter__.return_value = cursor
        connection.cursor.return_value.__exit__.return_value = False
        return connection, cursor

    @patch("workers.scheduler.get_connection")
    def test_allocation_requires_recent_healthy_heartbeat(self, get_connection_mock) -> None:
        connection, cursor = self._connection_mocks()
        get_connection_mock.return_value.__enter__.return_value = connection
        cursor.fetchone.return_value = None

        self.assertIsNone(_allocate_one_task_device_pair())

        device_query = cursor.execute.call_args_list[0].args[0]
        self.assertIn("status = 'online'", device_query)
        self.assertIn("current_task_id IS NULL", device_query)
        self.assertIn(
            "last_heartbeat_at >= DATE_SUB(NOW(), INTERVAL 120 SECOND)",
            device_query,
        )

    @patch("workers.scheduler.get_connection")
    def test_stale_task_is_requeued_and_device_is_quarantined(self, get_connection_mock) -> None:
        connection, cursor = self._connection_mocks()
        get_connection_mock.return_value.__enter__.return_value = connection
        cursor.fetchall.return_value = [
            {
                "id": "task-1",
                "device_id": "device-1",
                "package_name": "  com.example.badapp  ",
            }
        ]
        cursor.fetchone.return_value = {
            "id": "device-1",
            "current_task_id": "task-1",
            "status": "busy",
        }
        cursor.execute.return_value = 1

        self.assertEqual(_recover_stale_dynamic_tracing_tasks(), 1)

        executed_sql = "\n".join(call.args[0] for call in cursor.execute.call_args_list)
        stale_select_sql = cursor.execute.call_args_list[0].args[0]
        self.assertIn("LEFT JOIN static_results", stale_select_sql)
        self.assertIn("SET status = 'waiting_device'", executed_sql)
        self.assertIn("device_id = NULL", executed_sql)
        self.assertIn("SET status = 'quarantined'", executed_sql)
        self.assertIn("quarantine_reason = %s", executed_sql)
        self.assertIn("quarantined_at = NOW()", executed_sql)
        device_update = next(
            call for call in cursor.execute.call_args_list if "UPDATE devices" in call.args[0]
        )
        self.assertIn("quarantine_task_id = %s", device_update.args[0])
        self.assertIn("quarantine_package_name = %s", device_update.args[0])
        self.assertEqual(
            device_update.args[1][1:3],
            ("task-1", "com.example.badapp"),
        )
        self.assertNotIn("SET status = 'dynamic_failed'", executed_sql)
        connection.commit.assert_called_once()

    @patch("workers.scheduler.get_connection")
    def test_stale_recovery_requeues_task_without_touching_reassigned_device(
        self, get_connection_mock
    ) -> None:
        connection, cursor = self._connection_mocks()
        get_connection_mock.return_value.__enter__.return_value = connection
        cursor.fetchall.return_value = [{"id": "task-1", "device_id": "device-1"}]
        cursor.fetchone.return_value = None
        cursor.execute.return_value = 1

        self.assertEqual(_recover_stale_dynamic_tracing_tasks(), 1)

        executed_sql = "\n".join(call.args[0] for call in cursor.execute.call_args_list)
        self.assertIn("FROM devices", executed_sql)
        self.assertIn("current_task_id = %s", executed_sql)
        self.assertIn("FOR UPDATE", executed_sql)
        self.assertIn("SET status = 'waiting_device'", executed_sql)
        self.assertIn("device_id = NULL", executed_sql)
        self.assertNotIn("UPDATE devices", executed_sql)
        task_update_call = cursor.execute.call_args_list[-1]
        self.assertEqual(task_update_call.args[1][1:], ("task-1", "device-1"))
        connection.commit.assert_called_once()

    @patch("workers.scheduler.get_connection")
    def test_dispatch_release_restores_only_busy_owned_device(self, get_connection_mock) -> None:
        connection, cursor = self._connection_mocks()
        get_connection_mock.return_value.__enter__.return_value = connection
        cursor.fetchone.side_effect = [
            {"status": "dynamic_tracing", "device_id": "device-1"},
            {"status": "busy", "current_task_id": "task-1"},
        ]
        cursor.execute.side_effect = [1, 1, 1, 1]

        self.assertTrue(_release_pair("task-1", "device-1", "dispatch failed"))

        sql = "\n".join(call.args[0] for call in cursor.execute.call_args_list)
        self.assertIn("FOR UPDATE", sql)
        self.assertIn("status = 'busy'", sql)
        self.assertIn("SET status = 'online'", sql)
        connection.commit.assert_called_once()

    @patch("workers.scheduler.get_connection")
    def test_dispatch_release_keeps_quarantined_device_quarantined(self, get_connection_mock) -> None:
        connection, cursor = self._connection_mocks()
        get_connection_mock.return_value.__enter__.return_value = connection
        cursor.fetchone.side_effect = [
            {"status": "dynamic_tracing", "device_id": "device-1"},
            {"status": "quarantined", "current_task_id": "task-1"},
        ]
        cursor.execute.side_effect = [1, 1, 1, 1]

        self.assertTrue(_release_pair("task-1", "device-1", "dispatch failed"))

        device_update = cursor.execute.call_args_list[-1].args[0]
        self.assertIn("status = 'quarantined'", device_update)
        self.assertIn("SET current_task_id = NULL", device_update)
        self.assertNotIn("SET status = 'online'", device_update)
        connection.commit.assert_called_once()

    @patch("workers.scheduler.get_connection")
    def test_dispatch_release_rowcount_mismatch_rolls_back(self, get_connection_mock) -> None:
        connection, cursor = self._connection_mocks()
        get_connection_mock.return_value.__enter__.return_value = connection
        cursor.fetchone.side_effect = [
            {"status": "dynamic_tracing", "device_id": "device-1"},
            {"status": "busy", "current_task_id": "task-1"},
        ]
        cursor.execute.side_effect = [1, 1, 1, 0]

        with self.assertRaises(RuntimeError):
            _release_pair("task-1", "device-1", "dispatch failed")

        connection.rollback.assert_called_once()
        connection.commit.assert_not_called()

    @patch("workers.scheduler.get_connection")
    def test_dispatch_release_does_not_touch_reassigned_task(self, get_connection_mock) -> None:
        connection, cursor = self._connection_mocks()
        get_connection_mock.return_value.__enter__.return_value = connection
        cursor.fetchone.return_value = {
            "status": "dynamic_tracing",
            "device_id": "device-2",
        }

        self.assertFalse(_release_pair("task-1", "device-1", "dispatch failed"))

        executed_sql = [call.args[0] for call in cursor.execute.call_args_list]
        self.assertFalse(any("UPDATE tasks" in sql for sql in executed_sql))
        self.assertFalse(any("UPDATE devices" in sql for sql in executed_sql))
        connection.rollback.assert_called_once()


if __name__ == "__main__":
    unittest.main()
