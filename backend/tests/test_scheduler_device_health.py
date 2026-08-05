from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from workers.scheduler import (
    STALE_DYNAMIC_TRACE_MINUTES,
    _allocate_one_task_device_pair,
    _recover_stale_dynamic_tracing_tasks,
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
        cursor.fetchall.return_value = [{"id": "task-1", "device_id": "device-1"}]
        cursor.fetchone.return_value = {
            "id": "device-1",
            "current_task_id": "task-1",
            "status": "busy",
        }
        cursor.execute.return_value = 1

        self.assertEqual(_recover_stale_dynamic_tracing_tasks(), 1)

        executed_sql = "\n".join(call.args[0] for call in cursor.execute.call_args_list)
        self.assertIn("SET status = 'waiting_device'", executed_sql)
        self.assertIn("device_id = NULL", executed_sql)
        self.assertIn("SET status = 'quarantined'", executed_sql)
        self.assertIn("quarantine_reason = %s", executed_sql)
        self.assertIn("quarantined_at = NOW()", executed_sql)
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


if __name__ == "__main__":
    unittest.main()
