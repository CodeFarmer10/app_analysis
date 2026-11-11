from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from analyzers.https_urls import collect_https_urls
from services import task_service
from repositories import task_repo


class HttpsUrlTest(unittest.TestCase):
    def test_deduplicates_across_sources_without_collapsing_different_requests(self):
        self.assertEqual(collect_https_urls(
            [{'url': ' https://api.example/x?a=1 '}, {'url': 'https://api.example/x?a=1'},
             {'url': 'http://api.example/x'}, {'url': 'file:///x'}, None],
            [{'url': 'https://api.example/x?a=1'}, {'url': 'https://api.example/x?a=2'},
             {'url': 'https://api.example:8443/x'}, {'url': 'https://api.example/x/'}],
        ), ['https://api.example/x?a=1', 'https://api.example/x?a=2',
            'https://api.example:8443/x', 'https://api.example/x/'])
        self.assertEqual(collect_https_urls(None, 'invalid'), [])

    @patch('repositories.task_repo.fetch_all', return_value=[])
    def test_repository_queries_both_sources_for_current_page(self, fetch):
        task_repo.get_https_urls_for_operations('task-1', ['step-1'], [0, 1])
        sql, params = fetch.call_args.args
        self.assertIn('FROM ecapture_logs', sql)
        self.assertIn('FROM frida_http_logs', sql)
        self.assertIn('dynamic_result_id IN', sql)
        self.assertIn('seq IN', sql)
        self.assertEqual(params.count('task-1'), 2)
        self.assertEqual(task_repo.get_https_urls_for_operations('task-1', [], []), [])
        self.assertEqual(fetch.call_count, 1)

    def test_dynamic_result_includes_deduplicated_urls_per_operation(self):
        with (
            patch.object(task_service, 'get_task_by_id', return_value={'status': 'completed'}),
            patch.object(task_service, 'list_dynamic_results', return_value=[]),
            patch.object(task_service, 'list_traffic_logs', return_value=[]),
            patch.object(task_service, 'get_dynamic_results', return_value=([
                {'id': 'step-0', 'seq': 0}, {'id': 'step-1', 'seq': 1},
            ], 2)),
            patch.object(task_service, 'get_traffic_logs_by_dynamic_result_ids', return_value=[]),
            patch.object(task_service, 'get_traffic_logs_by_seqs', return_value=[]),
            patch.object(task_service, 'get_https_urls_for_operations', return_value=[
                {'dynamic_result_id': 'step-0', 'seq': 99, 'url': 'https://api.example/x'},
                {'dynamic_result_id': 'step-0', 'seq': 0, 'url': 'https://api.example/x'},
                {'dynamic_result_id': None, 'seq': 1, 'url': 'https://api.example/x'},
                {'dynamic_result_id': 'step-1', 'seq': 1, 'url': 'http://api.example/x'},
            ]) as get_urls,
        ):
            result = task_service.get_task_dynamic_result('task-1', 1, 20)
        self.assertEqual(result['step_https_urls'], {
            0: ['https://api.example/x'], 1: ['https://api.example/x'],
        })
        get_urls.assert_called_once_with('task-1', ['step-0', 'step-1'], [0, 1])


if __name__ == '__main__':
    unittest.main()
