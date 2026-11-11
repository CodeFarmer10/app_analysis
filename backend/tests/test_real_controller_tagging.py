from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from workers.real_controller_tagging import (
    _build_real_controller_prompt, _parse_real_controller_response, run_real_controller_tagging,
)


class ControllerEvidenceTest(unittest.TestCase):
    @patch('workers.real_controller_tagging._is_white_domain', return_value=False)
    def test_https_sources_supply_deduplicated_url_semantics_without_metadata(self, _white):
        prompt, candidates, steps, _ = _build_real_controller_prompt([{
            'step_num': 2, 'step': '登录账号',
            'ecapture_logs': [{
                'url': 'https://packet.example:8443/api/login?token=x', 'method': 'POST',
                'src_ip': '10.0.0.2', 'src_port': 50123,
                'dst_ip': '8.8.8.8', 'dst_port': 8443, 'event_time': 1710000000.125,
            }],
            'frida_http_logs': [{
                'url': 'https://hook.example/user/register?invite=abc', 'method': 'POST',
                'hook_library': 'okhttp3/4', 'event_time': 1710000000.25,
            }, {'url': 'https://packet.example:8443/api/login?token=x'}],
        }])
        self.assertEqual(candidates, ['hook.example', 'packet.example'])
        self.assertIn('https://packet.example:8443/api/login?token=x', prompt)
        self.assertIn('https://hook.example/user/register?invite=abc', prompt)
        self.assertNotIn('8.8.8.8', prompt)
        self.assertNotIn('src_port', prompt)
        self.assertNotIn('event_time', prompt)
        self.assertIn('URL路径和查询参数', prompt)
        self.assertEqual(steps[0]['https_urls'], [
            'https://packet.example:8443/api/login?token=x',
            'https://hook.example/user/register?invite=abc',
        ])
        self.assertEqual(prompt.count('https://packet.example:8443/api/login?token=x'), 1)
        self.assertNotIn('hook_library', prompt)

    @patch('workers.real_controller_tagging._is_white_domain', side_effect=lambda d: d == 'white.example')
    def test_https_evidence_includes_literal_ip_endpoints_but_filters_other_urls(self, _white):
        events = [{'url': url, 'domain': 'spoof.example'} for url in (
            'http://plain.example/login', 'file:///login',
            'https://white.example/login', 'https://8.8.8.8:8443/login',
            'https://[2001:4860:4860::8888]/login', 'https://real.example/api/config',
        )]
        _, candidates, steps, _ = _build_real_controller_prompt([{
            'step_num': 1, 'ecapture_logs': events, 'frida_http_logs': events,
        }])
        self.assertEqual(candidates, ['8.8.8.8:8443', '[2001:4860:4860::8888]:443', 'real.example'])
        self.assertEqual(len(steps[0]['https_urls']), 4)

    @patch('workers.real_controller_tagging._is_white_domain', return_value=False)
    def test_ip_endpoints_use_default_port_and_keep_different_ports_separate(self, _white):
        prompt, candidates, _, _ = _build_real_controller_prompt([{
            'traffic_logs': [{'domain': '10.12.123.1', 'dst_port': 9999}],
            'ecapture_logs': [{'url': url} for url in (
                'https://10.12.123.1:8080/login', 'https://10.12.123.1/login',
                'https://10.12.123.1:443/config', 'https://10.12.123.1:bad/login',
            )],
            'frida_http_logs': [{'url': 'https://10.12.123.1:8080/config'}],
        }])
        self.assertEqual(candidates, ['10.12.123.1:443', '10.12.123.1:8080'])
        self.assertNotIn('9999', prompt)
        self.assertIn('IP:端口', prompt)
        chosen, reasons = _parse_real_controller_response(json.dumps({'c2_domains': [
            {'domain': '10.12.123.1:8080', 'reason': '登录接口'},
            {'domain': '10.12.123.1', 'reason': 'missing port'},
            {'domain': '10.12.123.1:9999', 'reason': 'unobserved port'},
        ]}), candidates)
        self.assertEqual(chosen, ['10.12.123.1:8080'])
        self.assertEqual(reasons[0]['reason'], '登录接口')


class DomainOnlyTaggingTest(unittest.TestCase):
    @patch('workers.real_controller_tagging._is_white_domain', return_value=False)
    @patch('workers.real_controller_tagging.OpenAI')
    def test_ip_only_https_observation_can_be_selected_by_model(self, client, _white):
        response = MagicMock()
        response.choices[0].message.content = json.dumps({'c2_domains': [{
            'domain': '10.12.123.1:8080', 'reason': '步骤1的HTTPS登录接口',
        }]})
        client.return_value.chat.completions.create.return_value = response
        packets = [{'url': 'https://10.12.123.1:8080/login'}]
        with tempfile.TemporaryDirectory() as folder:
            result, _ = run_real_controller_tagging(
                operation_results=[{'step_num': 1, 'step': '登录', 'ecapture_logs': packets}],
                traffic_rows=[], ecapture_rows=packets, result_dir=Path(folder), enabled=True,
                model_base_url='http://unused', model_api_key='unused', model_name='unused',
            )
            saved = json.loads((Path(folder) / 'real_controller_tagging.json').read_text())
        self.assertEqual(result['candidate_domains'], ['10.12.123.1:8080'])
        self.assertEqual(saved['c2_domains'], ['10.12.123.1:8080'])
        self.assertEqual(result['matched_ecapture_count'], 1)
        self.assertEqual(packets[0]['is_real_controller'], 1)

    @patch('workers.real_controller_tagging._is_white_domain', return_value=False)
    @patch('workers.real_controller_tagging.OpenAI')
    def test_hook_only_url_can_trigger_domain_inference(self, client, _white):
        response = MagicMock()
        response.choices[0].message.content = json.dumps({'c2_domains': [{
            'domain': 'hook.example', 'reason': '步骤2登录请求 https://hook.example/api/login',
        }]})
        client.return_value.chat.completions.create.return_value = response
        with tempfile.TemporaryDirectory() as folder:
            result, _ = run_real_controller_tagging(
                operation_results=[{'step_num': 2, 'step': '登录', 'frida_http_logs': [{
                    'url': 'https://hook.example/api/login', 'method': 'POST',
                }]}], traffic_rows=[], result_dir=Path(folder), enabled=True,
                model_base_url='http://unused', model_api_key='unused', model_name='unused',
            )
        self.assertEqual(result['c2_domains'], ['hook.example'])
        sent_prompt = client.return_value.chat.completions.create.call_args.kwargs['messages'][1]['content']
        self.assertIn('https://hook.example/api/login', sent_prompt)
        self.assertIn('https_urls:', sent_prompt)

    def run_tagging(self, domains, traffic, packets):
        with tempfile.TemporaryDirectory() as folder, patch(
            'workers.real_controller_tagging._infer_real_controller_domains',
            return_value={'status': 'ok', 'c2_domains': domains},
        ):
            result, count = run_real_controller_tagging(
                operation_results=[{'step_num': 1, 'step': '登录'}],
                traffic_rows=traffic, ecapture_rows=packets, result_dir=Path(folder),
                enabled=True, model_base_url='http://unused', model_api_key='unused', model_name='unused',
            )
            saved = json.loads((Path(folder) / 'real_controller_tagging.json').read_text())
        self.assertNotIn('c2_ips', result)
        self.assertNotIn('c2_ip_reasons', saved)
        return result, count

    def test_empty_domain_result_does_not_fall_back_to_ip_scoring(self):
        traffic = [{
            'seq': 1, 'src_ip': '10.0.0.2', 'dst_ip': '8.8.8.8', 'dst_port': 8443,
            'protocol': 'TLSv1.3', 'ip_country': '美国', 'is_real_controller': 1,
        }]
        packets = [dict(traffic[0])]
        result, count = self.run_tagging([], traffic, packets)
        self.assertEqual(count, 0)
        self.assertEqual(result['tagging_basis'], 'empty')
        self.assertEqual(traffic[0]['is_real_controller'], 0)
        self.assertEqual(packets[0]['is_real_controller'], 0)

    def test_shared_ip_does_not_mark_unselected_domain(self):
        traffic = [{'domain': d, 'dst_ip': '8.8.8.8', 'src_ip': '10.0.0.2'}
                   for d in ('CONTROL.EXAMPLE.', 'other.example', '')]
        packets = [{'url': 'https://control.example/api/login'}, {'url': 'https://other.example/api'}]
        _, count = self.run_tagging(['control.example'], traffic, packets)
        self.assertEqual(count, 1)
        self.assertEqual([r['is_real_controller'] for r in traffic], [1, 0, 0])
        self.assertEqual([r['is_real_controller'] for r in packets], [1, 0])

    def test_selected_direct_ip_url_is_tagged_only_for_matching_port(self):
        traffic = [{'url': url} for url in (
            'https://10.12.123.1:8080/login', 'https://10.12.123.1:8443/login',
            'https://10.12.123.1/login', 'https://other.example/login',
        )]
        packets = [dict(row) for row in traffic]
        result, count = self.run_tagging(['10.12.123.1:8080'], traffic, packets)
        self.assertEqual(count, 1)
        self.assertEqual(result['matched_ecapture_count'], 1)
        self.assertEqual([r['is_real_controller'] for r in traffic], [1, 0, 0, 0])
        self.assertEqual([r['is_real_controller'] for r in packets], [1, 0, 0, 0])

    def test_default_https_port_and_ipv6_endpoints_match(self):
        packets = [{'url': url} for url in (
            'https://10.12.123.1/login', 'https://10.12.123.1:443/login',
            'https://[2001:db8::1]/config', 'https://[2001:db8::1]:8443/config',
        )]
        self.run_tagging(['10.12.123.1:443', '[2001:db8::1]:443'], [], packets)
        self.assertEqual([r['is_real_controller'] for r in packets], [1, 1, 1, 0])


if __name__ == '__main__':
    unittest.main()
