from __future__ import annotations

import unittest
import sys
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from analyzers.ecapture_parser import ECaptureEvent, ECaptureParser
from phone_agent.adb.ecapture import ECaptureCapture
from phone_agent.frida.helper import FridaHelper, FridaHelperConfig
from phone_agent.frida.registry import load_frida_rules
from phone_agent.plan_agent import PlanAgent, PlanAgentConfig, PlanResult
from workers import dynamic_trace
from workers.real_controller_tagging import _build_real_controller_prompt


class ECaptureParserTest(unittest.TestCase):
    def test_decrypted_pcapng_row_preserves_plaintext_http_fields(self) -> None:
        parser = ECaptureParser("tshark")

        row = {
            "frame.time_epoch": "1710000000.25",
            "ip.src": "10.0.0.2",
            "tcp.srcport": "48120",
            "ip.dst": "8.8.8.8",
            "tcp.dstport": "443",
            "_ws.col.Protocol": "HTTP2",
            "http2.headers.method": "POST",
            "http2.headers.authority": "api.bad.example",
            "http2.headers.path": "/api/login",
            "http.file_data": '{"phone":"13800000000"}',
        }

        event = parser._parse_row(row)

        self.assertIsNotNone(event)
        self.assertEqual(event.method, "POST")
        self.assertEqual(event.domain, "api.bad.example")
        self.assertEqual(event.http_path, "/api/login")
        self.assertEqual(event.url, "https://api.bad.example/api/login")
        self.assertEqual(event.body_preview, '{"phone":"13800000000"}')

    def test_http1_request_and_response_are_correlated_as_one_transaction(self) -> None:
        parser = ECaptureParser("tshark")
        packets = [
            {
                "timestamp": "1710000000.25",
                "layers": {
                    "frame_number": ["10"],
                    "tls_record_version": ["0x0303"],
                    "ip_src": ["10.0.0.2"], "tcp_srcport": ["48120"],
                    "ip_dst": ["8.8.8.8"], "tcp_dstport": ["443"],
                    "tcp_stream": ["4"], "http_request_method": ["POST"],
                    "http_host": ["api.bad.example"], "http_request_uri": ["/api/login"],
                    "http_request_line": ["Content-Type: application/json\\r\\n"],
                    "http_file_data": ["7b2270686f6e65223a223133383030303030303030227d"],
                },
            },
            {
                "timestamp": "1710000000.50",
                "layers": {
                    "frame_number": ["11"],
                    "ip_src": ["8.8.8.8"], "tcp_srcport": ["443"],
                    "ip_dst": ["10.0.0.2"], "tcp_dstport": ["48120"],
                    "tcp_stream": ["4"], "http_response_code": ["200"],
                    "http_request_in": ["10"],
                    "http_response_line": ["Content-Type: application/json\\r\\n", "Content-Length: 11\\r\\n"],
                    "http_file_data": ["7b226f6b223a747275657d"],
                },
            },
        ]

        transactions = parser.parse_ek_packets(packets)

        self.assertEqual(len(transactions), 1)
        transaction = transactions[0]
        self.assertEqual(transaction.url, "https://api.bad.example/api/login")
        self.assertEqual(transaction.request_body_preview, '{"phone":"13800000000"}')
        self.assertEqual(transaction.response_status, 200)
        self.assertEqual(transaction.response_body_preview, '{"ok":true}')
        self.assertEqual(transaction.src_ip, "10.0.0.2")
        self.assertEqual(transaction.dst_port, "443")
        self.assertTrue(transaction.is_complete)

    def test_http2_streams_keep_partial_and_complete_transactions_separate(self) -> None:
        parser = ECaptureParser("tshark")
        packets = [
            {"timestamp": "1710000001.0", "layers": {
                "ip_src": ["10.0.0.2"], "tcp_srcport": ["50000"],
                "ip_dst": ["9.9.9.9"], "tcp_dstport": ["443"], "tcp_stream": ["7"],
                "http2_streamid": ["3"], "http2_type": ["1"],
                "http2_headers_method": ["GET"], "http2_headers_scheme": ["https"],
                "http2_headers_authority": ["api.example"], "http2_headers_path": ["/partial"],
                "http2_flags_end_stream": ["True"],
            }},
            {"timestamp": "1710000001.1", "layers": {
                "ip_src": ["10.0.0.2"], "tcp_srcport": ["50000"],
                "ip_dst": ["9.9.9.9"], "tcp_dstport": ["443"], "tcp_stream": ["7"],
                "http2_streamid": ["5"], "http2_type": ["1"],
                "http2_headers_method": ["POST"], "http2_headers_scheme": ["https"],
                "http2_headers_authority": ["api.example"], "http2_headers_path": ["/complete"],
                "http2_flags_end_stream": ["False"],
            }},
            {"timestamp": "1710000001.2", "layers": {
                "ip_src": ["10.0.0.2"], "tcp_srcport": ["50000"],
                "ip_dst": ["9.9.9.9"], "tcp_dstport": ["443"], "tcp_stream": ["7"],
                "http2_streamid": ["5"], "http2_type": ["0"],
                "http2_data_data": ["68656c6c6f"], "http2_flags_end_stream": ["True"],
            }},
            {"timestamp": "1710000001.3", "layers": {
                "ip_src": ["9.9.9.9"], "tcp_srcport": ["443"],
                "ip_dst": ["10.0.0.2"], "tcp_dstport": ["50000"], "tcp_stream": ["7"],
                "http2_streamid": ["5"], "http2_type": ["1"], "http2_request_in": ["21"],
                "http2_headers_status": ["201"],
                "http2_header_name": [":status", "content-length"],
                "http2_header_value": ["201", "2"], "http2_flags_end_stream": ["False"],
            }},
            {"timestamp": "1710000001.4", "layers": {
                "ip_src": ["9.9.9.9"], "tcp_srcport": ["443"],
                "ip_dst": ["10.0.0.2"], "tcp_dstport": ["50000"], "tcp_stream": ["7"],
                "http2_streamid": ["5"], "http2_type": ["0"],
                "http2_data_data": ["6f6b"], "http2_flags_end_stream": ["True"],
            }},
        ]

        transactions = parser.parse_ek_packets(packets)

        self.assertEqual([item.http_path for item in transactions], ["/partial", "/complete"])
        self.assertEqual(transactions[1].request_body_preview, "hello")
        self.assertEqual(transactions[1].response_body_preview, "ok")
        self.assertEqual(transactions[1].response_status, 201)
        self.assertTrue(transactions[1].is_complete)
        self.assertFalse(transactions[0].is_complete)

    def test_ek_packet_timestamp_prefers_frame_epoch_over_millisecond_envelope(self) -> None:
        parser = ECaptureParser("tshark")
        packets = [{
            "timestamp": "1789112399750",
            "layers": {
                "frame_time_epoch": ["1789112399.750216598"],
                "ip_src": ["10.0.0.2"], "tcp_srcport": ["50000"],
                "ip_dst": ["9.9.9.9"], "tcp_dstport": ["443"], "tcp_stream": ["7"],
                "http2_streamid": ["1"], "http2_type": ["1"],
                "http2_headers_method": ["GET"], "http2_headers_scheme": ["https"],
                "http2_headers_authority": ["api.example"],
                "http2_headers_path": ["/config"],
                "http2_flags_end_stream": ["True"],
            },
        }]

        transactions = parser.parse_ek_packets(packets)

        self.assertEqual(len(transactions), 1)
        self.assertAlmostEqual(transactions[0].timestamp, 1789112399.750216598)

    def test_timestamp_normalizes_millisecond_epoch_values(self) -> None:
        parser = ECaptureParser("tshark")
        event = ECaptureEvent.from_mapping({
            "timestamp": 1789112399750,
            "url": "https://api.example/config",
            "method": "GET",
        })

        self.assertAlmostEqual(event.timestamp, 1789112399.75)

    def test_parser_uses_ek_output(self) -> None:
        command = ECaptureParser("/usr/bin/tshark")._build_command("capture.pcapng", "http or http2")

        self.assertIn("ek", command)
        self.assertNotIn("fields", command)

    def test_http1_scheme_uses_tls_evidence_rather_than_port(self) -> None:
        layers = {
            "frame_number": ["1"], "http_request_method": ["GET"],
            "http_host": ["api.example"], "http_request_uri": ["/x"],
            "tcp_dstport": ["443"],
        }
        parser = ECaptureParser()
        plain = parser.parse_ek_packets([{"timestamp": "1710000000", "layers": layers}])[0]
        secure = parser.parse_ek_packets([{
            "timestamp": "1710000000",
            "layers": {**layers, "tls_record_version": ["0x0303"], "tcp_dstport": ["8443"]},
        }])[0]
        self.assertEqual(plain.url, "http://api.example/x")
        self.assertEqual(secure.url, "https://api.example/x")


class IndependentCaptureTest(unittest.TestCase):
    def test_sources_stay_separate_and_map_by_event_time(self) -> None:
        packet = ECaptureEvent(
            timestamp=1710000000.0, src_ip="10.0.0.2", src_port="48120",
            dst_ip="8.8.8.8", dst_port="443", protocol="HTTP/2",
            domain="api.example", url="https://api.example/login", method="POST",
            http_path="/login", parse_status="partial", is_complete=False,
        )
        hook = {
            "frida_http_log_id": "frida-http-1", "timestamp": 1710000000.4,
            "url": "https://api.example/login", "method": "POST",
            "request_body_preview": '{"phone":"13800000000"}', "response_status": 200,
            "response_body_preview": '{"token":"x"}', "capture_source": "network_hook",
            "parse_status": "complete", "is_complete": True,
        }

        agent = PlanAgent.__new__(PlanAgent)
        agent.ecapture_parser = MagicMock()
        agent.ecapture_parser.parse_pcapng.return_value = [packet]
        agent._execution_results = [
            PlanResult(step_num=0, start_time=datetime.fromtimestamp(1710000000)),
            PlanResult(step_num=1, start_time=datetime.fromtimestamp(1710000000.3)),
        ]
        agent._map_ecapture_to_operations("capture.pcapng", [hook])

        first, second = agent._execution_results
        self.assertEqual(first.ecapture_logs, [packet])
        self.assertEqual(first.frida_http_logs, [])
        self.assertEqual(second.ecapture_logs, [])
        self.assertEqual(len(second.frida_http_logs), 1)
        self.assertEqual(second.frida_http_logs[0]["event_time"], 1710000000.4)
        self.assertIsNone(packet.response_status)
        self.assertFalse(packet.is_complete)
        self.assertEqual(packet.capture_source, "ecapture")

    def test_mapping_excludes_cleartext_and_non_network_urls_from_both_sources(self) -> None:
        agent = PlanAgent.__new__(PlanAgent)
        agent.ecapture_parser = MagicMock()
        urls = ["https://api.example:8443/x", "http://api.example:443/x", "file:///x", "data:text/html,x"]
        agent.ecapture_parser.parse_pcapng.return_value = [
            ECaptureEvent(timestamp=1710000000.25, src_ip=None, src_port=None,
                          dst_ip=None, dst_port="443", protocol="HTTP/2", url=url)
            for url in urls
        ]
        agent._execution_results = [PlanResult(start_time=datetime.fromtimestamp(1710000000))]
        agent._map_ecapture_to_operations("capture.pcapng", [
            {"timestamp": 1710000000250, "url": url} for url in urls
        ])
        result = agent._execution_results[0]
        self.assertEqual([e.url for e in result.ecapture_logs], urls[:1])
        self.assertEqual([e["url"] for e in result.frida_http_logs], urls[:1])
        self.assertEqual(result.frida_http_logs[0]["event_time"], 1710000000.25)

    def test_hook_event_time_at_step_boundary_takes_precedence_over_other_timestamps(self) -> None:
        agent = PlanAgent.__new__(PlanAgent)
        agent._execution_results = [
            PlanResult(start_time=datetime.fromtimestamp(1710000000)),
            PlanResult(start_time=datetime.fromtimestamp(1710000001)),
        ]
        agent._map_ecapture_to_operations(None, [{
            "url": "https://api.example/x", "event_time": 1710000001,
            "timestamp": 1710000000.5,
        }])
        self.assertEqual(agent._execution_results[0].frida_http_logs, [])
        self.assertEqual(len(agent._execution_results[1].frida_http_logs), 1)
        self.assertEqual(agent._execution_results[1].ecapture_logs, [])


class NetworkHookCollectionTest(unittest.TestCase):
    def test_legacy_http_rules_replaced_by_network_hooks_are_removed(self) -> None:
        rule_ids = {rule.id for rule in load_frida_rules(BACKEND_DIR / "phone_agent" / "frida" / "rules.json")}

        self.assertNotIn("webview_load_url", rule_ids)
        self.assertNotIn("webview_post_url", rule_ids)
        self.assertNotIn("webview_load_data_with_base_url", rule_ids)
        self.assertNotIn("okhttp_request_builder_url", rule_ids)
        self.assertNotIn("java_net_url_init", rule_ids)
        self.assertNotIn("java_net_url_open_connection", rule_ids)

    def test_http_transactions_are_separate_from_generic_events(self) -> None:
        helper = FridaHelper("device-1", FridaHelperConfig(enabled=True))

        helper._on_message({
            "type": "send",
            "payload": {"type": "http_transaction", "payload": {
                    "timestamp": 1710000000.0, "url": "https://api.example/login",
                    "method": "POST", "response_status": 200,
                    "hook_library": "okhttp3/4", "frida_http_log_id": "frida-http-1",
                }},
        }, None)

        self.assertEqual(helper.export_events(), [])
        self.assertEqual(len(helper.export_http_transactions()), 1)
        self.assertEqual(helper.export_http_transactions()[0]["capture_source"], "network_hook")
        self.assertEqual(helper.export_http_transactions()[0]["hook_library"], "okhttp3/4")

    def test_plan_result_keeps_hook_transactions_separate_from_merged_ecapture_logs(self) -> None:
        result = PlanResult()
        result.frida_http_logs = [{"url": "https://api.example/login", "hook_library": "okhttp"}]

        payload = result.to_dict()

        self.assertEqual(payload["frida_http_logs"][0]["hook_library"], "okhttp")

    def test_frida_source_contains_supported_network_stack_adapters(self) -> None:
        source = (BACKEND_DIR / "phone_agent" / "frida" / "agent_src" / "index.js").read_text()

        for class_name in (
            "okhttp3.Response$Builder",
            "java.net.HttpURLConnection",
            "android.webkit.WebView",
            "org.chromium.net.UrlRequest$Builder",
        ):
            self.assertIn(class_name, source)
        self.assertIn("postUrl", source)

    def test_retrofit_does_not_register_a_second_http_hook(self) -> None:
        source = (BACKEND_DIR / "phone_agent" / "frida" / "agent_src" / "index.js").read_text()

        self.assertNotIn("retrofit2.OkHttpCall", source)
        self.assertNotIn("installRetrofitHooks", source)

    def test_static_response_body_is_skipped_before_peek_body(self) -> None:
        source = (BACKEND_DIR / "phone_agent" / "frida" / "agent_src" / "index.js").read_text()

        self.assertIn("function isStaticResponse", source)
        self.assertIn("image/", source)
        self.assertIn("video/", source)
        self.assertIn("text/css", source)
        self.assertIn("responseBody = isStaticResponse", source)
        self.assertIn("response.peekBody(65536)", source)
        self.assertIn("safeToString(responseHeaders && responseHeaders['content-type']) || ''", source)

    def test_identical_okhttp_events_are_coalesced_in_a_short_window(self) -> None:
        source = (BACKEND_DIR / "phone_agent" / "frida" / "agent_src" / "index.js").read_text()

        self.assertIn("HTTP_DUPLICATE_WINDOW_MS", source)
        self.assertIn("recentHttpFingerprints", source)
        self.assertIn("http_transaction_duplicate", source)

    @patch("phone_agent.frida.helper.load_frida_rules", return_value=[])
    def test_frida_starts_network_hooks_when_no_generic_rules_remain(self, _load_rules) -> None:
        helper = FridaHelper("device-1", FridaHelperConfig(enabled=True))
        device = MagicMock()
        device.spawn.return_value = 123
        session = MagicMock()
        script = MagicMock()
        session.create_script.return_value = script
        device.attach.return_value = session

        with (
            patch.object(helper, "_get_frida_module", return_value=object()),
            patch.object(helper, "_ensure_frida_server_ready"),
            patch.object(helper, "_resolve_device", return_value=device),
        ):
            self.assertTrue(helper.start("com.example.app", defer_resume=True))

        self.assertEqual(helper.status, "running")
        script.load.assert_called_once()


class CaptureLifecycleTest(unittest.TestCase):
    def test_collectors_start_before_spawn_resume(self) -> None:
        calls: list[str] = []
        agent = PlanAgent.__new__(PlanAgent)
        agent.traffic_capture = MagicMock()
        agent.traffic_capture.start_capture.side_effect = lambda: calls.append("traffic")
        agent.ecapture_capture = MagicMock()
        agent.ecapture_capture.start_capture.side_effect = lambda: calls.append("ecapture")
        agent.frida_helper = MagicMock()
        agent.frida_helper.mode = "spawn"
        agent.frida_helper.start.side_effect = lambda package, defer_resume=False: calls.append(
            f"hook:{defer_resume}"
        ) or True
        agent.frida_helper.resume.side_effect = lambda: calls.append("resume")
        device_factory = MagicMock()

        agent._start_collectors_and_app("com.example.app", device_factory)

        self.assertEqual(calls, ["traffic", "ecapture", "hook:True", "resume"])
        device_factory.launch_app_by_package.assert_not_called()


class ECaptureCaptureTest(unittest.TestCase):
    def test_start_uses_pcap_model_iface_and_verifies_process(self) -> None:
        capture = ECaptureCapture(
            device_id="device-1",
            binary_path="/tmp/ecapture",
            device_output_path="/data/local/tmp/decrypted-test.pcapng",
            iface="wlan0",
            ssl_version="boringssl_a_15",
            enabled=True,
        )

        with (
            patch.object(capture, "_resolve_host_binary", return_value="/tmp/ecapture"),
            patch.object(capture, "_has_root", return_value=True),
            patch.object(capture, "_stop_existing"),
            patch.object(capture, "_resolve_capture_iface", return_value="wlan0"),
            patch.object(capture, "_is_process_running", return_value=True),
            patch.object(capture, "_execute_adb_command") as execute_adb_command,
            patch("phone_agent.adb.ecapture.time.sleep"),
        ):
            self.assertTrue(capture.start_capture())

        executed = "\n".join(call.args[0] for call in execute_adb_command.call_args_list)
        self.assertIn("tls -m pcap", executed)
        self.assertIn("--pcapfile /data/local/tmp/decrypted-test.pcapng", executed)
        self.assertIn("--ssl_version=boringssl_a_15", executed)
        self.assertIn("-i wlan0", executed)
        self.assertNotIn("tcp port 443", executed)

    def test_start_uses_writable_keylog_path_for_pcapng_secret_material(self) -> None:
        capture = ECaptureCapture(
            device_id="device-1",
            binary_path="/tmp/ecapture",
            device_output_path="/data/local/tmp/decrypted-test.pcapng",
            enabled=True,
        )

        with (
            patch.object(capture, "_resolve_host_binary", return_value="/tmp/ecapture"),
            patch.object(capture, "_has_root", return_value=True),
            patch.object(capture, "_stop_existing"),
            patch.object(capture, "_resolve_capture_iface", return_value="wlan0"),
            patch.object(capture, "_is_process_running", return_value=True),
            patch.object(capture, "_execute_adb_command") as execute_adb_command,
            patch("phone_agent.adb.ecapture.time.sleep"),
        ):
            self.assertTrue(capture.start_capture())

        executed = "\n".join(call.args[0] for call in execute_adb_command.call_args_list)
        self.assertIn("--keylogfile /data/local/tmp/decrypted-test.keys", executed)

    def test_start_returns_false_when_ecapture_exits_immediately(self) -> None:
        capture = ECaptureCapture(
            device_id="device-1",
            binary_path="/tmp/ecapture",
            iface="wlan0",
            enabled=True,
        )

        with (
            patch.object(capture, "_resolve_host_binary", return_value="/tmp/ecapture"),
            patch.object(capture, "_has_root", return_value=True),
            patch.object(capture, "_stop_existing"),
            patch.object(capture, "_resolve_capture_iface", return_value="wlan0"),
            patch.object(capture, "_is_process_running", return_value=False),
            patch.object(capture, "_read_device_file_tail", return_value="missing CAP_BPF"),
            patch.object(capture, "_execute_adb_command"),
            patch("phone_agent.adb.ecapture.time.sleep"),
        ):
            self.assertFalse(capture.start_capture())
            self.assertFalse(capture._is_capturing)


class ECapturePersistenceTest(unittest.TestCase):
    @patch("workers.dynamic_trace.get_connection")
    def test_result_persistence_writes_ecapture_rows_to_separate_table(self, get_connection_mock) -> None:
        cursor = MagicMock()
        cursor.fetchone.side_effect = [
            {"status": "dynamic_tracing", "device_id": "device-1"},
            {"status": "busy", "current_task_id": "task-1"},
        ]
        cursor.execute.side_effect = [None, None, None, None, None, None, None, 1]
        conn = MagicMock()
        conn.cursor.return_value.__enter__.return_value = cursor
        get_connection_mock.return_value.__enter__.return_value = conn

        dynamic_trace._persist_trace_results(
            task_id="task-1",
            device_id="device-1",
            pcap_path="task-1/attempts/a/pcap/capture.pcap",
            ecapture_pcapng_path="task-1/attempts/a/ecapture/decrypted_capture.pcapng",
            run_log_path="task-1/attempts/a/log/run.log",
            dynamic_rows=[],
            traffic_rows=[],
            frida_rows=[],
            ecapture_rows=[
                {
                    "id": "ecapture-1",
                    "task_id": "task-1",
                    "dynamic_result_id": "dynamic-1",
                    "seq": 1,
                    "src_ip": "10.0.0.2",
                    "dst_ip": "8.8.8.8",
                    "src_port": 48120,
                    "dst_port": 443,
                    "protocol": "HTTPS",
                    "domain": "api.bad.example",
                    "url": "https://api.bad.example/api/login",
                    "resolved_ip": None,
                    "ip_country": "美国",
                    "is_up": 1,
                    "is_real_controller": 1,
                    "http_method": "POST",
                    "http_path": "/api/login",
                    "headers_json": '{"host":"api.bad.example"}',
                    "body_preview": '{"phone":"13800000000"}',
                    "process_name": "com.bad.app",
                }
            ],
        )

        executed_sql = "\n".join(str(call.args[0]) for call in cursor.execute.call_args_list)
        self.assertIn("DELETE FROM frida_http_logs WHERE task_id = %s", executed_sql)
        self.assertIn("DELETE FROM ecapture_logs WHERE task_id = %s", executed_sql)
        cursor.executemany.assert_called_once()
        insert_sql = cursor.executemany.call_args.args[0]
        self.assertIn("INSERT INTO ecapture_logs", insert_sql)
        self.assertIn("request_body_preview", insert_sql)
        self.assertIn("response_body_preview", insert_sql)
        self.assertIn("capture_source", insert_sql)
        self.assertIn("event_time", insert_sql)
        self.assertNotIn("frida_http_log_id", insert_sql)
        self.assertEqual(insert_sql.count("%s"), len(cursor.executemany.call_args.args[1][0]))
        self.assertNotIn("frida_supplement_fields", insert_sql)
        update_args = cursor.execute.call_args_list[-1].args[1]
        self.assertEqual(
            update_args,
            (
                "task-1/attempts/a/pcap/capture.pcap",
                "task-1/attempts/a/ecapture/decrypted_capture.pcapng",
                "task-1/attempts/a/log/run.log",
                "task-1",
                "device-1",
            ),
        )

    def test_hook_transaction_cannot_be_written_to_ecapture_table(self) -> None:
        dynamic_rows, traffic_rows, frida_rows, frida_http_rows, ecapture_rows = dynamic_trace._parse_operation_results(
            task_id="task-1",
            operation_results=[{
                "step_num": 1,
                "step": "提交登录",
                "successed": True,
                "start_time": "2026-09-10 10:00:00",
                "ecapture_logs": [{
                    "timestamp": 1710000000.0,
                    "url": "https://api.example/login",
                    "method": "POST",
                    "request_body_preview": '{"phone":"13800000000"}',
                    "response_status": 200,
                    "response_body_preview": '{"ok":true}',
                    "capture_source": "network_hook",
                    "parse_status": "complete",
                    "is_complete": True,
                }],
            }],
            result_dir=Path("/tmp"),
            object_namespace="task-1/attempts/a",
        )

        self.assertEqual(len(dynamic_rows), 1)
        self.assertEqual(traffic_rows, [])
        self.assertEqual(frida_rows, [])
        self.assertEqual(frida_http_rows, [])
        self.assertEqual(ecapture_rows, [])

    def test_storage_filters_https_and_preserves_event_time_in_both_tables(self) -> None:
        events = [
            {"url": url, "timestamp": "1710000000.123456", "method": "GET"}
            for url in ("https://api.example:8443/x", "http://api.example:443/x", "file:///x")
        ]
        *_, hook_rows, packet_rows = dynamic_trace._parse_operation_results(
            task_id="task-1", operation_results=[{
                "step_num": 1, "step": "open", "successed": True,
                "start_time": "2024-03-09 10:00:00",
                "frida_http_logs": events, "ecapture_logs": events,
            }], result_dir=Path("/tmp"), object_namespace="task-1/attempts/a",
        )
        self.assertEqual(len(hook_rows), 1)
        self.assertEqual(len(packet_rows), 1)
        for row in (hook_rows[0], packet_rows[0]):
            self.assertEqual(row["event_time"], datetime.fromtimestamp(1710000000.123456))
        self.assertNotIn("frida_supplement_fields", packet_rows[0])

    def test_hook_transaction_is_converted_to_a_separate_frida_http_row(self) -> None:
        _dynamic_rows, _traffic_rows, _frida_rows, frida_http_rows, _ecapture_rows = (
            dynamic_trace._parse_operation_results(
                task_id="task-1",
                operation_results=[{
                    "step_num": 1,
                    "step": "提交登录",
                    "successed": True,
                    "start_time": "2026-09-10 10:00:00",
                    "frida_http_logs": [{
                        "frida_http_log_id": "frida-http-1",
                        "timestamp": 1710000000.0,
                        "hook_library": "httpurlconnection",
                        "hook_class": "java.net.HttpURLConnection",
                        "hook_method": "getResponseCode",
                        "url": "https://api.example/login",
                        "method": "POST",
                        "response_status": 200,
                        "parse_status": "partial",
                    }],
                }],
                result_dir=Path("/tmp"),
                object_namespace="task-1/attempts/a",
            )
        )

        self.assertEqual(len(frida_http_rows), 1)
        self.assertEqual(frida_http_rows[0]["frida_http_log_id"], "frida-http-1")
        self.assertEqual(frida_http_rows[0]["hook_library"], "httpurlconnection")


class ECaptureRealControllerPromptTest(unittest.TestCase):
    def test_prompt_uses_ecapture_only_domain_as_candidate_and_evidence(self) -> None:
        prompt, candidate_domains, _step_summaries, _observations = _build_real_controller_prompt(
            operation_results=[
                {
                    "step_num": 1,
                    "step": "登录账号",
                    "traffic_logs": [],
                    "frida_events": [],
                    "ecapture_logs": [
                        ECaptureEvent(
                            timestamp=1710000000.25,
                            src_ip="10.0.0.2",
                            src_port="48120",
                            dst_ip="8.8.8.8",
                            dst_port="443",
                            protocol="HTTPS",
                            domain="api.bad.example",
                            url="https://api.bad.example/api/login",
                            method="POST",
                            http_path="/api/login",
                            body_preview='{"phone":"13800000000"}',
                        ).to_dict()
                    ],
                }
            ]
        )

        self.assertEqual(candidate_domains, ["api.bad.example"])
        self.assertIn("https_urls:", prompt)
        self.assertIn("https://api.bad.example/api/login", prompt)
        self.assertNotIn("event_time", prompt)


if __name__ == "__main__":
    unittest.main()
