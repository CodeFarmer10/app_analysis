"""Build HTTP transactions from decrypted TLS traffic captured by eCapture."""

from __future__ import annotations

import gzip
import json
import logging
import shutil
import subprocess
import zlib
from dataclasses import dataclass, field, fields
from datetime import datetime
from typing import Any, Iterable, Iterator
from urllib.parse import urlsplit

from analyzers.pcapng_secrets import prepared_pcapng

logger = logging.getLogger(__name__)
_TSHARK_AVAILABILITY_CACHE: dict[str, bool] = {}


@dataclass
class ECaptureEvent:
    """One HTTP request and its correlated response."""

    timestamp: float
    src_ip: str | None
    src_port: str | None
    dst_ip: str | None
    dst_port: str | None
    protocol: str
    domain: str | None = None
    url: str | None = None
    resolved_ip: str | None = None
    method: str | None = None
    http_path: str | None = None
    response_timestamp: float | None = None
    response_status: int | None = None
    request_headers_json: str | None = None
    request_body_preview: str | None = None
    response_headers_json: str | None = None
    response_body_preview: str | None = None
    content_type: str | None = None
    capture_source: str = "ecapture"
    parse_status: str = "partial"
    is_complete: bool = False
    process_name: str | None = None
    hook_library: str | None = None
    hook_class: str | None = None
    hook_method: str | None = None
    # Compatibility aliases for old operation-results consumers.
    headers_json: str | None = None
    body_preview: str | None = None

    def __post_init__(self) -> None:
        if self.request_headers_json is None and self.headers_json is not None:
            self.request_headers_json = self.headers_json
        if self.request_body_preview is None and self.body_preview is not None:
            self.request_body_preview = self.body_preview
        if self.headers_json is None:
            self.headers_json = self.request_headers_json
        if self.body_preview is None:
            self.body_preview = self.request_body_preview or self.response_body_preview

    def get_unique_key(self) -> str:
        return (
            f"{self.timestamp}:{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}:"
            f"{self.protocol}:{self.method}:{self.url}"
        )

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "ECaptureEvent":
        url = _clean(value.get("url"))
        parsed = urlsplit(url) if url else None
        payload = {
            key: value[key]
            for key in {item.name for item in fields(cls)}
            if key in value
        }
        payload.update(
            {
                "timestamp": _to_timestamp(value.get("event_time") or value.get("timestamp") or value.get("request_time")),
                "src_ip": _clean(value.get("src_ip")),
                "src_port": _clean(value.get("src_port")),
                "dst_ip": _clean(value.get("dst_ip")),
                "dst_port": _clean(value.get("dst_port")),
                "protocol": _clean(value.get("protocol")) or "HTTPS",
                "domain": _clean(value.get("domain")) or (parsed.hostname if parsed else None),
                "url": url,
                "method": _clean(value.get("method") or value.get("http_method")),
                "http_path": _clean(value.get("http_path")) or _url_path(parsed),
                "response_timestamp": _optional_timestamp(
                    value.get("response_timestamp") or value.get("response_time")
                ),
                "response_status": _to_int(value.get("response_status")),
                "request_headers_json": value.get("request_headers_json") or value.get("headers_json"),
                "request_body_preview": value.get("request_body_preview") or value.get("body_preview"),
                "capture_source": _clean(value.get("capture_source")) or "network_hook",
                "parse_status": _clean(value.get("parse_status")) or "partial",
                "is_complete": bool(value.get("is_complete", False)),
            }
        )
        return cls(**payload)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "event_time": self.timestamp,
            "request_time": self.timestamp,
            "response_time": self.response_timestamp,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "domain": self.domain,
            "url": self.url,
            "resolved_ip": self.resolved_ip,
            "dns_ip": self.resolved_ip,
            "http_method": self.method,
            "method": self.method,
            "http_path": self.http_path,
            "response_status": self.response_status,
            "request_headers_json": self.request_headers_json,
            "request_body_preview": self.request_body_preview,
            "response_headers_json": self.response_headers_json,
            "response_body_preview": self.response_body_preview,
            "content_type": self.content_type,
            "capture_source": self.capture_source,
            "parse_status": self.parse_status,
            "is_complete": self.is_complete,
            "process_name": self.process_name,
            "hook_library": self.hook_library,
            "hook_class": self.hook_class,
            "hook_method": self.hook_method,
            "headers_json": self.request_headers_json,
            "body_preview": self.request_body_preview or self.response_body_preview,
        }


@dataclass
class _TransactionState:
    event: ECaptureEvent
    request_body: bytearray = field(default_factory=bytearray)
    response_body: bytearray = field(default_factory=bytearray)
    request_end: bool = False
    response_end: bool = False
    request_content_length: int | None = None
    response_content_length: int | None = None
    request_content_encoding: str | None = None
    response_content_encoding: str | None = None


class ECaptureParser:
    """Parse decrypted PCAPNG files into correlated HTTP transactions."""

    FIELDS = [
        "frame.number", "frame.time_epoch", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst",
        "tcp.srcport", "tcp.dstport", "tcp.stream", "tls.record.version", "http.request", "http.response",
        "http.request_in", "http.response_in", "http.request.method", "http.host",
        "http.request.uri", "http.request.full_uri", "http.response.code", "http.request.line",
        "http.response.line", "http.file_data", "http2.streamid", "http2.type",
        "http2.flags.end_stream", "http2.headers.method",
        "http2.headers.scheme", "http2.headers.authority", "http2.headers.path", "http2.headers.status",
        "http2.header.name", "http2.header.value", "http2.data.data",
    ]

    def __init__(self, tshark_path: str = "tshark", body_preview_limit: int = 2048):
        self.tshark_path = tshark_path
        self.body_preview_limit = max(int(body_preview_limit or 0), 0)

    def _check_tshark(self) -> bool:
        cached = _TSHARK_AVAILABILITY_CACHE.get(self.tshark_path)
        if cached is not None:
            return cached
        available = shutil.which(self.tshark_path) is not None
        _TSHARK_AVAILABILITY_CACHE[self.tshark_path] = available
        return available

    def parse_pcapng(self, pcapng_path: str, filter_expr: str | None = None) -> list[ECaptureEvent]:
        return list(self.parse_pcapng_stream(pcapng_path, filter_expr=filter_expr))

    def parse_pcapng_stream(
        self, pcapng_path: str, filter_expr: str | None = None
    ) -> Iterator[ECaptureEvent]:
        if not self._check_tshark():
            raise RuntimeError(f"tshark executable not found: {self.tshark_path}")
        with prepared_pcapng(pcapng_path) as prepared_path:
            yield from self._parse_prepared_stream(prepared_path, filter_expr)

    def _parse_prepared_stream(
        self, pcapng_path: str, filter_expr: str | None
    ) -> Iterator[ECaptureEvent]:
        process = subprocess.Popen(
            self._build_command(pcapng_path, filter_expr),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        def packets() -> Iterator[dict[str, Any]]:
            assert process.stdout is not None
            for line in process.stdout:
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict) and isinstance(item.get("layers"), dict):
                    yield item

        try:
            yield from self.parse_ek_packets(packets())
            stderr = process.stderr.read() if process.stderr else ""
            code = process.wait()
            if code != 0:
                raise RuntimeError(f"tshark exited with code {code}: {stderr[:1000]}")
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait()

    def _build_command(self, pcapng_path: str, filter_expr: str | None) -> list[str]:
        command = [self.tshark_path, "-n", "-r", pcapng_path, "-T", "ek"]
        if filter_expr:
            command.extend(["-Y", filter_expr])
        for field_name in self.FIELDS:
            command.extend(["-e", field_name])
        return command

    def parse_ek_packets(self, packets: Iterable[dict[str, Any]]) -> list[ECaptureEvent]:
        http1: dict[str, _TransactionState] = {}
        http2: dict[tuple[str, str], _TransactionState] = {}
        for packet in packets:
            layers = packet.get("layers") or {}
            timestamp = _packet_timestamp(packet, layers)
            if _values(layers, "http_request_method") or _values(layers, "http_response_code"):
                self._consume_http1(layers, timestamp, http1)
            if _values(layers, "http2_streamid"):
                self._consume_http2(layers, timestamp, http2)
        result = [self._finalize(state) for state in [*http1.values(), *http2.values()]]
        return sorted(result, key=lambda item: item.timestamp)

    def _consume_http1(
        self, layers: dict[str, Any], timestamp: float, transactions: dict[str, _TransactionState]
    ) -> None:
        method = _first(layers, "http_request_method")
        frame = _first(layers, "frame_number")
        if method and frame:
            headers = _headers_from_lines(_values(layers, "http_request_line"))
            domain = _first(layers, "http_host")
            path = _first(layers, "http_request_uri")
            state = _TransactionState(
                event=ECaptureEvent(
                    timestamp=timestamp,
                    src_ip=_first(layers, "ip_src", "ipv6_src"),
                    src_port=_first(layers, "tcp_srcport"),
                    dst_ip=_first(layers, "ip_dst", "ipv6_dst"),
                    dst_port=_first(layers, "tcp_dstport"),
                    protocol="HTTP/1.1", domain=domain,
                    url=_first(layers, "http_request_full_uri") or _build_url(
                        domain, path, "https" if _first(layers, "tls_record_version") else "http"
                    ),
                    method=method, http_path=path,
                    request_headers_json=_json_headers(headers),
                ),
                request_end=True,
            )
            state.request_content_length = _header_int(headers, "content-length")
            state.request_content_encoding = headers.get("content-encoding")
            state.request_body.extend(_decode_hex_values(_values(layers, "http_file_data")))
            transactions[frame] = state

        status = _to_int(_first(layers, "http_response_code"))
        request_frame = _first(layers, "http_request_in")
        state = transactions.get(request_frame) if request_frame else None
        if state is None or status is None:
            return
        headers = _headers_from_lines(_values(layers, "http_response_line"))
        state.event.response_timestamp = timestamp
        state.event.response_status = status
        state.event.response_headers_json = _json_headers(headers)
        state.event.content_type = headers.get("content-type")
        state.response_content_length = _header_int(headers, "content-length")
        state.response_content_encoding = headers.get("content-encoding")
        state.response_body.extend(_decode_hex_values(_values(layers, "http_file_data")))
        state.response_end = True

    def _consume_http2(
        self, layers: dict[str, Any], timestamp: float,
        transactions: dict[tuple[str, str], _TransactionState]
    ) -> None:
        tcp_stream = _first(layers, "tcp_stream")
        stream_ids = _values(layers, "http2_streamid")
        positive_ids = [value for value in stream_ids if _to_int(value)]
        if not tcp_stream or not positive_ids:
            return
        method = _first(layers, "http2_headers_method")
        status = _to_int(_first(layers, "http2_headers_status"))
        end_stream = any(_to_bool(value) for value in _values(layers, "http2_flags_end_stream"))
        stream_id = positive_ids[-1]
        key = (tcp_stream, stream_id)
        if method:
            headers = _headers_from_pairs(
                _values(layers, "http2_header_name"), _values(layers, "http2_header_value")
            )
            domain = _first(layers, "http2_headers_authority") or headers.get(":authority")
            path = _first(layers, "http2_headers_path") or headers.get(":path")
            scheme = _first(layers, "http2_headers_scheme") or headers.get(":scheme") or (
                "https" if _first(layers, "tls_record_version") else "http"
            )
            state = _TransactionState(
                event=ECaptureEvent(
                    timestamp=timestamp,
                    src_ip=_first(layers, "ip_src", "ipv6_src"),
                    src_port=_first(layers, "tcp_srcport"),
                    dst_ip=_first(layers, "ip_dst", "ipv6_dst"),
                    dst_port=_first(layers, "tcp_dstport"),
                    protocol="HTTP/2", domain=domain, url=_build_url(domain, path, scheme),
                    method=method, http_path=path, request_headers_json=_json_headers(headers),
                ),
                request_end=end_stream,
            )
            state.request_content_length = _header_int(headers, "content-length")
            state.request_content_encoding = headers.get("content-encoding")
            transactions[key] = state
        if status is not None:
            state = transactions.get(key)
            if state:
                headers = _headers_from_pairs(
                    _values(layers, "http2_header_name"), _values(layers, "http2_header_value")
                )
                state.event.response_timestamp = timestamp
                state.event.response_status = status
                state.event.response_headers_json = _json_headers(headers)
                state.event.content_type = headers.get("content-type")
                state.response_content_length = _header_int(headers, "content-length")
                state.response_content_encoding = headers.get("content-encoding")
                state.response_end = end_stream

        data_values = _values(layers, "http2_data_data")
        if not data_values:
            return
        data_ids = _data_stream_ids(stream_ids, _values(layers, "http2_type"), len(data_values))
        src_ip = _first(layers, "ip_src", "ipv6_src")
        src_port = _first(layers, "tcp_srcport")
        for index, value in enumerate(data_values):
            data_key = (tcp_stream, data_ids[index] if index < len(data_ids) else stream_id)
            state = transactions.get(data_key)
            if state is None:
                continue
            is_request = src_ip == state.event.src_ip and src_port == state.event.src_port
            if is_request:
                state.request_body.extend(_decode_hex_values([value]))
                state.request_end = state.request_end or end_stream
            else:
                state.response_body.extend(_decode_hex_values([value]))
                state.response_end = state.response_end or end_stream
                state.event.response_timestamp = timestamp

    def _finalize(self, state: _TransactionState) -> ECaptureEvent:
        event = state.event
        event.request_body_preview = self._body_preview(
            bytes(state.request_body), state.request_content_encoding
        )
        event.response_body_preview = self._body_preview(
            bytes(state.response_body), state.response_content_encoding
        )
        request_complete = _body_complete(
            state.request_end, state.request_content_length, len(state.request_body)
        )
        response_no_body = event.response_status in {204, 304} or (
            event.method == "HEAD" and event.response_status is not None
        )
        response_complete = event.response_status is not None and (
            response_no_body or _body_complete(
                state.response_end, state.response_content_length, len(state.response_body)
            )
        )
        event.is_complete = request_complete and response_complete
        event.parse_status = "complete" if event.is_complete else "partial"
        event.headers_json = event.request_headers_json
        event.body_preview = event.request_body_preview or event.response_body_preview
        return event

    def _body_preview(self, body: bytes, content_encoding: str | None) -> str | None:
        if not body or self.body_preview_limit <= 0:
            return None
        decoded = body
        encoding = (content_encoding or "").lower()
        try:
            if "gzip" in encoding:
                decoded = gzip.decompress(body)
            elif "deflate" in encoding:
                decoded = zlib.decompress(body)
            elif "br" in encoding:
                import brotli  # type: ignore[import-not-found]

                decoded = brotli.decompress(body)
        except Exception:
            decoded = body
        return decoded[: self.body_preview_limit].decode("utf-8", errors="replace")

    # Kept for callers and older tests that inspect one tshark fields row.
    def _parse_row(self, row: dict[str, Any]) -> ECaptureEvent | None:
        src_ip, dst_ip = _clean(row.get("ip.src")), _clean(row.get("ip.dst"))
        if not src_ip and not dst_ip:
            return None
        method = _clean(row.get("http.request.method") or row.get("http2.headers.method"))
        domain = _clean(row.get("http.host") or row.get("http2.headers.authority"))
        path = _clean(row.get("http.request.uri") or row.get("http2.headers.path"))
        event = ECaptureEvent(
            timestamp=_to_timestamp(row.get("frame.time_epoch")), src_ip=src_ip,
            src_port=_clean(row.get("tcp.srcport") or row.get("udp.srcport")),
            dst_ip=dst_ip, dst_port=_clean(row.get("tcp.dstport") or row.get("udp.dstport")),
            protocol="HTTPS" if _clean(row.get("_ws.col.Protocol")) == "HTTP2" else (
                _clean(row.get("_ws.col.Protocol")) or "HTTPS"
            ), domain=domain, url=_clean(row.get("http.request.full_uri")) or _build_url(domain, path),
            method=method, http_path=path,
            body_preview=_legacy_body_preview(row.get("http.file_data") or row.get("http2.data.data"), self.body_preview_limit),
        )
        return event


def is_https_transaction(url: object, protocol: object = None) -> bool:
    """Require an HTTPS URL, or explicit HTTPS evidence when no URL is available."""
    text = str(url or "").strip()
    if not text:
        return str(protocol or "").strip().upper() == "HTTPS"
    try:
        parsed = urlsplit(text)
        return parsed.scheme.lower() == "https" and bool(parsed.hostname)
    except ValueError:
        return False


def _values(layers: dict[str, Any], *names: str) -> list[str]:
    for name in names:
        raw = layers.get(name)
        if raw is None:
            continue
        return [str(value) for value in raw] if isinstance(raw, list) else [str(raw)]
    return []


def _first(layers: dict[str, Any], *names: str) -> str | None:
    values = _values(layers, *names)
    return _clean(values[0]) if values else None


def _clean(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _to_int(value: object) -> int | None:
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None


def _to_bool(value: object) -> bool:
    return str(value or "").lower() in {"1", "true", "yes"}


def _to_timestamp(value: object) -> float:
    try:
        timestamp = float(value)
        # tshark EK wraps frame.time_epoch in a top-level millisecond timestamp.
        # Normalize both forms so hook and pcapng events share Unix seconds.
        return timestamp / 1000 if timestamp >= 100_000_000_000 else timestamp
    except (TypeError, ValueError):
        text = str(value or "").strip().replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(text).timestamp()
        except ValueError:
            return 0.0


def _optional_timestamp(value: object) -> float | None:
    return None if value in (None, "") else _to_timestamp(value)


def _packet_timestamp(packet: dict[str, Any], layers: dict[str, Any]) -> float:
    # The EK envelope timestamp is milliseconds; frame.time_epoch is the
    # packet timestamp in seconds and retains the precision needed for merge.
    return _to_timestamp(_first(layers, "frame_time_epoch") or packet.get("timestamp"))


def _headers_from_lines(lines: Iterable[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in lines:
        line = line.strip().rstrip("\r\n")
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        _add_header(result, name, value)
    return result


def _headers_from_pairs(names: list[str], values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, value in zip(names, values):
        _add_header(result, name, value)
    return result


def _add_header(headers: dict[str, str], name: str, value: str) -> None:
    name = name.strip().lower()
    if not name:
        return
    headers[name] = f"{headers[name]}, {value.strip()}" if name in headers else value.strip()


def _json_headers(headers: dict[str, str]) -> str | None:
    return json.dumps(headers, ensure_ascii=False) if headers else None


def _header_int(headers: dict[str, str], name: str) -> int | None:
    value = headers.get(name)
    return _to_int(value.split(",", 1)[0]) if value else None


def _decode_hex_values(values: Iterable[str]) -> bytes:
    output = bytearray()
    for value in values:
        normalized = "".join(character for character in value if character in "0123456789abcdefABCDEF")
        if len(normalized) % 2:
            normalized = normalized[:-1]
        try:
            output.extend(bytes.fromhex(normalized))
        except ValueError:
            continue
    return bytes(output)


def _build_url(domain: str | None, path: str | None, scheme: str = "https") -> str | None:
    if not domain:
        return None
    path = path or "/"
    if path.startswith(("http://", "https://")):
        return path
    return f"{scheme or 'https'}://{domain}{path if path.startswith('/') else '/' + path}"


def _url_path(parsed: Any) -> str | None:
    if not parsed:
        return None
    return (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")


def _data_stream_ids(stream_ids: list[str], frame_types: list[str], count: int) -> list[str]:
    if len(stream_ids) == len(frame_types):
        values = [stream_id for stream_id, frame_type in zip(stream_ids, frame_types) if frame_type == "0"]
        if values:
            return values[:count]
    positive = [stream_id for stream_id in stream_ids if _to_int(stream_id)]
    return positive[-count:]


def _body_complete(end_seen: bool, content_length: int | None, captured_length: int) -> bool:
    return captured_length >= content_length if content_length is not None else end_seen


def _legacy_body_preview(value: object, limit: int) -> str | None:
    text = _clean(value)
    return text[:limit] if text and limit > 0 else None
