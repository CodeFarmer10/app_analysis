from __future__ import annotations

import copy
import re
import zipfile
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Iterator

import yaml

from analyzers.artifact_policy import (
    MAX_BLOB_BYTES,
    MAX_TEXT_FILE_BYTES,
    TEXT_EXTENSIONS,
    should_skip_artifact,
)
from analyzers.java_source_index import JavaSourceIndex, JavaSourceUnit


DEFAULT_FINGERPRINT_PATH = Path(__file__).resolve().parents[1] / "tools" / "sdk_fingerprints.yaml"
SDK_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_]*$")
MAX_RECOGNITION_EVIDENCE = 5
MAX_OCCURRENCES_PER_VALUE = 5
MAX_EVIDENCE_CHARS = 300
MAX_PARAM_VALUE_CHARS = 512
JAVA_IDENTIFIER = r"[A-Za-z_$][A-Za-z0-9_$]*"


@dataclass(frozen=True)
class SdkCallExtractor:
    class_name: str
    method_name: str
    params: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class SdkFingerprint:
    sdk_id: str
    sdk_name: str
    sdk_type: str
    vendor: str
    package_prefixes: tuple[str, ...]
    recognition_patterns: tuple[re.Pattern[str], ...]
    param_patterns: dict[str, tuple[re.Pattern[str], ...]]
    call_extractors: tuple[SdkCallExtractor, ...]


@dataclass
class SdkDetectResult:
    findings: list[dict]

    def merge(self, other: "SdkDetectResult") -> "SdkDetectResult":
        merged: dict[str, dict] = {}
        order: list[str] = []
        for source in (self.findings, other.findings):
            for raw_finding in source:
                sdk_id = str(raw_finding.get("sdk_id") or "").strip()
                if not sdk_id:
                    continue
                if sdk_id not in merged:
                    merged[sdk_id] = copy.deepcopy(raw_finding)
                    order.append(sdk_id)
                    continue
                _merge_finding(merged[sdk_id], raw_finding)
        return SdkDetectResult(findings=[merged[sdk_id] for sdk_id in order])


def load_sdk_fingerprints(path: str | Path | None = None) -> tuple[SdkFingerprint, ...]:
    fingerprint_path = Path(path or DEFAULT_FINGERPRINT_PATH).resolve()
    try:
        modified_at = fingerprint_path.stat().st_mtime_ns
    except OSError as exc:
        raise ValueError(f"SDK 指纹库不存在: {fingerprint_path}") from exc
    return _load_sdk_fingerprints_cached(str(fingerprint_path), modified_at)


@lru_cache(maxsize=8)
def _load_sdk_fingerprints_cached(path: str, modified_at: int) -> tuple[SdkFingerprint, ...]:
    _ = modified_at
    try:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"SDK 指纹库读取失败: {exc}") from exc
    if not isinstance(raw, list) or not raw:
        raise ValueError("SDK 指纹库根节点必须是非空列表")

    fingerprints: list[SdkFingerprint] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"SDK 指纹第 {index} 项必须是对象")
        sdk_id = _required_text(item, "sdk_id", index)
        if not SDK_ID_PATTERN.fullmatch(sdk_id):
            raise ValueError(f"SDK 指纹第 {index} 项 sdk_id 格式无效: {sdk_id}")
        if sdk_id in seen_ids:
            raise ValueError(f"SDK 指纹 sdk_id 重复: {sdk_id}")
        seen_ids.add(sdk_id)

        prefixes_raw = item.get("package_prefix")
        if not isinstance(prefixes_raw, list) or not prefixes_raw:
            raise ValueError(f"SDK {sdk_id} 的 package_prefix 必须是非空列表")
        prefixes = tuple(
            dict.fromkeys(
                str(value).strip().rstrip(".")
                for value in prefixes_raw
                if str(value).strip()
            )
        )
        if not prefixes:
            raise ValueError(f"SDK {sdk_id} 的 package_prefix 不能为空")

        regex_raw = item.get("param_regex")
        if not isinstance(regex_raw, dict):
            raise ValueError(f"SDK {sdk_id} 的 param_regex 必须是对象")
        compiled: dict[str, tuple[re.Pattern[str], ...]] = {}
        for param_name, patterns in regex_raw.items():
            normalized_name = str(param_name).strip()
            if not normalized_name or not isinstance(patterns, list) or not patterns:
                raise ValueError(f"SDK {sdk_id} 的参数 {normalized_name or '<empty>'} 必须配置正则列表")
            compiled_patterns: list[re.Pattern[str]] = []
            for pattern_text in patterns:
                if not isinstance(pattern_text, str) or not pattern_text.strip():
                    raise ValueError(f"SDK {sdk_id} 的参数 {normalized_name} 存在空正则")
                try:
                    pattern = re.compile(pattern_text, re.MULTILINE)
                except re.error as exc:
                    raise ValueError(f"SDK {sdk_id} 的参数 {normalized_name} 正则无效: {exc}") from exc
                if not pattern.groupindex:
                    raise ValueError(f"SDK {sdk_id} 的参数 {normalized_name} 正则必须包含命名分组")
                if normalized_name not in pattern.groupindex:
                    raise ValueError(f"SDK {sdk_id} 的参数 {normalized_name} 正则缺少同名分组")
                compiled_patterns.append(pattern)
            compiled[normalized_name] = tuple(compiled_patterns)

        recognition_patterns = _load_recognition_patterns(item.get("recognition_regex"), sdk_id)
        call_extractors = _load_call_extractors(item.get("call_extract"), sdk_id)

        fingerprints.append(
            SdkFingerprint(
                sdk_id=sdk_id,
                sdk_name=_required_text(item, "sdk_name", index),
                sdk_type=_required_text(item, "sdk_type", index),
                vendor=_required_text(item, "vendor", index),
                package_prefixes=prefixes,
                recognition_patterns=recognition_patterns,
                param_patterns=compiled,
                call_extractors=call_extractors,
            )
        )
    return tuple(fingerprints)


def detect_sdks(
    input_path: str,
    *,
    jadx_output_dir: str | None = None,
    fingerprint_path: str | Path | None = None,
) -> SdkDetectResult:
    fingerprints = load_sdk_fingerprints(fingerprint_path)
    source_root = jadx_output_dir if jadx_output_dir and Path(jadx_output_dir).is_dir() else None
    collector = SdkScanCollector(fingerprints, source_root=source_root)
    for source_file, data in _iter_input_blobs(input_path):
        collector.scan_blob(source_file, data)
    if source_root:
        for source_file, text in _iter_source_texts(source_root):
            collector.scan_source(source_file, text)
    return collector.build_result()


class SdkScanCollector:
    """Collect SDK evidence and credentials while each artifact is read once."""

    def __init__(
        self,
        fingerprints: tuple[SdkFingerprint, ...],
        *,
        source_root: str | None = None,
    ) -> None:
        self.fingerprints = fingerprints
        self.fingerprint_list = list(fingerprints)
        self.matches: dict[str, dict] = {
            item.sdk_id: {"prefixes": [], "evidence": []} for item in fingerprints
        }
        self.finding_by_id: dict[str, dict] = {
            item.sdk_id: {"credentials": []} for item in fingerprints
        }
        self.recognition_fingerprints = [item for item in fingerprints if item.recognition_patterns]
        self.java_index = JavaSourceIndex(source_root) if source_root else None

    def scan_blob(self, source_file: str, data: bytes) -> None:
        self._scan_prefix_bytes(source_file, data)
        for text in _decode_blob_texts(data):
            self._scan_text(source_file, text, structured_java=False)

    def scan_source(self, source_file: str, text: str) -> None:
        self._scan_source_path(source_file)
        self._scan_text(
            source_file,
            text,
            structured_java=Path(source_file).suffix.lower() == ".java",
        )

    def build_result(self) -> SdkDetectResult:
        findings: list[dict] = []
        for fingerprint in self.fingerprints:
            match = self.matches[fingerprint.sdk_id]
            if not match["prefixes"]:
                continue
            if fingerprint.recognition_patterns and not match.get("recognition_matched"):
                continue
            finding = _new_finding(fingerprint, match)
            finding["credentials"] = copy.deepcopy(
                self.finding_by_id[fingerprint.sdk_id].get("credentials") or []
            )
            findings.append(finding)
        return SdkDetectResult(findings=findings)

    def _scan_prefix_bytes(self, source_file: str, data: bytes) -> None:
        for fingerprint in self.fingerprints:
            for prefix in fingerprint.package_prefixes:
                if _blob_contains_prefix(data, prefix):
                    _record_prefix_match(self.matches[fingerprint.sdk_id], prefix, source_file)

    def _scan_source_path(self, source_file: str) -> None:
        normalized_path = source_file.replace("\\", "/").replace("/", ".")
        for fingerprint in self.fingerprints:
            for prefix in fingerprint.package_prefixes:
                if re.search(rf"(?:^|\.){re.escape(prefix)}(?:\.|$)", normalized_path):
                    _record_prefix_match(self.matches[fingerprint.sdk_id], prefix, source_file)

    def _scan_text(self, source_file: str, text: str, *, structured_java: bool) -> None:
        _match_recognition_patterns(
            self.recognition_fingerprints,
            self.matches,
            source_file,
            text,
        )
        if structured_java and self.java_index is not None:
            candidate_extractors = [
                (fingerprint, extractor)
                for fingerprint in self.fingerprints
                for extractor in fingerprint.call_extractors
                if _is_call_candidate(text, extractor)
            ]
            unit = self.java_index.register_source(source_file, text) if candidate_extractors else None
            for fingerprint, extractor in candidate_extractors:
                _extract_call_credentials(
                    self.finding_by_id[fingerprint.sdk_id],
                    extractor,
                    source_file,
                    text,
                    self.java_index,
                    unit,
                )
        _extract_regex_credentials(
            self.fingerprint_list,
            self.finding_by_id,
            source_file,
            text,
        )


def _load_call_extractors(raw: object, sdk_id: str) -> tuple[SdkCallExtractor, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise ValueError(f"SDK {sdk_id} 的 call_extract 必须是列表")
    extractors: list[SdkCallExtractor] = []
    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"SDK {sdk_id} 的 call_extract 第 {index} 项必须是对象")
        class_name = str(item.get("class_name") or "").strip()
        method_name = str(item.get("method_name") or "").strip()
        params_raw = item.get("params")
        if not class_name or not method_name or not isinstance(params_raw, dict) or not params_raw:
            raise ValueError(f"SDK {sdk_id} 的 call_extract 第 {index} 项配置不完整")
        params: list[tuple[str, int]] = []
        for param_name, argument_index in params_raw.items():
            normalized_name = str(param_name).strip()
            if not normalized_name or isinstance(argument_index, bool) or not isinstance(argument_index, int):
                raise ValueError(f"SDK {sdk_id} 的调用参数 {normalized_name or '<empty>'} 下标无效")
            if argument_index < 0:
                raise ValueError(f"SDK {sdk_id} 的调用参数 {normalized_name} 下标不能为负数")
            params.append((normalized_name, argument_index))
        extractors.append(SdkCallExtractor(class_name, method_name, tuple(params)))
    return tuple(extractors)


def _load_recognition_patterns(raw: object, sdk_id: str) -> tuple[re.Pattern[str], ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or not raw:
        raise ValueError(f"SDK {sdk_id} 的 recognition_regex 必须是非空列表")
    patterns: list[re.Pattern[str]] = []
    for pattern_text in raw:
        if not isinstance(pattern_text, str) or not pattern_text.strip():
            raise ValueError(f"SDK {sdk_id} 的 recognition_regex 存在空正则")
        try:
            patterns.append(re.compile(pattern_text, re.MULTILINE))
        except re.error as exc:
            raise ValueError(f"SDK {sdk_id} 的 recognition_regex 无效: {exc}") from exc
    return tuple(patterns)


def _required_text(item: dict, field_name: str, index: int) -> str:
    value = str(item.get(field_name) or "").strip()
    if not value:
        raise ValueError(f"SDK 指纹第 {index} 项缺少 {field_name}")
    return value


def _iter_input_blobs(path: str) -> Iterator[tuple[str, bytes]]:
    input_path = Path(path)
    if input_path.is_dir():
        for file_path in sorted(item for item in input_path.rglob("*") if item.is_file()):
            try:
                file_size = file_path.stat().st_size
                if file_size > MAX_BLOB_BYTES or should_skip_artifact(file_path.name, file_size):
                    continue
                yield file_path.relative_to(input_path).as_posix(), file_path.read_bytes()
            except OSError:
                continue
        return

    try:
        with zipfile.ZipFile(input_path) as archive:
            for info in archive.infolist():
                if (
                    info.is_dir()
                    or info.file_size > MAX_BLOB_BYTES
                    or should_skip_artifact(info.filename, info.file_size)
                ):
                    continue
                try:
                    yield info.filename, archive.read(info)
                except (OSError, RuntimeError, zipfile.BadZipFile):
                    continue
            return
    except (OSError, zipfile.BadZipFile):
        pass

    try:
        if input_path.stat().st_size <= MAX_BLOB_BYTES:
            yield input_path.name, input_path.read_bytes()
    except OSError:
        return


def _blob_contains_prefix(data: bytes, prefix: str) -> bool:
    dotted = prefix.encode("utf-8")
    slashed = prefix.replace(".", "/").encode("utf-8")
    return _blob_contains_package_token(data, dotted) or _blob_contains_package_token(data, slashed)


def _blob_contains_package_token(data: bytes, token: bytes) -> bool:
    offset = data.find(token)
    while offset >= 0:
        end = offset + len(token)
        if end == len(data) or data[end : end + 1] in {b".", b"/", b";", b"$", b"\x00"}:
            return True
        offset = data.find(token, offset + 1)
    return False


def _record_prefix_match(bucket: dict, prefix: str, source_file: str) -> None:
    prefixes = bucket["prefixes"]
    evidence = bucket["evidence"]
    if prefix not in prefixes:
        prefixes.append(prefix)
    item = {"source_file": source_file, "evidence": f"命中包名前缀 {prefix}"}
    if item not in evidence and len(evidence) < MAX_RECOGNITION_EVIDENCE:
        evidence.append(item)


def _match_recognition_patterns(
    fingerprints: list[SdkFingerprint],
    matches: dict[str, dict],
    source_file: str,
    text: str,
) -> None:
    for fingerprint in fingerprints:
        bucket = matches[fingerprint.sdk_id]
        if bucket.get("recognition_matched"):
            continue
        if _is_sdk_owned_source(source_file, fingerprint.package_prefixes):
            continue
        for pattern in fingerprint.recognition_patterns:
            match = pattern.search(text)
            if not match:
                continue
            bucket["recognition_matched"] = True
            evidence = bucket["evidence"]
            item = {
                "source_file": source_file,
                "evidence": _evidence_snippet(text, match.start(), match.end()),
            }
            if item not in evidence and len(evidence) < MAX_RECOGNITION_EVIDENCE:
                evidence.append(item)
            break


def _is_sdk_owned_source(source_file: str, package_prefixes: tuple[str, ...]) -> bool:
    if Path(source_file).suffix.lower() not in {".java", ".kt", ".smali"}:
        return False
    normalized = "/" + source_file.replace("\\", "/").strip("/")
    return any(f"/{prefix.replace('.', '/')}/" in normalized for prefix in package_prefixes)


def _iter_source_files(root: str | None, *, extensions: set[str] | None = None) -> Iterator[str]:
    if not root:
        return
    root_path = Path(root)
    allowed_extensions = extensions or TEXT_EXTENSIONS
    for file_path in sorted(item for item in root_path.rglob("*") if item.is_file()):
        if file_path.suffix.lower() not in allowed_extensions:
            continue
        try:
            if file_path.stat().st_size > MAX_TEXT_FILE_BYTES:
                continue
        except OSError:
            continue
        yield file_path.relative_to(root_path).as_posix()


def _iter_source_texts(
    root: str | None,
    *,
    extensions: set[str] | None = None,
) -> Iterator[tuple[str, str]]:
    if not root:
        return
    root_path = Path(root)
    for source_file in _iter_source_files(root, extensions=extensions):
        try:
            text = (root_path / source_file).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        yield source_file, text


def _iter_blob_texts(path: str) -> Iterator[tuple[str, str]]:
    for source_file, data in _iter_input_blobs(path):
        for text in _decode_blob_texts(data):
            yield source_file, text


def _decode_blob_texts(data: bytes) -> Iterator[str]:
    if len(data) > MAX_TEXT_FILE_BYTES:
        chunks = re.findall(rb"[\x20-\x7e\r\n\t]{8,}", data)
        if chunks:
            yield "\n".join(chunk.decode("latin1", "ignore") for chunk in chunks)
        return
    utf8_text = data.decode("utf-8", "ignore")
    if utf8_text:
        yield utf8_text
    if b"\x00" in data:
        utf16_text = data.decode("utf-16-le", "ignore")
        if utf16_text:
            yield utf16_text


def _new_finding(fingerprint: SdkFingerprint, match: dict) -> dict:
    return {
        "sdk_id": fingerprint.sdk_id,
        "sdk_name": fingerprint.sdk_name,
        "sdk_type": fingerprint.sdk_type,
        "vendor": fingerprint.vendor,
        "matched_package_prefixes": list(match["prefixes"]),
        "recognition_evidence": copy.deepcopy(match["evidence"]),
        "credentials": [],
    }


def _evidence_snippet(text: str, start: int, end: int) -> str:
    padding = max((MAX_EVIDENCE_CHARS - (end - start)) // 2, 20)
    snippet = text[max(0, start - padding) : min(len(text), end + padding)]
    normalized = re.sub(r"\s+", " ", snippet).strip()
    return normalized[:MAX_EVIDENCE_CHARS]


def _extract_regex_credentials(
    fingerprints: list[SdkFingerprint],
    finding_by_id: dict[str, dict],
    source_file: str,
    text: str,
) -> None:
    for fingerprint in fingerprints:
        finding = finding_by_id[fingerprint.sdk_id]
        for patterns in fingerprint.param_patterns.values():
            for pattern in patterns:
                for match in pattern.finditer(text):
                    for param_name, value in match.groupdict().items():
                        normalized_value = str(value or "").strip()
                        if not normalized_value or len(normalized_value) > MAX_PARAM_VALUE_CHARS:
                            continue
                        occurrence = {
                            "source_file": source_file,
                            "line": text.count("\n", 0, match.start()) + 1,
                            "evidence": _evidence_snippet(text, match.start(), match.end()),
                        }
                        _add_credential(finding, param_name, normalized_value, occurrence)


def _extract_call_credentials(
    finding: dict,
    extractor: SdkCallExtractor,
    source_file: str,
    text: str,
    java_index: JavaSourceIndex,
    unit: JavaSourceUnit | None,
) -> None:
    for call_start, call_end, arguments in _iter_configured_calls(text, extractor):
        for param_name, argument_index in extractor.params:
            if argument_index >= len(arguments):
                continue
            expression, _argument_start, _argument_end = arguments[argument_index]
            resolved = java_index.resolve(expression, unit)
            if resolved is None:
                continue
            value = resolved.value.strip()
            if not value or len(value) > MAX_PARAM_VALUE_CHARS:
                continue
            occurrence = {
                "source_file": source_file,
                "line": text.count("\n", 0, call_start) + 1,
                "evidence": _evidence_snippet(text, call_start, call_end),
                "expression": expression.strip(),
                "extraction_method": "java_call",
            }
            if resolved.definitions:
                definition = resolved.definitions[0]
                occurrence.update(
                    {
                        "definition_source_file": definition.source_file,
                        "definition_line": definition.line,
                        "definition_evidence": definition.evidence,
                    }
                )
                if len(resolved.definitions) > 1:
                    occurrence["definition_chain"] = [
                        {
                            "source_file": item.source_file,
                            "line": item.line,
                            "evidence": item.evidence,
                        }
                        for item in resolved.definitions
                    ]
            _add_credential(finding, param_name, value, occurrence)


def _iter_configured_calls(
    text: str,
    extractor: SdkCallExtractor,
) -> Iterator[tuple[int, int, list[tuple[str, int, int]]]]:
    simple_class = extractor.class_name.rsplit(".", 1)[-1]
    if not _is_call_candidate(text, extractor):
        return
    call_pattern = re.compile(
        rf"(?<![A-Za-z0-9_$])"
        rf"(?P<receiver>(?:{JAVA_IDENTIFIER}\s*\.\s*)*{re.escape(simple_class)})"
        rf"\s*\.\s*{re.escape(extractor.method_name)}\s*\("
    )
    searchable_text = _mask_java_non_code(text)
    for match in call_pattern.finditer(searchable_text):
        opening = match.end() - 1
        closing = _find_java_call_end(text, opening)
        if closing is None:
            continue
        yield match.start(), closing + 1, _split_java_arguments(text, opening + 1, closing)


def _is_call_candidate(text: str, extractor: SdkCallExtractor) -> bool:
    simple_class = extractor.class_name.rsplit(".", 1)[-1]
    return simple_class in text and extractor.method_name in text


def _find_java_call_end(text: str, opening: int) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    index = opening
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
        elif block_comment:
            if char == "*" and following == "/":
                block_comment = False
                index += 1
        elif quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char == "/" and following == "/":
            line_comment = True
            index += 1
        elif char == "/" and following == "*":
            block_comment = True
            index += 1
        elif char in {'"', "'"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _mask_java_non_code(text: str) -> str:
    chars = list(text)
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    index = 0
    while index < len(chars):
        char = chars[index]
        following = chars[index + 1] if index + 1 < len(chars) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
            else:
                chars[index] = " "
        elif block_comment:
            if char == "*" and following == "/":
                chars[index] = " "
                chars[index + 1] = " "
                block_comment = False
                index += 1
            elif char != "\n":
                chars[index] = " "
        elif quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            if char != "\n":
                chars[index] = " "
        elif char in {'"', "'"}:
            quote = char
            chars[index] = " "
        elif char == "/" and following == "/":
            chars[index] = " "
            chars[index + 1] = " "
            line_comment = True
            index += 1
        elif char == "/" and following == "*":
            chars[index] = " "
            chars[index + 1] = " "
            block_comment = True
            index += 1
        index += 1
    return "".join(chars)


def _split_java_arguments(text: str, start: int, end: int) -> list[tuple[str, int, int]]:
    arguments: list[tuple[str, int, int]] = []
    argument_start = start
    depths = {"(": 0, "[": 0, "{": 0}
    closing = {")": "(", "]": "[", "}": "{"}
    quote: str | None = None
    escaped = False
    line_comment = False
    block_comment = False
    index = start
    while index < end:
        char = text[index]
        following = text[index + 1] if index + 1 < end else ""
        if line_comment:
            if char == "\n":
                line_comment = False
        elif block_comment:
            if char == "*" and following == "/":
                block_comment = False
                index += 1
        elif quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
        elif char == "/" and following == "/":
            line_comment = True
            index += 1
        elif char == "/" and following == "*":
            block_comment = True
            index += 1
        elif char in {'"', "'"}:
            quote = char
        elif char in depths:
            depths[char] += 1
        elif char in closing:
            opener = closing[char]
            depths[opener] = max(0, depths[opener] - 1)
        elif char == "," and not any(depths.values()):
            _append_java_argument(arguments, text, argument_start, index)
            argument_start = index + 1
        index += 1
    _append_java_argument(arguments, text, argument_start, end)
    return arguments


def _append_java_argument(
    arguments: list[tuple[str, int, int]],
    text: str,
    start: int,
    end: int,
) -> None:
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    arguments.append((text[start:end], start, end))


def _add_credential(finding: dict, param_name: str, value: str, occurrence: dict) -> None:
    credentials = finding.setdefault("credentials", [])
    credential = next(
        (
            item
            for item in credentials
            if item.get("param_name") == param_name and item.get("value") == value
        ),
        None,
    )
    if credential is None:
        credential = {"param_name": param_name, "value": value, "occurrences": []}
        credentials.append(credential)
    occurrences = credential["occurrences"]
    occurrence_key = _occurrence_key(occurrence)
    existing_index = next(
        (index for index, item in enumerate(occurrences) if _occurrence_key(item) == occurrence_key),
        None,
    )
    if existing_index is not None:
        existing = occurrences[existing_index]
        if occurrence.get("extraction_method") == "java_call" and existing.get("extraction_method") != "java_call":
            occurrences[existing_index] = occurrence
        return
    if len(occurrences) < MAX_OCCURRENCES_PER_VALUE:
        occurrences.append(occurrence)


def _occurrence_key(occurrence: dict) -> tuple[object, ...]:
    source_file = occurrence.get("source_file")
    line = occurrence.get("line")
    if source_file and line is not None:
        return source_file, line
    return source_file, line, occurrence.get("evidence")


def _merge_finding(target: dict, source: dict) -> None:
    for field_name in ("matched_package_prefixes", "recognition_evidence"):
        target_values = target.setdefault(field_name, [])
        for value in source.get(field_name) or []:
            if value not in target_values:
                target_values.append(copy.deepcopy(value))
    for credential in source.get("credentials") or []:
        if not isinstance(credential, dict):
            continue
        for occurrence in credential.get("occurrences") or [{}]:
            _add_credential(
                target,
                str(credential.get("param_name") or ""),
                str(credential.get("value") or ""),
                copy.deepcopy(occurrence),
            )
