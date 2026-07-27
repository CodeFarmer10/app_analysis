from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from analyzers.artifact_policy import MAX_BLOB_BYTES, MAX_TEXT_FILE_BYTES, TEXT_EXTENSIONS
from analyzers.ioc_extractor import SourceIocCollector, SourceIocResult, iter_artifact_blobs
from analyzers.sdk_detector import (
    SdkDetectResult,
    SdkScanCollector,
    load_sdk_fingerprints,
)


@dataclass(frozen=True)
class SourceArtifactScanResult:
    iocs: SourceIocResult
    sdks: SdkDetectResult


def scan_source_artifacts(
    input_path: str,
    *,
    is_packed: bool,
    jadx_output_dir: str | None = None,
    jadx_sources_dir: str | None = None,
) -> SourceArtifactScanResult:
    """Scan raw and JADX artifacts once and feed both IOC and SDK collectors."""
    ioc_collector = SourceIocCollector()
    source_root = jadx_output_dir if jadx_output_dir and Path(jadx_output_dir).is_dir() else None
    sdk_collector = SdkScanCollector(load_sdk_fingerprints(), source_root=source_root)

    for source_file, data in iter_artifact_blobs(input_path):
        ioc_collector.scan_blob(source_file, data)
        if len(data) <= MAX_BLOB_BYTES:
            sdk_collector.scan_blob(source_file, data)
    ioc_collector.finalize_blobs()

    if source_root:
        sources_root = _resolve_sources_root(source_root, jadx_sources_dir)
        for source_file, ioc_source_file, text, sdk_eligible in _iter_jadx_texts(
            source_root,
            sources_root,
        ):
            if not is_packed and ioc_source_file is not None and ioc_collector.has_dex_iocs:
                ioc_collector.scan_java_source(ioc_source_file, text)
            if sdk_eligible:
                sdk_collector.scan_source(source_file, text)

    return SourceArtifactScanResult(
        iocs=ioc_collector.build_result(),
        sdks=sdk_collector.build_result(),
    )


def _resolve_sources_root(output_dir: str, sources_dir: str | None) -> Path:
    candidate = Path(sources_dir).resolve() if sources_dir else Path(output_dir, "sources").resolve()
    if candidate.is_dir():
        return candidate
    return Path(output_dir).resolve()


def _iter_jadx_texts(
    output_dir: str,
    sources_root: Path,
) -> Iterator[tuple[str, str | None, str, bool]]:
    output_root = Path(output_dir).resolve()
    files = sorted(item for item in output_root.rglob("*") if item.is_file())
    for file_path in files:
        extension = file_path.suffix.lower()
        ioc_source_file = _ioc_source_file(file_path, sources_root)
        try:
            file_size = file_path.stat().st_size
        except OSError:
            continue
        if file_size > MAX_TEXT_FILE_BYTES:
            ioc_source_file = None
        sdk_eligible = extension in TEXT_EXTENSIONS and file_size <= MAX_TEXT_FILE_BYTES
        if ioc_source_file is None and not sdk_eligible:
            continue
        try:
            text = _read_source_text(file_path)
        except OSError:
            continue
        yield (
            file_path.relative_to(output_root).as_posix(),
            ioc_source_file,
            text,
            sdk_eligible,
        )


def _ioc_source_file(file_path: Path, sources_root: Path) -> str | None:
    if file_path.suffix.lower() != ".java":
        return None
    try:
        return file_path.relative_to(sources_root).as_posix()
    except ValueError:
        return None


def _read_source_text(file_path: Path) -> str:
    return file_path.read_text(encoding="utf-8", errors="ignore")
