from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path

from protection.dex_filter import FRAMEWORK_PREFIXES


logger = logging.getLogger(__name__)

# Cap inflated output, not compressed input. This avoids zip-bomb memory spikes
# while still scanning the full compressed entry up to the next local header.
MAX_INFLATE_BYTES = 64 * 1024 * 1024

PATTERNS = {
    "url": re.compile(r'https?://[^\s"\'<>)\]\\]{4,}'),
    "email": re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
    "phone": re.compile(r"(?<![0-9A-Za-z_])1[3-9]\d{9}(?![0-9A-Za-z_])"),
}

COMMON_TLDS = {
    "app",
    "art",
    "asia",
    "au",
    "biz",
    "br",
    "ca",
    "cc",
    "click",
    "club",
    "cloud",
    "cn",
    "co",
    "com",
    "de",
    "edu",
    "fr",
    "fun",
    "gov",
    "hk",
    "icu",
    "in",
    "info",
    "ink",
    "io",
    "jp",
    "kr",
    "link",
    "live",
    "ltd",
    "me",
    "mobi",
    "net",
    "online",
    "org",
    "pro",
    "ren",
    "ru",
    "sg",
    "shop",
    "site",
    "store",
    "tech",
    "top",
    "tv",
    "tw",
    "uk",
    "us",
    "vip",
    "wang",
    "win",
    "work",
    "xyz",
}

NOISE_HOST_PREFIXES = (
    "android.",
    "androidx.",
    "dalvik.",
    "java.",
    "javax.",
    "kotlin.",
    "kotlinx.",
    "okhttp3.",
    "okio.",
    "org.intellij.",
    "org.jetbrains.",
    "org.json.",
    "org.w3c.",
    "org.xml.",
    "org.xmlpull.",
    "schemas.android.com",
    "sun.",
)
NOISE_URL_SUBSTR = (
    ".apache.org/",
    "android.googlesource.com",
    "issuetracker.google.com",
    "java.sun.com",
    "json-schema.org",
    "mozilla.org/mpl",
    "ns.adobe.com",
    "publicsuffix.org",
    "schemas.android.com",
    "schemas.openxmlformats.org",
    "slf4j.org",
    "www.w3.org",
    "xmlpull.org",
)
NOISE_SOURCE_RE = re.compile(r"(META-INF/.*\.(RSA|DSA|EC|SF|MF)$|NOTICE|LICENSE)", re.I)
FRAMEWORK_PATH_PREFIXES = tuple(prefix[1:] for prefix in FRAMEWORK_PREFIXES) + (
    "javax/xml/",
    "org/xml/",
    "org/xmlpull/",
)
MAX_ITEMS_PER_TYPE = 200
MAX_SOURCES_PER_ITEM = 5


@dataclass
class SourceIocItem:
    value: str
    sources: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "value": self.value,
            "sources": self.sources,
        }


@dataclass
class SourceIocResult:
    items: dict[str, list[SourceIocItem]] = field(
        default_factory=lambda: {key: [] for key in PATTERNS}
    )

    def to_static_fields(self) -> dict:
        items = {key: [item.to_dict() for item in values] for key, values in self.items.items()}
        return {
            "source_urls": items.get("url", []),
            "source_emails": items.get("email", []),
            "source_phones": items.get("phone", []),
        }

    @classmethod
    def from_static_fields(cls, fields: dict | None) -> "SourceIocResult":
        """从已入库的静态字段（to_static_fields 形态）还原结果，用于与脱壳后结果合并。"""
        result = cls()
        field_map = {"url": "source_urls", "email": "source_emails", "phone": "source_phones"}
        fields = fields or {}
        for ioc_type, field_name in field_map.items():
            items: list[SourceIocItem] = []
            for entry in fields.get(field_name) or []:
                if isinstance(entry, dict):
                    value = str(entry.get("value") or "").strip()
                    sources = [str(source) for source in (entry.get("sources") or [])]
                else:
                    value = str(entry or "").strip()
                    sources = []
                if value:
                    items.append(SourceIocItem(value=value, sources=sources))
            result.items[ioc_type] = items
        return result

    def merge(self, other: "SourceIocResult") -> "SourceIocResult":
        """按 value 去重合并两份结果，sources 取并集；同值若已有 java 反编译来源则丢弃 dex 字节来源（java 优先）。"""
        merged = SourceIocResult()
        for ioc_type in PATTERNS:
            by_value: dict[str, list[str]] = {}
            order: list[str] = []
            for item in list(self.items.get(ioc_type, [])) + list(other.items.get(ioc_type, [])):
                if item.value not in by_value:
                    by_value[item.value] = []
                    order.append(item.value)
                bucket = by_value[item.value]
                for source in item.sources:
                    if source not in bucket:
                        bucket.append(source)
            merged.items[ioc_type] = [
                SourceIocItem(value=value, sources=_prefer_java_sources(by_value[value])[:MAX_SOURCES_PER_ITEM])
                for value in order[:MAX_ITEMS_PER_TYPE]
            ]
        return merged


def extract_source_iocs(apk_path: str, *, is_packed: bool, jadx_timeout: int = 300) -> SourceIocResult:
    # 无论是否加壳都先 carve/字节扫描提取候选 IOC。加壳包真实 dex 被加密，jadx 反编译
    # 无意义，故跳过 jadx 校验、仅保留资源等来源；真实 dex 的 IOC 由脱壳后单独提取再合并。
    found = _extract_from_apk(apk_path)
    java_sources: dict[str, list[str]] = {}

    if not is_packed:
        dex_iocs = [
            value
            for values in found.values()
            for value, sources in values.items()
            if _is_dex_source(sources)
        ]
        if dex_iocs:
            try:
                java_sources = _locate_with_jadx(apk_path, dex_iocs, timeout=jadx_timeout)
            except Exception as exc:  # pragma: no cover - depends on jadx/runtime
                logger.warning("source ioc jadx locate failed path=%s err=%s", apk_path, exc)

    result = SourceIocResult()
    for ioc_type, values in found.items():
        items: list[SourceIocItem] = []
        for value, sources in sorted(values.items(), key=lambda item: item[0]):
            located_sources = java_sources.get(value, [])
            if _all_framework_sources(located_sources):
                continue
            normalized_sources = located_sources or sorted(sources)
            items.append(
                SourceIocItem(
                    value=value,
                    sources=normalized_sources[:MAX_SOURCES_PER_ITEM],
                )
            )
            if len(items) >= MAX_ITEMS_PER_TYPE:
                break
        result.items[ioc_type] = items
    return result


def _extract_from_apk(path: str) -> dict[str, dict[str, set[str]]]:
    found: dict[str, dict[str, set[str]]] = {key: {} for key in PATTERNS}
    for label, blob in _iter_blobs(path):
        for text in _iter_texts(blob):
            for ioc_type, pattern in PATTERNS.items():
                for match in pattern.findall(text):
                    if _is_noise(ioc_type, match):
                        continue
                    found[ioc_type].setdefault(match, set()).add(label)

    for values in found.values():
        for value in list(values):
            sources = values[value]
            if sources and all(NOISE_SOURCE_RE.search(source) for source in sources):
                del values[value]
    return found


def _iter_blobs(path: str):
    if os.path.isdir(path):
        for root, _dirs, files in os.walk(path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                rel_path = os.path.relpath(file_path, path)
                try:
                    data = Path(file_path).read_bytes()
                except OSError:
                    continue
                if data[:4] == b"PK\x03\x04":
                    yield from _zip_carve(data, rel_path)
                else:
                    yield rel_path, data
        return

    data = Path(path).read_bytes()
    if data[:4] == b"PK\x03\x04":
        yield from _zip_carve(data, "")
    else:
        yield os.path.basename(path), data


def _zip_carve(data: bytes, prefix: str, depth: int = 0):
    sig = b"PK\x03\x04"
    offsets: list[int] = []
    offset = data.find(sig)
    while offset >= 0:
        offsets.append(offset)
        offset = data.find(sig, offset + 4)

    for index, offset in enumerate(offsets):
        try:
            method = int.from_bytes(data[offset + 8 : offset + 10], "little")
            name_len = int.from_bytes(data[offset + 26 : offset + 28], "little")
            extra_len = int.from_bytes(data[offset + 28 : offset + 30], "little")
            name = data[offset + 30 : offset + 30 + name_len].decode("utf-8", "replace")
            name = name or f"<entry@{offset}>"
            start = offset + 30 + name_len + extra_len
            next_offset = offsets[index + 1] if index + 1 < len(offsets) else len(data)
            if method == 8:
                blob = zlib.decompressobj(-15).decompress(data[start:next_offset], MAX_INFLATE_BYTES)
            else:
                blob = data[start:next_offset]
            label = f"{prefix}!{name}" if prefix else name
            if depth < 2 and blob[:4] == sig:
                yield from _zip_carve(blob, label, depth + 1)
            else:
                yield label, blob
        except Exception:
            continue

    if not offsets:
        yield (f"{prefix}!<unassigned>" if prefix else "<unassigned>"), data


def _iter_texts(data: bytes):
    for match in re.finditer(rb"[\x20-\x7e]{4,}", data):
        yield match.group().decode("latin1")
    try:
        decoded = data.decode("utf-16-le", "ignore")
    except Exception:
        return
    for match in re.finditer(r"[\x20-\x7e]{4,}", decoded):
        yield match.group()


def _jadx_inputs(path: str) -> list[str]:
    """jadx 输入：APK 直接传文件；脱壳 dex 目录则展开成各 .dex 文件多输入。"""
    if not os.path.isdir(path):
        return [path]
    dex_files = sorted(
        os.path.join(root, name)
        for root, _dirs, files in os.walk(path)
        for name in files
        if name.endswith(".dex")
    )
    return dex_files or [path]


def _locate_with_jadx(apk_path: str, iocs: list[str], *, timeout: int) -> dict[str, list[str]]:
    jadx = shutil.which("jadx")
    if not jadx:
        raise RuntimeError("未找到 jadx，请先安装 jadx 后再定位 Java 代码")

    with tempfile.TemporaryDirectory(prefix="source-ioc-jadx-") as output_dir:
        completed = subprocess.run(
            [jadx, "-q", "-d", output_dir, *_jadx_inputs(apk_path)],
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
        if completed.returncode != 0:
            stderr = (completed.stderr or completed.stdout or "").strip()
            raise RuntimeError(stderr or f"jadx 执行失败，退出码 {completed.returncode}")
        sources_dir = os.path.join(output_dir, "sources")
        if not os.path.isdir(sources_dir):
            sources_dir = output_dir
        return _locate_in_sources(iocs, sources_dir)


def _locate_in_sources(iocs: list[str], sources_dir: str) -> dict[str, list[str]]:
    locations: dict[str, list[str]] = {value: [] for value in iocs}
    ioc_set = set(iocs)
    if not ioc_set or not os.path.isdir(sources_dir):
        return locations

    for root, _dirs, files in os.walk(sources_dir):
        for file_name in files:
            if not file_name.endswith(".java"):
                continue
            file_path = os.path.join(root, file_name)
            try:
                text = Path(file_path).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            hits = [value for value in ioc_set if value in text]
            if not hits:
                continue
            rel_path = os.path.relpath(file_path, sources_dir)
            for value in hits:
                if len(locations[value]) < MAX_SOURCES_PER_ITEM and rel_path not in locations[value]:
                    locations[value].append(rel_path)
    return locations


def _host_of(url: str) -> str:
    match = re.match(r"https?://([^/:?#]+)", url, re.I)
    return (match.group(1) if match else "").lower()


def _bad_host(host: str) -> bool:
    if not host or host.startswith(NOISE_HOST_PREFIXES):
        return True
    if re.match(r"^[\d.]+(:\d+)?$", host):
        return False
    return host.split(":")[0].rsplit(".", 1)[-1].lower() not in COMMON_TLDS


def _is_noise(ioc_type: str, value: str) -> bool:
    lowered = value.lower()
    if ioc_type == "url":
        if any(fragment in lowered for fragment in NOISE_URL_SUBSTR):
            return True
        return _bad_host(_host_of(value))
    if ioc_type == "email":
        return value.rsplit(".", 1)[-1].lower() not in COMMON_TLDS
    return False


def _is_dex_source(sources: set[str]) -> bool:
    return any(".dex" in source.lower() for source in sources)


def _prefer_java_sources(sources: list[str]) -> list[str]:
    """同一 IOC 若已有 java 反编译来源，则丢弃 dex 字节来源（java 来源更精确，优先保留）。"""
    if any(source.endswith(".java") for source in sources):
        return [source for source in sources if not source.endswith(".dex")]
    return sources


def _location_is_framework(java_location: str) -> bool:
    path = java_location.split("sources/", 1)[-1]
    return path.startswith(FRAMEWORK_PATH_PREFIXES)


def _all_framework_sources(java_sources: list[str]) -> bool:
    return bool(java_sources) and all(_location_is_framework(source) for source in java_sources)
