from __future__ import annotations

import functools
import ipaddress
import logging
import os
import re
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from analyzers.artifact_policy import (
    MAX_BLOB_BYTES,
    MAX_TEXT_FILE_BYTES,
    is_media_artifact,
    is_text_artifact,
    should_skip_artifact,
)
from analyzers.jadx_workspace import open_jadx_workspace
from protection.dex_filter import FRAMEWORK_PREFIXES


logger = logging.getLogger(__name__)

# Cap inflated output, not compressed input. This avoids zip-bomb memory spikes
# while still scanning the full compressed entry up to the next local header.
MAX_INFLATE_BYTES = MAX_BLOB_BYTES

DNS_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
DNS_TLD = r"(?:[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?|xn--[A-Za-z0-9-]{1,59})"
URL_HOST = rf"(?:(?:{DNS_LABEL}\.)+{DNS_TLD}|(?:\d{{1,3}}\.){{3}}\d{{1,3}}|\[[0-9A-Fa-f:.]+\])"
URL_PATTERN = re.compile(
    rf'https?://{URL_HOST}(?::\d{{1,5}})?(?=[/?#\s"\'<>)\]\\]|$)[^\s"\'<>)\]\\]*',
    re.IGNORECASE,
)

EMAIL_LOCAL_MAX_CHARS = 32
EMAIL_DOMAIN_MAX_CHARS = 32
EMAIL_LOCAL_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+-"
)
EMAIL_LOCAL_BOUNDARY_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._%+-"
)
EMAIL_DOMAIN_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-"
)
EMAIL_LOCAL = r"[A-Za-z0-9_+-]+(?:\.[A-Za-z0-9_+-]+)*"
EMAIL_DOMAIN_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
EMAIL_TLD = r"(?:[A-Za-z]{2,63}|xn--[A-Za-z0-9-]{1,59})"
EMAIL_CANDIDATE_PATTERN = re.compile(
    rf"{EMAIL_LOCAL}@(?:{EMAIL_DOMAIN_LABEL}\.)+{EMAIL_TLD}",
    re.ASCII,
)

PATTERNS = {
    "url": URL_PATTERN,
    "email": EMAIL_CANDIDATE_PATTERN,
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


class SourceIocCollector:
    """Incrementally collect IOC candidates and their JADX source locations."""

    def __init__(self) -> None:
        self.found: dict[str, dict[str, set[str]]] = {key: {} for key in PATTERNS}
        self.java_sources: dict[str, list[str]] = {}
        self._dex_iocs: set[str] = set()
        self._blobs_finalized = False

    def scan_blob(self, label: str, blob: bytes) -> None:
        if self._blobs_finalized:
            raise RuntimeError("IOC blob scanning already finalized")
        for text in _iter_texts(blob):
            for ioc_type, pattern in PATTERNS.items():
                for match in _iter_ioc_matches(ioc_type, pattern, text):
                    if _is_noise(ioc_type, match):
                        continue
                    self.found[ioc_type].setdefault(match, set()).add(label)

    def finalize_blobs(self) -> None:
        if self._blobs_finalized:
            return
        for values in self.found.values():
            for value in list(values):
                sources = values[value]
                if sources and all(NOISE_SOURCE_RE.search(source) for source in sources):
                    del values[value]
        self._dex_iocs = {
            value
            for values in self.found.values()
            for value, sources in values.items()
            if _is_dex_source(sources)
        }
        self.java_sources = {value: [] for value in self._dex_iocs}
        self._blobs_finalized = True

    @property
    def has_dex_iocs(self) -> bool:
        self.finalize_blobs()
        return bool(self._dex_iocs)

    def scan_java_source(self, source_file: str, text: str) -> None:
        self.finalize_blobs()
        for value in self._dex_iocs:
            if value not in text:
                continue
            locations = self.java_sources[value]
            if len(locations) < MAX_SOURCES_PER_ITEM and source_file not in locations:
                locations.append(source_file)

    def build_result(self) -> SourceIocResult:
        self.finalize_blobs()
        result = SourceIocResult()
        for ioc_type, values in self.found.items():
            items: list[SourceIocItem] = []
            for value, sources in sorted(values.items(), key=lambda item: item[0]):
                located_sources = self.java_sources.get(value, [])
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


def extract_source_iocs(
    apk_path: str,
    *,
    is_packed: bool,
    jadx_timeout: int = 300,
    jadx_sources_dir: str | None = None,
    jadx_enabled: bool = True,
) -> SourceIocResult:
    # 无论是否加壳都先 carve/字节扫描提取候选 IOC。加壳包真实 dex 被加密，jadx 反编译
    # 无意义，故跳过 jadx 校验、仅保留资源等来源；真实 dex 的 IOC 由脱壳后单独提取再合并。
    collector = SourceIocCollector()
    for label, blob in iter_artifact_blobs(apk_path):
        collector.scan_blob(label, blob)
    collector.finalize_blobs()

    if not is_packed and collector.has_dex_iocs:
        if jadx_sources_dir:
            _scan_java_sources(collector, jadx_sources_dir)
        elif jadx_enabled:
            try:
                with open_jadx_workspace(apk_path, timeout=jadx_timeout) as workspace:
                    _scan_java_sources(collector, workspace.sources_dir)
            except Exception as exc:  # pragma: no cover - depends on jadx/runtime
                logger.warning("source ioc jadx locate failed path=%s err=%s", apk_path, exc)

    return collector.build_result()


def _scan_java_sources(collector: SourceIocCollector, sources_dir: str) -> None:
    if not os.path.isdir(sources_dir):
        return
    for root, dirs, files in os.walk(sources_dir):
        dirs.sort()
        for file_name in sorted(files):
            if not file_name.endswith(".java"):
                continue
            file_path = os.path.join(root, file_name)
            try:
                if os.path.getsize(file_path) > MAX_TEXT_FILE_BYTES:
                    continue
                text = Path(file_path).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            collector.scan_java_source(os.path.relpath(file_path, sources_dir), text)


def iter_artifact_blobs(path: str):
    if os.path.isdir(path):
        for root, dirs, files in os.walk(path):
            dirs.sort()
            for file_name in sorted(files):
                file_path = os.path.join(root, file_name)
                rel_path = os.path.relpath(file_path, path)
                try:
                    file_size = os.path.getsize(file_path)
                    if should_skip_artifact(rel_path, file_size):
                        _log_skipped_artifact(rel_path, file_size)
                        continue
                    data = Path(file_path).read_bytes()
                except OSError:
                    continue
                if data[:4] == b"PK\x03\x04":
                    yield from _zip_carve(data, rel_path)
                else:
                    yield rel_path, data
        return

    file_name = os.path.basename(path)
    try:
        file_size = os.path.getsize(path)
    except OSError:
        return
    if should_skip_artifact(file_name, file_size):
        _log_skipped_artifact(file_name, file_size)
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
            declared_size = int.from_bytes(data[offset + 22 : offset + 26], "little")
            name_len = int.from_bytes(data[offset + 26 : offset + 28], "little")
            extra_len = int.from_bytes(data[offset + 28 : offset + 30], "little")
            name = data[offset + 30 : offset + 30 + name_len].decode("utf-8", "replace")
            name = name or f"<entry@{offset}>"
            label = f"{prefix}!{name}" if prefix else name
            if should_skip_artifact(name, declared_size):
                _log_skipped_artifact(label, declared_size)
                continue
            start = offset + 30 + name_len + extra_len
            next_offset = offsets[index + 1] if index + 1 < len(offsets) else len(data)
            inflate_limit = MAX_TEXT_FILE_BYTES + 1 if is_text_artifact(name) else MAX_INFLATE_BYTES
            if method == 8:
                blob = zlib.decompressobj(-15).decompress(data[start:next_offset], inflate_limit)
            else:
                blob = data[start : min(next_offset, start + inflate_limit)]
            if is_text_artifact(name) and len(blob) > MAX_TEXT_FILE_BYTES:
                _log_skipped_artifact(label, len(blob), size_is_lower_bound=True)
                continue
            if depth < 2 and blob[:4] == sig:
                yield from _zip_carve(blob, label, depth + 1)
            else:
                yield label, blob
        except Exception:
            continue

    if not offsets:
        yield (f"{prefix}!<unassigned>" if prefix else "<unassigned>"), data


def _log_skipped_artifact(label: str, size: int, *, size_is_lower_bound: bool = False) -> None:
    if is_media_artifact(label):
        logger.debug("artifact media skipped label=%r size=%s", label, size)
        return
    suffix = "+" if size_is_lower_bound else ""
    logger.warning("artifact text skipped label=%r size=%s%s limit=%s", label, size, suffix, MAX_TEXT_FILE_BYTES)


def _iter_ioc_matches(ioc_type: str, pattern: re.Pattern[str], text: str):
    if ioc_type == "email":
        yield from _iter_emails(text)
        return
    yield from pattern.findall(text)


def _iter_emails(text: str):
    search_from = 0
    text_length = len(text)
    while True:
        at = text.find("@", search_from)
        if at < 0:
            return
        search_from = at + 1

        left_limit = max(0, at - EMAIL_LOCAL_MAX_CHARS)
        left = at
        while left > left_limit and text[left - 1] in EMAIL_LOCAL_CHARS:
            left -= 1
        if left == at or (left > 0 and text[left - 1] in EMAIL_LOCAL_BOUNDARY_CHARS):
            continue

        right_limit = min(text_length, at + 1 + EMAIL_DOMAIN_MAX_CHARS)
        right = at + 1
        while right < right_limit and text[right] in EMAIL_DOMAIN_CHARS:
            right += 1
        if right == at + 1 or (right < text_length and text[right] in EMAIL_DOMAIN_CHARS):
            continue

        candidate = text[left:right]
        if EMAIL_CANDIDATE_PATTERN.fullmatch(candidate):
            yield candidate


def _iter_texts(data: bytes):
    for match in re.finditer(rb"[\x20-\x7e]{4,}", data):
        yield match.group().decode("latin1")
    try:
        decoded = data.decode("utf-16-le", "ignore")
    except Exception:
        return
    for match in re.finditer(r"[\x20-\x7e]{4,}", decoded):
        yield match.group()


WHITE_DOMAIN_CSV = Path(__file__).resolve().parents[1] / "tools" / "white_domain.csv"
IMAGE_URL_EXTENSIONS = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".bmp",
    ".svg",
    ".ico",
    ".tif",
    ".tiff",
    ".heic",
    ".heif",
)


@functools.lru_cache(maxsize=1)
def _white_domains() -> frozenset[str]:
    """加载白名单域名（每行一个，首行表头 DOMAIN），用于过滤常见正规域名。"""
    domains: set[str] = set()
    try:
        with WHITE_DOMAIN_CSV.open(encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                domain = line.strip().lower().rstrip(".")
                if domain and domain != "domain":
                    domains.add(domain)
    except OSError as exc:  # pragma: no cover - depends on deployment files
        logger.warning("white domain list load failed path=%s err=%s", WHITE_DOMAIN_CSV, exc)
    return frozenset(domains)


def _is_whitelisted_domain(host: str) -> bool:
    host = host.split(":")[0].strip().lower().rstrip(".")
    if not host:
        return False
    white = _white_domains()
    if not white:
        return False
    labels = host.split(".")
    # 命中域名本身或其任一父域（如 a.b.example.com 命中 example.com）即视为白名单。
    for index in range(len(labels) - 1):
        if ".".join(labels[index:]) in white:
            return True
    return False


def _is_image_url(url: str) -> bool:
    path = re.split(r"[?#]", url, maxsplit=1)[0].lower()
    return path.endswith(IMAGE_URL_EXTENSIONS)


def _is_garbage_email(value: str) -> bool:
    """过滤明显非真实邮箱的噪声，如 q@I.Tv（用户名/主域名过短）。"""
    local, _, domain = value.partition("@")
    if len(local) < 2:
        return True
    labels = domain.split(".")
    if len(labels) < 2 or len(labels[-2]) < 2:
        return True
    return False


def _host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _is_valid_http_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return False
        _ = parsed.port
    except ValueError:
        return False
    return True


def _bad_host(host: str) -> bool:
    if not host or host.startswith(NOISE_HOST_PREFIXES):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
            return True
        return labels[-1].lower() not in COMMON_TLDS
    return not address.is_global


def _is_noise(ioc_type: str, value: str) -> bool:
    lowered = value.lower()
    if ioc_type == "url":
        if not _is_valid_http_url(value):
            return True
        if any(fragment in lowered for fragment in NOISE_URL_SUBSTR):
            return True
        if _bad_host(_host_of(value)):
            return True
        if _is_image_url(value):
            return True
        return _is_whitelisted_domain(_host_of(value))
    if ioc_type == "email":
        if value.rsplit(".", 1)[-1].lower() not in COMMON_TLDS:
            return True
        return _is_garbage_email(value)
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
