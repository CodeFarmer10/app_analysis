from __future__ import annotations

import hashlib
import os
import shutil
import struct
import zlib
from dataclasses import dataclass, field


FRAMEWORK_PREFIXES = (
    "Landroid/",
    "Landroidx/",
    "Lcom/android/",
    "Ldalvik/",
    "Lj$/",
    "Ljava/",
    "Ljavax/",
    "Lsun/",
    "Lcom/sun/",
    "Ljdk/",
    "Llibcore/",
    "Lorg/w3c/",
    "Lorg/xml/",
    "Lorg/xmlpull/",
    "Lorg/json/",
    "Lorg/apache/",
    "Lkotlin/",
    "Lkotlinx/",
    "Lcom/google/",
    "Lpub/devrel/",
    "Lokhttp3/",
    "Lokio/",
    "Lretrofit2/",
    "Lcom/squareup/",
    "Lio/reactivex/",
    "Lcom/bumptech/glide/",
    "Lorg/intellij/",
    "Lorg/jetbrains/",
    "Lorg/checkerframework/",
    "Lcom/facebook/",
    "Lcom/airbnb/",
    "Lcom/alibaba/",
    "Lcom/tencent/",
    "Lcom/bytedance/",
)


@dataclass
class DexInfo:
    path: str
    valid: bool = False
    class_count: int = 0
    classes: frozenset[str] = field(default_factory=frozenset)
    app_class_count: int = 0
    framework_class_count: int = 0
    size: int = 0
    error: str = ""

    @property
    def class_sig(self) -> str:
        digest = hashlib.md5()
        for class_name in sorted(self.classes):
            digest.update(class_name.encode("utf-8", "replace"))
            digest.update(b"\n")
        return digest.hexdigest()


@dataclass
class DexFilterResult:
    infos: list[DexInfo]
    kept: list[DexInfo]
    duplicates_removed: list[DexInfo]
    framework_removed: list[DexInfo]
    invalid: list[DexInfo]


def repair_dex_header(data: bytes) -> bytes:
    if len(data) < 0x70 or data[:4] != b"dex\n":
        return data
    patched = bytearray(data)
    patched[12:32] = hashlib.sha1(patched[32:]).digest()
    struct.pack_into("<I", patched, 8, zlib.adler32(patched[12:]) & 0xFFFFFFFF)
    return bytes(patched)


def pkg_to_prefixes(package_name: str | list[str]) -> tuple[str, ...]:
    packages = [package_name] if isinstance(package_name, str) else package_name
    prefixes: list[str] = []
    for package in packages:
        parts = [part for part in str(package or "").split(".") if part]
        if not parts:
            continue
        prefixes.append("L" + "/".join(parts) + "/")
        if len(parts) >= 2:
            prefixes.append("L" + "/".join(parts[:2]) + "/")
    return tuple(dict.fromkeys(prefixes))


def parse_dex_classes(path: str) -> DexInfo:
    info = DexInfo(path=path)
    try:
        with open(path, "rb") as file_obj:
            data = file_obj.read()
    except OSError as exc:
        info.error = str(exc)
        return info

    info.size = len(data)
    if len(data) < 0x70 or data[:4] != b"dex\n":
        info.error = "非法 dex 头"
        return info

    try:
        string_ids_size = struct.unpack_from("<I", data, 0x38)[0]
        string_ids_off = struct.unpack_from("<I", data, 0x3C)[0]
        type_ids_size = struct.unpack_from("<I", data, 0x40)[0]
        type_ids_off = struct.unpack_from("<I", data, 0x44)[0]
        class_defs_size = struct.unpack_from("<I", data, 0x60)[0]
        class_defs_off = struct.unpack_from("<I", data, 0x64)[0]

        def read_uleb128(offset: int) -> tuple[int, int]:
            result = 0
            shift = 0
            while True:
                byte = data[offset]
                offset += 1
                result |= (byte & 0x7F) << shift
                if (byte & 0x80) == 0:
                    return result, offset
                shift += 7

        def read_string(string_idx: int) -> str:
            if string_idx >= string_ids_size:
                return ""
            string_off = struct.unpack_from("<I", data, string_ids_off + string_idx * 4)[0]
            _size, offset = read_uleb128(string_off)
            end = data.index(b"\x00", offset)
            return data[offset:end].decode("utf-8", "replace")

        def type_descriptor(type_idx: int) -> str:
            string_idx = struct.unpack_from("<I", data, type_ids_off + type_idx * 4)[0]
            return read_string(string_idx)

        classes: set[str] = set()
        for index in range(class_defs_size):
            base = class_defs_off + index * 32
            class_type_idx = struct.unpack_from("<I", data, base)[0]
            if class_type_idx < type_ids_size:
                descriptor = type_descriptor(class_type_idx)
                if descriptor:
                    classes.add(descriptor)

        info.classes = frozenset(classes)
        info.class_count = len(classes)
        info.valid = True
    except (IndexError, struct.error, ValueError) as exc:
        info.error = f"解析失败: {exc}"
    return info


def analyze_and_filter_dex(paths: list[str], app_prefixes: tuple[str, ...] | None) -> DexFilterResult:
    infos = [parse_dex_classes(path) for path in paths]
    invalid = [info for info in infos if not info.valid]
    valid = [info for info in infos if info.valid]

    if app_prefixes:
        for info in valid:
            _classify_counts(info, app_prefixes)

    groups: dict[str, list[DexInfo]] = {}
    for info in valid:
        groups.setdefault(info.class_sig, []).append(info)

    deduped: list[DexInfo] = []
    duplicates_removed: list[DexInfo] = []
    for group in groups.values():
        group.sort(key=lambda item: (item.app_class_count, item.class_count, item.size), reverse=True)
        deduped.append(group[0])
        duplicates_removed.extend(group[1:])

    kept: list[DexInfo] = []
    framework_removed: list[DexInfo] = []
    for info in deduped:
        if not app_prefixes:
            kept.append(info)
            continue
        has_app = info.app_class_count > 0
        pure_framework = (not has_app) and (
            info.framework_class_count >= max(1, int(info.class_count * 0.8))
        )
        (framework_removed if pure_framework else kept).append(info)

    return DexFilterResult(
        infos=infos,
        kept=kept,
        duplicates_removed=duplicates_removed,
        framework_removed=framework_removed,
        invalid=invalid,
    )


def copy_repaired_dex_files(dex_infos: list[DexInfo], output_dir: str) -> list[str]:
    os.makedirs(output_dir, exist_ok=True)
    copied: list[str] = []
    for info in dex_infos:
        target = os.path.join(output_dir, os.path.basename(info.path))
        try:
            with open(info.path, "rb") as source:
                data = source.read()
            with open(target, "wb") as destination:
                destination.write(repair_dex_header(data))
        except OSError:
            shutil.copy2(info.path, target)
        copied.append(target)
    return copied


def _classify_counts(info: DexInfo, app_prefixes: tuple[str, ...]) -> None:
    app_count = 0
    framework_count = 0
    for class_name in info.classes:
        if any(class_name.startswith(prefix) for prefix in app_prefixes):
            app_count += 1
        elif any(class_name.startswith(prefix) for prefix in FRAMEWORK_PREFIXES):
            framework_count += 1
    info.app_class_count = app_count
    info.framework_class_count = framework_count
