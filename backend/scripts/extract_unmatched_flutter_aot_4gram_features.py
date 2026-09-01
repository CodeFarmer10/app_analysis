from __future__ import annotations

import argparse
import ast
import csv
import gzip
import hashlib
import json
import math
import re
import shutil
import subprocess
import sys
import tempfile
import time
import warnings
import zipfile
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.parse import urlsplit

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from core.database import fetch_all  # noqa: E402
from services.storage_service import storage_service  # noqa: E402


ARM64_LIBAPP = "lib/arm64-v8a/libapp.so"
ARM64_LIBFLUTTER = "lib/arm64-v8a/libflutter.so"
NGRAM_N = 4
MASK64 = (1 << 64) - 1
POLY = 0x9E3779B185EBCA87

NETWORK_PREFIXES = ("http://", "https://", "ws://", "wss://", "ftp://")
URL_RE = re.compile(r"(?:https?|wss?|ftp)://[^\s\"'<>]{4,2048}", re.IGNORECASE)
LIBRARY_URI_LIKE_RES = [
    re.compile(r"package:[A-Za-z0-9_./@+\-]+"),
    re.compile(r"file:///[A-Za-z0-9_%./@+~:\-]+"),
    re.compile(r"org-dartlang-app:[A-Za-z0-9_%./@+~:\-]+"),
]
API_ROUTE_RE = re.compile(r"(?<![A-Za-z0-9])/(?:[A-Za-z0-9_.~:@+\-]+/?){1,12}(?:\?[A-Za-z0-9_%&=.+:@/\-]*)?")
API_ROUTE_HINTS = {
    "api",
    "auth",
    "login",
    "logout",
    "register",
    "user",
    "users",
    "account",
    "profile",
    "trade",
    "order",
    "orders",
    "pay",
    "payment",
    "wallet",
    "asset",
    "assets",
    "market",
    "quote",
    "message",
    "messages",
    "recharge",
    "withdraw",
    "bank",
    "card",
    "verify",
    "captcha",
    "notice",
    "config",
    "bootstrap",
    "session",
    "token",
}
COMMON_FILE_EXTS = {
    ".dart",
    ".so",
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".gif",
    ".svg",
    ".ttf",
    ".otf",
    ".json",
    ".yaml",
    ".yml",
    ".xml",
    ".html",
    ".htm",
    ".js",
    ".css",
    ".bin",
    ".db",
}
CAMEL_KEY_RE = re.compile(r"^[a-z][A-Za-z0-9]*(?:\.[a-z][A-Za-z0-9]*)*$")
STRUCTURED_UNDERSCORE_RE = re.compile(r"^[a-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+$")
COMMON_FRAMEWORK_IDENTIFIERS = {
    "toString",
    "hashCode",
    "runtimeType",
    "noSuchMethod",
    "addListener",
    "removeListener",
    "notifyListeners",
    "debugLabel",
    "debugFillProperties",
    "debugDescribeChildren",
    "didChangeDependencies",
    "didUpdateWidget",
    "deactivate",
    "dispose",
    "initState",
    "createState",
    "setState",
    "createElement",
    "createRenderObject",
    "updateRenderObject",
    "build",
    "mounted",
    "context",
    "widget",
    "child",
    "children",
    "builder",
    "listener",
    "controller",
    "animation",
    "duration",
    "curve",
    "alignment",
    "padding",
    "margin",
    "semanticLabel",
    "textDirection",
    "textAlign",
    "mainAxisAlignment",
    "crossAxisAlignment",
}
FRAMEWORK_URL_DOMAINS = {
    "api.flutter.dev",
    "flutter.dev",
    "www.flutter.dev",
    "dart.dev",
    "www.dart.dev",
    "pub.dev",
    "www.pub.dev",
    "developer.android.com",
    "www.w3.org",
    "www.ibm.com",
    "developer.mozilla.org",
    "github.com",
}


@dataclass
class Candidate:
    md5: str
    apk_path: str
    task_ids: list[str]
    app_name: str = ""
    package_name: str = ""
    version_name: str = ""
    version_code: str = ""


def stable_u64_token(token: str) -> int:
    return int.from_bytes(hashlib.blake2b(token.encode("utf-8", "ignore"), digest_size=8).digest(), "big")


def opcode_4gram_hashes(opcodes: Iterable[str]) -> set[int]:
    window: list[int] = []
    values: set[int] = set()
    cache: dict[str, int] = {}
    for opcode in opcodes:
        token = str(opcode or "").strip().upper()
        if not token:
            continue
        hv = cache.get(token)
        if hv is None:
            hv = stable_u64_token(token)
            cache[token] = hv
        window.append(hv)
        if len(window) < NGRAM_N:
            continue
        if len(window) > NGRAM_N:
            del window[0]
        digest = 0xCBF29CE484222325
        for item in window:
            digest = ((digest * POLY) ^ item) & MASK64
        values.add(digest)
    return values


def jaccard(left: set[int], right: set[int]) -> float:
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def jaccard_above_threshold(left_set: set[int], right_set: set[int], threshold: float) -> float | None:
    left_size = len(left_set)
    right_size = len(right_set)
    if not left_size and not right_size:
        return 1.0 if 1.0 > threshold else None
    if not left_size or not right_size:
        return None
    smaller_size = min(left_size, right_size)
    larger_size = max(left_size, right_size)
    if smaller_size / larger_size <= threshold:
        return None

    required_overlap = math.floor((threshold * (left_size + right_size)) / (1.0 + threshold)) + 1
    if smaller_size < required_overlap:
        return None

    smaller, larger = (left_set, right_set) if left_size <= right_size else (right_set, left_set)
    overlap = 0
    remaining = len(smaller)
    for value in smaller:
        remaining -= 1
        if value in larger:
            overlap += 1
        if overlap + remaining < required_overlap:
            return None

    union_size = left_size + right_size - overlap
    if not union_size:
        return None
    score = overlap / union_size
    return score if score > threshold else None


def connected_similarity_families(sets: dict[str, set[int]], threshold: float = 0.9) -> tuple[list[list[str]], list[dict[str, Any]]]:
    ids = sorted(sets)
    parent = {item: item for item in ids}

    def find(item: str) -> str:
        while parent[item] != item:
            parent[item] = parent[parent[item]]
            item = parent[item]
        return item

    def union(left: str, right: str) -> None:
        root_left, root_right = find(left), find(right)
        if root_left != root_right:
            parent[root_right] = root_left

    token_to_bit = {token: index for index, token in enumerate(sorted({token for values in sets.values() for token in values}))}
    masks: dict[str, int] = {}
    for item in ids:
        mask = 0
        for token in sets[item]:
            mask |= 1 << token_to_bit[token]
        masks[item] = mask

    ids_by_size = sorted((item for item in ids if sets[item]), key=lambda item: (len(sets[item]), item))
    pairs: list[dict[str, Any]] = []
    for index, left in enumerate(ids_by_size):
        left_size = len(sets[left])
        for right in ids_by_size[index + 1 :]:
            right_size = len(sets[right])
            if left_size / right_size <= threshold:
                break
            overlap = (masks[left] & masks[right]).bit_count()
            union_size = left_size + right_size - overlap
            if union_size:
                score = overlap / union_size
                if score > threshold:
                    union(left, right)
                    pairs.append({"left": left, "right": right, "similarity": round(score, 6)})

    groups: dict[str, list[str]] = {}
    for item in ids:
        groups.setdefault(find(item), []).append(item)
    families = sorted((sorted(group) for group in groups.values() if len(group) >= 2), key=lambda group: (-len(group), group))
    return families, pairs


def is_flutter_dart_public_noise(value: str) -> bool:
    text = str(value or "").strip().lower()
    if not text:
        return True
    if text.startswith(("dart:", "org-dartlang-sdk:", "package:flutter/", "package:flutter_", "package:cupertino_")):
        return True
    return any(
        marker in text
        for marker in (
            "flutter/src/",
            "dart-sdk/",
            "/sdk/lib/",
            "io.flutter.",
            "dev.flutter.",
            "flutter_assets/packages/flutter",
            "materialicons",
            "cupertinoicons",
            "fontmanifest.json",
            "assetmanifest.json",
            "kernel_blob.bin",
            "vm_snapshot_data",
            "isolate_snapshot_data",
            "flutterengine",
        )
    )


def extract_urls(value: str) -> list[str]:
    return sorted(
        set(
            item.group(0).rstrip(".,;:)]}")
            for item in URL_RE.finditer(value)
            if has_valid_url_host(item.group(0).rstrip(".,;:)]}"))
            and not is_framework_url(item.group(0).rstrip(".,;:)]}"))
        )
    )


def is_framework_url(value: str) -> bool:
    try:
        host = (urlsplit(value).hostname or "").lower()
    except ValueError:
        return True
    return host in FRAMEWORK_URL_DOMAINS or host.endswith(".flutter.dev") or host.endswith(".dart.dev")


def has_valid_url_host(value: str) -> bool:
    try:
        host = (urlsplit(value).hostname or "").lower()
    except ValueError:
        return False
    if "." not in host:
        return False
    labels = host.split(".")
    if any(not label for label in labels):
        return False
    return bool(re.fullmatch(r"[a-z]{2,63}", labels[-1]) or re.fullmatch(r"\d{1,3}", labels[-1]))


def extract_library_uri_like(value: str) -> list[str]:
    output: set[str] = set()
    for pattern in LIBRARY_URI_LIKE_RES:
        for match in pattern.finditer(value):
            uri = match.group(0).rstrip(".,;:)]}")
            if uri and not is_flutter_dart_public_noise(uri):
                output.add(uri)
    return sorted(output)


def extract_api_routes(value: str) -> list[str]:
    value = URL_RE.sub(" ", value)
    lowered = value.lower()
    if "file://" in lowered or "package:" in lowered:
        return []
    output: set[str] = set()
    for match in API_ROUTE_RE.finditer(value):
        route = match.group(0).rstrip(".,;:)]}")
        if len(route) < 4 or len(route) > 256:
            continue
        low = route.lower()
        if low.startswith(("//", "/assets/", "/flutter_assets/", "/users/", "/home/", "/var/", "/tmp/")):
            continue
        path_part = low.split("?", 1)[0]
        if any(path_part.endswith(ext) for ext in COMMON_FILE_EXTS):
            continue
        segments = [segment for segment in path_part.split("/") if segment]
        if not segments:
            continue
        first = segments[0]
        if first == "api" or re.fullmatch(r"v\d+", first) or any(segment in API_ROUTE_HINTS for segment in segments):
            output.add(route)
    return sorted(output)


def is_chinese_text(value: str) -> bool:
    return sum(1 for ch in value if "\u3400" <= ch <= "\u9fff") >= 2


def business_string_match_types(value: str) -> list[str]:
    text = str(value or "").strip()
    if not text or len(text) < 5 or len(text) > 120 or is_flutter_dart_public_noise(text):
        return []
    if any(item in text for item in ("/", "\\", " ", "\t", "\n", "?", "&", "=", "#")):
        return []
    if text in COMMON_FRAMEWORK_IDENTIFIERS:
        return []
    types: list[str] = []
    if CAMEL_KEY_RE.fullmatch(text) and re.search(r"[a-z][A-Z]", text):
        types.append("camelCase")
    if STRUCTURED_UNDERSCORE_RE.fullmatch(text) and "_" in text and not text.isupper():
        types.append("structured_key")
    return types


def classify_strings(strings: Iterable[str]) -> dict[str, Any]:
    api_routes: set[str] = set()
    urls: set[str] = set()
    library_uris: set[str] = set()
    chinese_texts: set[str] = set()
    camel_case: set[str] = set()
    structured_keys: set[str] = set()

    for raw in strings:
        value = clean_string(str(raw or ""))
        if not value or is_flutter_dart_public_noise(value):
            continue
        urls.update(extract_urls(value))
        library_uris.update(extract_library_uri_like(value))
        api_routes.update(extract_api_routes(value))
        if is_chinese_text(value):
            chinese_texts.add(value)
        match_types = business_string_match_types(value)
        if "camelCase" in match_types:
            camel_case.add(value)
        if "structured_key" in match_types:
            structured_keys.add(value)

    return {
        "api_route": sorted(api_routes),
        "url": sorted(urls),
        "library_uri_like": sorted(library_uris),
        "chinese_text": sorted(chinese_texts),
        "business_string": {
            "camelCase": sorted(camel_case),
            "structured_key": sorted(structured_keys),
        },
    }


def clean_string(value: str) -> str:
    return re.sub(r"\s+", " ", value.replace("\t", " ")).strip()


def extract_utf8_printable_strings(blob: bytes, min_len: int = 3, max_len: int = 8192) -> list[str]:
    output: list[str] = []
    buffer = bytearray()

    def flush_ascii() -> None:
        nonlocal buffer
        if len(buffer) >= min_len:
            try:
                text = buffer.decode("ascii", "strict").strip()
            except UnicodeDecodeError:
                text = ""
            if min_len <= len(text) <= max_len:
                output.append(text)
        buffer = bytearray()

    for byte in blob:
        if byte == 9 or 0x20 <= byte <= 0x7E:
            buffer.append(byte)
            if len(buffer) > max_len:
                flush_ascii()
        else:
            flush_ascii()
    flush_ascii()

    text = blob.decode("utf-8", "ignore")
    for match in re.finditer(r"[\u3400-\u4dbf\u4e00-\u9fff]{2,128}", text):
        output.append(match.group(0))
    return output


def find_tool(names: Sequence[str]) -> str:
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    raise RuntimeError(f"missing tool: {'/'.join(names)}")


def run_text(command: Sequence[str], timeout: int | None = None) -> str:
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}\n{result.stderr[:4000]}")
    return result.stdout


def parse_readelf_symbols(readelf: str, so_path: Path) -> dict[str, dict[str, int]]:
    text = run_text([readelf, "-Ws", str(so_path)])
    symbols: dict[str, dict[str, int]] = {}
    wanted = {
        "_kDartIsolateSnapshotInstructions",
        "_kDartIsolateSnapshotData",
    }
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 8 or not parts[0].endswith(":"):
            continue
        name = parts[-1]
        if name not in wanted:
            continue
        try:
            symbols[name] = {"vaddr": int(parts[1], 16), "size": int(parts[2], 0)}
        except ValueError:
            continue
    return symbols


def parse_load_segments(readelf: str, so_path: Path) -> list[tuple[int, int, int]]:
    text = run_text([readelf, "-lW", str(so_path)])
    segments: list[tuple[int, int, int]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("LOAD"):
            continue
        parts = stripped.split()
        if len(parts) < 6:
            continue
        try:
            segments.append((int(parts[2], 16), int(parts[1], 16), int(parts[4], 16)))
        except ValueError:
            continue
    return segments


def va_to_file_offset(va: int, segments: Sequence[tuple[int, int, int]]) -> int | None:
    for start_va, start_offset, file_size in segments:
        if start_va <= va < start_va + file_size:
            return start_offset + (va - start_va)
    return None


def iter_disassembly_opcodes(objdump: str, so_path: Path, start: int, stop: int) -> Iterable[str]:
    command = [
        objdump,
        "-D",
        "--triple=aarch64-linux-android",
        "--no-show-raw-insn",
        f"--start-address=0x{start:x}",
        f"--stop-address=0x{stop:x}",
        str(so_path),
    ]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
    assert process.stdout is not None
    pattern = re.compile(r"^\s*[0-9a-f]+:\s+(?:[0-9a-f]{2}\s+)*\s*([a-z][a-z0-9_.]*)\b", re.IGNORECASE)
    for line in process.stdout:
        match = pattern.match(line)
        if not match:
            continue
        opcode = match.group(1).upper()
        if opcode not in {".WORD", ".BYTE", ".LONG", ".QUAD"}:
            yield opcode
    stderr = process.stderr.read() if process.stderr else ""
    return_code = process.wait()
    if return_code != 0:
        raise RuntimeError(f"objdump failed ({return_code}): {stderr[:4000]}")


def iter_capstone_opcodes(libapp: bytes, segments: Sequence[tuple[int, int, int]], start: int, stop: int) -> Iterable[str]:
    try:
        from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
    except ImportError as exc:
        raise RuntimeError("AArch64 objdump is unavailable and Python capstone is not installed") from exc

    start_offset = va_to_file_offset(start, segments)
    stop_offset = va_to_file_offset(stop - 1, segments)
    if start_offset is None or stop_offset is None:
        raise RuntimeError("Dart isolate instruction virtual address cannot be mapped to file offset")
    disassembler = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    code = libapp[start_offset : stop_offset + 1]
    for instruction in disassembler.disasm(code, start):
        opcode = str(instruction.mnemonic or "").strip().upper()
        if opcode:
            yield opcode


def write_u64_gz(path: Path, values: set[int]) -> None:
    with gzip.open(path, "wt", encoding="ascii", newline="\n") as handle:
        for value in sorted(values):
            handle.write(f"{value:016x}\n")


def read_u64_gz(path: Path) -> set[int]:
    values: set[int] = set()
    with gzip.open(path, "rt", encoding="ascii") as handle:
        for line in handle:
            text = line.strip()
            if text:
                values.add(int(text, 16))
    return values


def write_onecol_tsv(path: Path, header: str, values: Iterable[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t")
        writer.writerow([header])
        for value in sorted(set(values)):
            writer.writerow([value])


def write_string_category_files(out_dir: Path, categories: dict[str, Any]) -> None:
    write_onecol_tsv(out_dir / "api_routes.tsv", "api_route", categories["api_route"])
    write_onecol_tsv(out_dir / "urls.tsv", "url", categories["url"])
    write_onecol_tsv(out_dir / "library_uri_like.tsv", "library_uri_like", categories["library_uri_like"])
    write_onecol_tsv(out_dir / "chinese_text.tsv", "chinese_text", categories["chinese_text"])
    with (out_dir / "business_strings.tsv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t")
        writer.writerow(["subtype", "string"])
        for subtype in ("camelCase", "structured_key"):
            for value in categories["business_string"][subtype]:
                writer.writerow([subtype, value])
    with (out_dir / "string_categories.tsv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t")
        writer.writerow(["category", "subtype", "string"])
        for category in ("api_route", "url", "library_uri_like", "chinese_text"):
            for value in categories[category]:
                writer.writerow([category, "", value])
        for subtype in ("camelCase", "structured_key"):
            for value in categories["business_string"][subtype]:
                writer.writerow(["business_string", subtype, value])


def load_candidates(limit: int | None = None) -> list[Candidate]:
    limit_sql = "LIMIT %s" if limit is not None else ""
    params: list[Any] = []
    if limit is not None:
        params.append(max(0, limit))
    rows = fetch_all(
        f"""
        SELECT
            t.id AS task_id,
            LOWER(t.file_md5) AS file_md5,
            t.apk_path,
            sr.app_name,
            sr.package_name,
            sr.version_name,
            sr.version_code,
            t.created_at
        FROM tasks t
        JOIN static_results sr ON sr.task_id = t.id
        WHERE sr.framework_name = 'Flutter'
          AND t.file_md5 IS NOT NULL
          AND t.file_md5 <> ''
          AND t.apk_path IS NOT NULL
          AND t.apk_path <> ''
          AND (sr.model_id IS NULL OR sr.model_id = '')
          AND (sr.model_name IS NULL OR sr.model_name = '')
        ORDER BY t.created_at DESC
        {limit_sql}
        """,
        tuple(params),
    )
    grouped: dict[str, Candidate] = {}
    for row in rows:
        md5 = str(row.get("file_md5") or "").strip().lower()
        apk_path = str(row.get("apk_path") or "").strip()
        if not md5 or not apk_path:
            continue
        candidate = grouped.get(md5)
        if candidate is None:
            candidate = Candidate(
                md5=md5,
                apk_path=apk_path,
                task_ids=[],
                app_name=str(row.get("app_name") or ""),
                package_name=str(row.get("package_name") or ""),
                version_name=str(row.get("version_name") or ""),
                version_code=str(row.get("version_code") or ""),
            )
            grouped[md5] = candidate
        candidate.task_ids.append(str(row["task_id"]))
    return list(grouped.values())


def md5_file(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cleanup_download(path: Path | None) -> None:
    if path is None:
        return
    path.unlink(missing_ok=True)
    if path.parent.exists() and path.parent.name.startswith("fraud_app_"):
        shutil.rmtree(path.parent, ignore_errors=True)


def download_verified(candidate: Candidate) -> Path:
    local_path = Path(storage_service.download_to_temp(candidate.apk_path))
    actual = md5_file(local_path)
    if actual != candidate.md5:
        cleanup_download(local_path)
        raise RuntimeError(f"APK MD5 mismatch: expected={candidate.md5} actual={actual}")
    return local_path


def extract_one(candidate: Candidate, out_root: Path, readelf: str, objdump: str, min_string_len: int) -> dict[str, Any]:
    started = time.monotonic()
    local_apk: Path | None = None
    app_dir = out_root / candidate.md5
    app_dir.mkdir(parents=True, exist_ok=True)
    try:
        local_apk = download_verified(candidate)
        with zipfile.ZipFile(local_apk) as apk:
            names = set(apk.namelist())
            if ARM64_LIBAPP not in names or ARM64_LIBFLUTTER not in names:
                return write_app_result(app_dir, candidate, "skipped", started, reason="missing arm64-v8a libapp.so/libflutter.so")
            libapp = apk.read(ARM64_LIBAPP)
            libflutter = apk.read(ARM64_LIBFLUTTER)

        with tempfile.TemporaryDirectory(prefix="flutter_aot_") as temp_dir:
            so_path = Path(temp_dir) / "libapp.so"
            so_path.write_bytes(libapp)
            symbols = parse_readelf_symbols(readelf, so_path)
            segments = parse_load_segments(readelf, so_path)
            iso_instructions = symbols.get("_kDartIsolateSnapshotInstructions")
            if not iso_instructions:
                raise RuntimeError("ARM64 _kDartIsolateSnapshotInstructions not found")
            code_start = iso_instructions["vaddr"] + 0x80 if iso_instructions["size"] > 0x80 else iso_instructions["vaddr"]
            code_stop = iso_instructions["vaddr"] + iso_instructions["size"]
            try:
                opcodes = list(iter_disassembly_opcodes(objdump, so_path, code_start, code_stop))
                disassembler_backend = objdump
            except RuntimeError as exc:
                if "--triple" not in str(exc) and "can't disassemble" not in str(exc).lower():
                    raise
                opcodes = list(iter_capstone_opcodes(libapp, segments, code_start, code_stop))
                disassembler_backend = "capstone"
            grams = opcode_4gram_hashes(opcodes)

            string_blob = libapp
            iso_data = symbols.get("_kDartIsolateSnapshotData")
            if iso_data:
                offset = va_to_file_offset(iso_data["vaddr"], segments)
                if offset is not None and offset + iso_data["size"] <= len(libapp):
                    string_blob = libapp[offset : offset + iso_data["size"]] + b"\x00" + libapp
            raw_strings = sorted(set(clean_string(item) for item in extract_utf8_printable_strings(string_blob, min_len=min_string_len)))
            raw_strings = [item for item in raw_strings if item and len(item) >= min_string_len]
            noise_strings = sorted(item for item in raw_strings if is_flutter_dart_public_noise(item))
            categories = classify_strings(raw_strings)

        write_u64_gz(app_dir / "aot_opcode_4gram.u64.txt.gz", grams)
        with gzip.open(app_dir / "raw_strings_all.txt.gz", "wt", encoding="utf-8") as handle:
            for value in raw_strings:
                handle.write(value.replace("\n", "\\n") + "\n")
        with gzip.open(app_dir / "flutter_dart_noise_strings.txt.gz", "wt", encoding="utf-8") as handle:
            for value in noise_strings:
                handle.write(value.replace("\n", "\\n") + "\n")
        write_string_category_files(app_dir, categories)

        return write_app_result(
            app_dir,
            candidate,
            "success",
            started,
            aot={
                "instruction_count": len(opcodes),
                "disassembler_backend": disassembler_backend,
                "opcode_sequence_sha256": hashlib.sha256(("\n".join(opcodes)).encode("utf-8")).hexdigest(),
                "opcode_4gram_unique_count": len(grams),
                "dart_isolate_snapshot_instructions_size": iso_instructions["size"],
            },
            strings={
                "raw_string_count_all": len(raw_strings),
                "flutter_dart_noise_count": len(noise_strings),
                "categories": categories,
                "category_counts": category_counts(categories),
            },
        )
    except Exception as exc:
        return write_app_result(app_dir, candidate, "failed", started, error=f"{type(exc).__name__}: {exc}"[:2000])
    finally:
        cleanup_download(local_apk)


def category_counts(categories: dict[str, Any]) -> dict[str, Any]:
    return {
        "api_route": len(categories["api_route"]),
        "url": len(categories["url"]),
        "library_uri_like": len(categories["library_uri_like"]),
        "chinese_text": len(categories["chinese_text"]),
        "business_string": {
            "camelCase": len(categories["business_string"]["camelCase"]),
            "structured_key": len(categories["business_string"]["structured_key"]),
        },
    }


def write_app_result(app_dir: Path, candidate: Candidate, status: str, started: float, **fields: Any) -> dict[str, Any]:
    result = {
        "app": {
            "md5": candidate.md5,
            "app_name": candidate.app_name,
            "package_name": candidate.package_name,
            "version_name": candidate.version_name,
            "version_code": candidate.version_code,
            "task_ids": candidate.task_ids,
        },
        "status": status,
        "elapsed_seconds": round(time.monotonic() - started, 2),
        **fields,
    }
    (app_dir / "features.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result


def emit(event: str, **fields: Any) -> None:
    print(json.dumps({"time": time.strftime("%Y-%m-%d %H:%M:%S"), "event": event, **fields}, ensure_ascii=False), flush=True)


def worker(args: tuple[Candidate, str, str, str, int]) -> dict[str, Any]:
    candidate, out_root, readelf, objdump, min_string_len = args
    return extract_one(candidate, Path(out_root), readelf, objdump, min_string_len)


def build_reports(out_root: Path) -> dict[str, Any]:
    result_paths = sorted(out_root.glob("*/features.json"))
    results = [json.loads(path.read_text(encoding="utf-8")) for path in result_paths]
    success_ids = [item["app"]["md5"] for item in results if item.get("status") == "success"]
    gram_sets = {
        md5: read_u64_gz(out_root / md5 / "aot_opcode_4gram.u64.txt.gz")
        for md5 in success_ids
        if (out_root / md5 / "aot_opcode_4gram.u64.txt.gz").exists()
    }
    families, pairs = connected_similarity_families(gram_sets, threshold=0.9)

    app_index = {item["app"]["md5"]: item["app"] for item in results}
    enriched_families = [
        {
            "family_id": f"family_{index:04d}",
            "size": len(members),
            "members": [app_index.get(member, {"md5": member}) for member in members],
        }
        for index, members in enumerate(families, start=1)
    ]

    with (out_root / "similarity_pairs_gt_0.9.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["left", "right", "similarity"])
        writer.writeheader()
        writer.writerows(pairs)
    (out_root / "families.json").write_text(json.dumps(enriched_families, ensure_ascii=False, indent=2), encoding="utf-8")

    with (out_root / "summary.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        fieldnames = [
            "md5",
            "app_name",
            "package_name",
            "version_name",
            "status",
            "instruction_count",
            "opcode_4gram_unique_count",
            "raw_string_count_all",
            "flutter_dart_noise_count",
            "api_route_count",
            "url_count",
            "library_uri_like_count",
            "chinese_text_count",
            "business_camelCase_count",
            "business_structured_key_count",
            "error",
            "reason",
        ]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in results:
            app = item.get("app") or {}
            counts = ((item.get("strings") or {}).get("category_counts") or {})
            business = counts.get("business_string") or {}
            aot = item.get("aot") or {}
            writer.writerow(
                {
                    "md5": app.get("md5"),
                    "app_name": app.get("app_name"),
                    "package_name": app.get("package_name"),
                    "version_name": app.get("version_name"),
                    "status": item.get("status"),
                    "instruction_count": aot.get("instruction_count"),
                    "opcode_4gram_unique_count": aot.get("opcode_4gram_unique_count"),
                    "raw_string_count_all": (item.get("strings") or {}).get("raw_string_count_all"),
                    "flutter_dart_noise_count": (item.get("strings") or {}).get("flutter_dart_noise_count"),
                    "api_route_count": counts.get("api_route"),
                    "url_count": counts.get("url"),
                    "library_uri_like_count": counts.get("library_uri_like"),
                    "chinese_text_count": counts.get("chinese_text"),
                    "business_camelCase_count": business.get("camelCase"),
                    "business_structured_key_count": business.get("structured_key"),
                    "error": item.get("error"),
                    "reason": item.get("reason"),
                }
            )

    status_counts = Counter(item.get("status") for item in results)
    manifest = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "app_count": len(results),
        "status_counts": dict(status_counts),
        "similarity_threshold": 0.9,
        "family_count": len(enriched_families),
        "similar_pair_count": len(pairs),
        "notes": [
            "AOT similarity uses Jaccard over unique ARM64 Dart isolate opcode 4-gram hashes.",
            "Each app stores features.json plus per-category TSV/string evidence files in its md5 directory.",
            "String categories are derived from raw extracted strings after conservative Flutter/Dart public-noise filtering.",
        ],
    }
    (out_root / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract unmatched Flutter AOT opcode 4-gram features and categorized raw strings.")
    parser.add_argument("--output-root", type=Path, default=Path("outputs/flutter_aot_4gram_features"))
    parser.add_argument("--limit", type=int)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--min-string-len", type=int, default=3)
    args = parser.parse_args()

    readelf = find_tool(["readelf", "llvm-readelf"])
    objdump = find_tool(["llvm-objdump", "aarch64-linux-gnu-objdump", "objdump"])
    args.output_root.mkdir(parents=True, exist_ok=True)

    candidates = load_candidates(args.limit)
    emit("start", candidates=len(candidates), output_root=str(args.output_root), workers=max(1, args.workers))
    stats: Counter[str] = Counter()
    summary_jsonl = args.output_root / "results.jsonl"
    with summary_jsonl.open("w", encoding="utf-8") as output:
        workers = max(1, args.workers)
        if workers == 1:
            iterator = ((index, extract_one(candidate, args.output_root, readelf, objdump, args.min_string_len)) for index, candidate in enumerate(candidates, 1))
        else:
            executor = ProcessPoolExecutor(max_workers=workers)
            futures = {
                executor.submit(worker, (candidate, str(args.output_root), readelf, objdump, args.min_string_len)): candidate
                for candidate in candidates
            }
            iterator = ((index, future.result()) for index, future in enumerate(as_completed(futures), 1))
        try:
            for index, result in iterator:
                status = str(result.get("status") or "failed")
                stats[status] += 1
                output.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n")
                output.flush()
                app = result.get("app") or {}
                emit("item", index=index, total=len(candidates), md5=app.get("md5"), status=status)
        finally:
            if "executor" in locals():
                executor.shutdown(cancel_futures=True)

    manifest = build_reports(args.output_root)
    emit("complete", **dict(stats), families=manifest["family_count"], similar_pairs=manifest["similar_pair_count"])
    return 0 if not stats.get("failed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
