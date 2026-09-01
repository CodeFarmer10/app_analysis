from __future__ import annotations

import gzip
import hashlib
import math
import re
import shutil
import subprocess
import tempfile
import warnings
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.parse import urlsplit


ARM64_LIBAPP = "lib/arm64-v8a/libapp.so"
ARM64_LIBFLUTTER = "lib/arm64-v8a/libflutter.so"
NGRAM_N = 4
MASK64 = (1 << 64) - 1
POLY = 0x9E3779B185EBCA87

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


@dataclass
class FlutterAotFeatureResult:
    status: str
    aot_opcode_4grams: list[str] = field(default_factory=list)
    string_features: dict[str, Any] = field(default_factory=dict)
    instruction_count: int = 0
    raw_string_count_all: int = 0
    flutter_dart_noise_count: int = 0
    disassembler_backend: str = ""
    error: str = ""

    def to_static_fields(self) -> dict[str, Any]:
        return {
            "flutter_aot_opcode_4grams": self.aot_opcode_4grams,
            "flutter_string_features": self.string_features,
        }


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


def clean_string(value: str) -> str:
    return re.sub(r"\s+", " ", value.replace("\t", " ")).strip()


def extract_urls(value: str) -> list[str]:
    return sorted(
        set(
            item.group(0).rstrip(".,;:)]}")
            for item in URL_RE.finditer(value)
            if has_valid_url_host(item.group(0).rstrip(".,;:)]}"))
            and not is_framework_url(item.group(0).rstrip(".,;:)]}"))
        )
    )


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


def classify_flutter_raw_strings(strings: Iterable[str]) -> dict[str, Any]:
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


def extract_flutter_aot_features_from_apk(apk_path: str | Path, min_string_len: int = 3) -> FlutterAotFeatureResult:
    try:
        readelf = find_tool(["readelf", "llvm-readelf"])
        objdump = find_tool(["llvm-objdump", "aarch64-linux-gnu-objdump", "objdump"])
        with zipfile.ZipFile(apk_path) as apk:
            names = set(apk.namelist())
            if ARM64_LIBAPP not in names or ARM64_LIBFLUTTER not in names:
                return FlutterAotFeatureResult(status="skipped", error="missing arm64-v8a libapp.so/libflutter.so")
            libapp = apk.read(ARM64_LIBAPP)

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
            grams = sorted(f"{value:016x}" for value in opcode_4gram_hashes(opcodes))

            string_blob = libapp
            iso_data = symbols.get("_kDartIsolateSnapshotData")
            if iso_data:
                offset = va_to_file_offset(iso_data["vaddr"], segments)
                if offset is not None and offset + iso_data["size"] <= len(libapp):
                    string_blob = libapp[offset : offset + iso_data["size"]] + b"\x00" + libapp
            raw_strings = sorted(set(clean_string(item) for item in extract_utf8_printable_strings(string_blob, min_len=min_string_len)))
            raw_strings = [item for item in raw_strings if item and len(item) >= min_string_len]
            noise_strings = sorted(item for item in raw_strings if is_flutter_dart_public_noise(item))
            categories = classify_flutter_raw_strings(raw_strings)

        return FlutterAotFeatureResult(
            status="success",
            aot_opcode_4grams=grams,
            string_features=categories,
            instruction_count=len(opcodes),
            raw_string_count_all=len(raw_strings),
            flutter_dart_noise_count=len(noise_strings),
            disassembler_backend=disassembler_backend,
        )
    except Exception as exc:
        return FlutterAotFeatureResult(status="failed", error=f"{type(exc).__name__}: {exc}"[:2000])


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
