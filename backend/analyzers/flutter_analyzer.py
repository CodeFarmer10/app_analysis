from __future__ import annotations

import ast
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


LIBRARY_RE = re.compile(r"^// lib:.*?, url:\s*(.*?)\s*$")
PACKAGE_ROOT_RE = re.compile(r"^package:([^/]+)/")
CLASS_RE = re.compile(
    r"^(?:(?:abstract|base|final|sealed|interface)\s+)?"
    r"(?:class|mixin)\s+(.+?)"
    r"(?=\s+extends\b|\s+implements\b|\s+with\b|\s+on\b|\s*\{?\s*$)"
)
MAIN_RE = re.compile(r"^\s+(?:\[closure\]\s+)?static\s+(?:Future(?:<[^>]+>)?|void|dynamic|_)\s+main\s*\(")
RUN_APP_RE = re.compile(r"\br\d+\s*=\s*runApp\(\)|\[package:flutter/src/widgets/binding\.dart\]\s+::runApp")
ALLOCATED_CLASS_RE = re.compile(r"Allocate([A-Za-z_$][A-Za-z0-9_$]*)Stub(?:\s*->\s*([A-Za-z_$][A-Za-z0-9_$]*))?")
INSTANCE_CLASS_RE = re.compile(r"\bInstance_([A-Za-z_$][A-Za-z0-9_$]*)\b")
BUILD_RE = re.compile(r"^\s{2}(?!//).*\bbuild\s*\(")
CREATE_STATE_RE = re.compile(r"^\s{2}(?!//).*\bcreateState\s*\(")

ROOT_APP_PATTERNS = {
    "MaterialApp": re.compile(r"\b(?:AllocateMaterialAppStub|MaterialApp::MaterialApp)\b"),
    "CupertinoApp": re.compile(r"\b(?:AllocateCupertinoAppStub|CupertinoApp::CupertinoApp)\b"),
    "WidgetsApp": re.compile(r"\b(?:AllocateWidgetsAppStub|WidgetsApp::WidgetsApp)\b"),
    "GetMaterialApp": re.compile(r"\b(?:AllocateGetMaterialAppStub|GetMaterialApp::GetMaterialApp)\b"),
}

COMMON_DART_PACKAGES = {
    "analyzer",
    "archive",
    "args",
    "async",
    "characters",
    "collection",
    "convert",
    "crypto",
    "dio",
    "ffi",
    "flutter",
    "http",
    "intl",
    "js",
    "logging",
    "meta",
    "path",
    "plugin_platform_interface",
    "protobuf",
    "quiver",
    "typed_data",
    "vector_math",
    "web",
    "xml",
}


@dataclass
class FlutterAnalysisResult:
    status: str = "ok"
    asm_dir: str = ""
    primary_package: str = ""
    primary_entry_uri: str = ""
    primary_entry_method: str = ""
    primary_entry_confidence: str = "none"
    root_widget_class: str = ""
    root_widget_library_uri: str = ""
    library_uris: list[str] = field(default_factory=list)
    primary_package_classes: list[str] = field(default_factory=list)
    class_count: int = 0
    error: str = ""

    def to_static_field(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "asm_dir": self.asm_dir,
            "primary_package": self.primary_package,
            "primary_entry_uri": self.primary_entry_uri,
            "primary_entry_method": self.primary_entry_method,
            "primary_entry_confidence": self.primary_entry_confidence,
            "root_widget_class": self.root_widget_class,
            "root_widget_library_uri": self.root_widget_library_uri,
            "library_uris": self.library_uris,
            "primary_package_classes": self.primary_package_classes,
            "class_count": self.class_count,
            "error": self.error,
        }


def missing_flutter_asm_result(candidates: list[str]) -> dict[str, Any]:
    return FlutterAnalysisResult(
        status="missing_asm",
        error="未找到 Flutter blutter asm 产物",
        library_uris=[],
        primary_package_classes=[],
    ).to_static_field() | {"candidate_asm_dirs": candidates}


def analyze_flutter_asm_dir(asm_dir: str | Path) -> FlutterAnalysisResult:
    root = Path(asm_dir)
    if not root.is_dir():
        return FlutterAnalysisResult(status="missing_asm", asm_dir=str(root), error="asm 目录不存在")

    records = _scan_library_records(root)
    primary = _locate_primary_entry(records)
    features = _extract_primary_features(records, primary)

    return FlutterAnalysisResult(
        status="ok" if records else "empty_asm",
        asm_dir=str(root),
        primary_package=str(primary["package"]),
        primary_entry_uri=str(primary["entry_uri"]),
        primary_entry_method=str(primary["method"]),
        primary_entry_confidence=str(primary["confidence"]),
        root_widget_class=str(primary["root_widget_class"]),
        root_widget_library_uri=str(primary["root_widget_library_uri"]),
        library_uris=features["library_uris"],
        primary_package_classes=features["classes"],
        class_count=len(features["classes"]),
    )


def resolve_flutter_asm_dir(file_md5: str | None, roots: list[str | Path]) -> tuple[Path | None, list[str]]:
    md5 = str(file_md5 or "").strip().lower()
    if not md5:
        return None, []
    candidates: list[Path] = []
    for raw_root in roots:
        if not raw_root:
            continue
        root = Path(raw_root).expanduser()
        candidates.append(root / md5 / "asm")
    seen: set[str] = set()
    unique = []
    for candidate in candidates:
        text = str(candidate)
        if text not in seen:
            seen.add(text)
            unique.append(candidate)
    for candidate in unique:
        if candidate.is_dir():
            return candidate, [str(item) for item in unique]
    return None, [str(item) for item in unique]


def _package_root(uri: str) -> str:
    match = PACKAGE_ROOT_RE.match(uri)
    return match.group(1) if match else ""


def _decode_quoted(value: str) -> str:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            decoded = ast.literal_eval(value)
    except (SyntaxError, ValueError):
        return value[1:-1]
    return decoded if isinstance(decoded, str) else str(decoded)


def _strip_generic_segments(value: str) -> str:
    output: list[str] = []
    index = 0
    while index < len(value):
        if value[index] != "<":
            output.append(value[index])
            index += 1
            continue
        depth = 1
        cursor = index + 1
        while cursor < len(value) and depth:
            if value[cursor] == "<":
                depth += 1
            elif value[cursor] == ">":
                depth -= 1
            cursor += 1
        if depth:
            output.append(value[index:])
            break
        index = cursor
    return "".join(output)


def _normalize_class_name(value: str) -> str:
    return _strip_generic_segments(re.sub(r"[\r\n\u0085\u2028\u2029]+", " ", value)).strip()


def _opaque_package_name(uri: str, path: Path) -> str:
    root = _package_root(uri)
    if root:
        return root
    if uri.startswith("file:"):
        normalized = uri.replace("\\", "/")
        match = re.search(r"/([^/]+)/lib/(?:.+/)?main\.dart$", normalized)
        if match:
            return match.group(1)
        return path.parent.name
    if uri and ":" not in uri and "/" not in uri:
        return uri
    return ""


def _excluded_non_common_library(uri: str) -> bool:
    if not uri or uri.startswith(("dart:", "package:flutter/")):
        return True
    root = _package_root(uri)
    return bool(root and root in COMMON_DART_PACKAGES)


def _parse_library_record(path: Path) -> dict[str, Any]:
    uri = ""
    classes: set[str] = set()
    class_details: dict[str, dict[str, Any]] = {}
    current_class = ""
    in_main = False
    in_create_state = False
    create_state_owner = ""
    has_main = False
    calls_run_app = False
    main_instances: set[str] = set()

    with path.open(encoding="utf-8", errors="replace") as handle:
        for line_number, line in enumerate(handle):
            stripped = line.rstrip("\n")
            if line_number == 0:
                match = LIBRARY_RE.match(stripped)
                uri = match.group(1) if match else ""

            class_match = CLASS_RE.match(stripped)
            if class_match:
                current_class = _normalize_class_name(class_match.group(1))
                if current_class == "::":
                    current_class = ""
                    continue
                classes.add(current_class)
                owner_match = re.search(r"\bextends\s+State<\s*([^>,\s]+)", stripped)
                class_details[current_class] = {
                    "has_build": False,
                    "root_app_types": set(),
                    "widget_like": bool(re.search(r"\bextends\s+[A-Za-z0-9_$]*(?:Widget|State)(?:<|\b)", stripped)),
                    "widget_owner": owner_match.group(1) if owner_match else "",
                    "created_states": set(),
                }
                continue

            if stripped == "}":
                current_class = ""
            if current_class and BUILD_RE.match(line):
                class_details[current_class]["has_build"] = True
            if current_class and CREATE_STATE_RE.match(line):
                in_create_state = True
                create_state_owner = current_class
            elif in_create_state and stripped == "  }":
                in_create_state = False
                create_state_owner = ""
            if in_create_state and create_state_owner:
                for match in ALLOCATED_CLASS_RE.finditer(line):
                    class_details[create_state_owner]["created_states"].add(match.group(2) or match.group(1))
            if current_class:
                for app_type, pattern in ROOT_APP_PATTERNS.items():
                    if pattern.search(line):
                        class_details[current_class]["root_app_types"].add(app_type)
            if MAIN_RE.match(line):
                has_main = True
                in_main = True
            elif in_main and stripped == "  }":
                in_main = False
            calls_run_app = calls_run_app or bool(RUN_APP_RE.search(line))
            if in_main:
                for match in ALLOCATED_CLASS_RE.finditer(line):
                    main_instances.add(match.group(2) or match.group(1))
                main_instances.update(INSTANCE_CLASS_RE.findall(line))

    for widget_name, detail in class_details.items():
        for state_name in detail["created_states"]:
            if state_name in class_details:
                class_details[state_name]["widget_owner"] = widget_name

    return {
        "path": path,
        "uri": uri,
        "package": _opaque_package_name(uri, path),
        "has_main": has_main,
        "calls_run_app": calls_run_app,
        "main_instances": main_instances,
        "classes": classes,
        "class_details": class_details,
    }


def _scan_library_records(asm_dir: Path) -> list[dict[str, Any]]:
    return [_parse_library_record(path) for path in sorted(item for item in asm_dir.rglob("*") if item.is_file())]


def _root_widget_candidates(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for record in records:
        uri = str(record["uri"])
        if _excluded_non_common_library(uri):
            continue
        for class_name, detail in record["class_details"].items():
            root_types = set(detail["root_app_types"])
            if not detail["has_build"] or not detail["widget_like"] or not root_types or class_name in ROOT_APP_PATTERNS:
                continue
            candidates.append(
                {
                    "class": detail["widget_owner"] or class_name,
                    "build_class": class_name,
                    "uri": uri,
                    "path": record["path"],
                    "package": record["package"],
                    "root_app_types": sorted(root_types),
                }
            )
    return candidates


def _choose_root_widget(entry: dict[str, Any] | None, candidates: list[dict[str, Any]]) -> tuple[dict[str, Any] | None, str]:
    if not candidates:
        return None, ""
    if entry is not None:
        main_instances = set(entry["main_instances"])
        direct = [item for item in candidates if item["class"] in main_instances or item["build_class"] in main_instances]
        if len(direct) == 1:
            return direct[0], "direct"
        in_entry = [item for item in candidates if item["path"] == entry["path"]]
        if len(in_entry) == 1:
            return in_entry[0], "entry_library"
        entry_package = str(entry["package"])
        same_package = [item for item in candidates if entry_package and item["package"] == entry_package]
        if len(same_package) == 1:
            return same_package[0], "same_package"
    likely = [
        item for item in candidates
        if Path(item["path"]).name.lower() in {"main.dart", "app.dart"} or re.search(r"(?:App|Root)$", str(item["class"]))
    ]
    packages = {str(item["package"]) for item in likely if item["package"]}
    if len(likely) == 1 and len(packages) == 1:
        return likely[0], "unique_root_widget"
    return None, ""


def _locate_primary_entry(records: list[dict[str, Any]]) -> dict[str, Any]:
    metadata = [
        item for item in records
        if not _excluded_non_common_library(str(item["uri"]))
        and (Path(item["path"]).name.lower() == "main.dart" or Path(item["path"]).parent.name == "asm" or item["has_main"] or item["calls_run_app"])
    ]
    strong = [item for item in metadata if item["has_main"] and item["calls_run_app"]]
    main_only = [item for item in metadata if item["has_main"]]
    run_app_only = [item for item in metadata if item["calls_run_app"]]
    if strong:
        chosen, method, confidence = strong[0], "main_and_runApp", "high"
    elif main_only:
        chosen, method, confidence = main_only[0], "main_only", "medium"
    elif run_app_only:
        chosen, method, confidence = run_app_only[0], "runApp_only", "low"
    else:
        chosen, method, confidence = None, "unresolved", "none"

    root, root_evidence = _choose_root_widget(chosen, _root_widget_candidates(records))
    if chosen is None and root is not None:
        chosen = next(item for item in records if item["path"] == root["path"])
        method, confidence = "root_widget_build_app", "medium"
    elif chosen is not None and root is not None and method == "main_only":
        method = "main_root_widget_build_app"
        confidence = "high" if root_evidence == "direct" else "medium"

    if chosen is None:
        return {
            "package": "",
            "entry_uri": "",
            "method": "unresolved",
            "confidence": "none",
            "entry_path": None,
            "root_widget_class": "",
            "root_widget_library_uri": "",
        }
    primary_package = str(chosen["package"])
    if root is not None and (not primary_package or method == "root_widget_build_app"):
        primary_package = str(root["package"])
    return {
        "package": primary_package,
        "entry_uri": str(chosen["uri"]),
        "method": method,
        "confidence": confidence,
        "entry_path": Path(chosen["path"]),
        "root_widget_class": str(root["class"]) if root else "",
        "root_widget_library_uri": str(root["uri"]) if root else "",
    }


def _primary_library_records(records: list[dict[str, Any]], primary: dict[str, Any]) -> list[dict[str, Any]]:
    package = str(primary["package"])
    entry_uri = str(primary["entry_uri"])
    entry_path = primary["entry_path"]
    if not package or not isinstance(entry_path, Path):
        return []
    root = _package_root(entry_uri)
    if root:
        return [record for record in records if _package_root(str(record["uri"])) == root]
    if entry_uri.startswith("file:"):
        marker = f"/{package}/"
        return [record for record in records if str(record["uri"]).startswith("file:") and marker in str(record["uri"])]
    return [record for record in records if Path(record["path"]) == entry_path]


def _extract_primary_features(records: list[dict[str, Any]], primary: dict[str, Any]) -> dict[str, list[str]]:
    classes: set[str] = set()
    library_uris: set[str] = set()
    for record in _primary_library_records(records, primary):
        uri = str(record["uri"])
        if uri:
            library_uris.add(uri)
        classes.update(record["classes"])
    return {"library_uris": sorted(library_uris), "classes": sorted(classes)}
