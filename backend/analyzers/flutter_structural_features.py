from __future__ import annotations

import ast
import hashlib
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


CLASS_RE = re.compile(r"^\s*(?:abstract\s+|base\s+|final\s+|sealed\s+|interface\s+)?(?:class|mixin)\s+\S+.*\{\s*$")
FUNCTION_RE = re.compile(r"^\s{2}(?!//)(?!class\b)(?!mixin\b).*\{\s*$")
ADDRESS_LINE_RE = re.compile(r"^\s*(?://\s*)?(0x[0-9a-fA-F]+):\s*(.*?)\s*$")
ADDR_PREFIX_RE = re.compile(r"^\s*(?://\s*)?0x[0-9a-fA-F]+:\s*")
PP_OFFSET_RE = re.compile(r"\[pp\+0x[0-9a-fA-F]+\]", re.IGNORECASE)
HEX_RE = re.compile(r"\b0x[0-9a-fA-F]+\b")
STACK_MEM_RE = re.compile(r"\[(?:sp|fp|x29)(?:,\s*#?-?(?:0x[0-9a-fA-F]+|\d+))?\]!?")
REGISTER_RE = re.compile(r"\b(?:[wx](?:[0-9]|[12][0-9]|3[01])|v[0-9]+|q[0-9]+|d[0-9]+|s[0-9]+)\b")
QUOTED_RE = re.compile(r'"(?:\\.|[^"\\])*"')
GENERIC_IL_RE = re.compile(r"^[A-Z][A-Za-z0-9_]+(?:Instr)?(?:\b|:)")

COMMON_STRING_EXACT = {
    "",
    "dart:async",
    "dart:collection",
    "dart:convert",
    "dart:core",
    "dart:developer",
    "dart:ffi",
    "dart:io",
    "dart:isolate",
    "dart:math",
    "dart:typed_data",
    "dynamic",
    "flutter",
    "MaterialApp",
    "StatelessWidget",
    "StatefulWidget",
    "Widget",
}
COMMON_STRING_PREFIXES = (
    "package:flutter/",
    "package:vector_math/",
    "package:collection/",
    "package:async/",
    "package:characters/",
    "package:meta/",
    "package:path/",
    "package:sky_engine/",
)


@dataclass
class _FunctionBlock:
    strings: set[str] = field(default_factory=set)
    instructions: list[str] = field(default_factory=list)

    def to_feature(self) -> dict[str, Any] | None:
        cleaned_strings = sorted(value for value in self.strings if _is_business_string(value))
        if not cleaned_strings:
            return None
        normalized = [_normalize_instruction(item) for item in self.instructions]
        normalized = [item for item in normalized if item]
        return {
            "aot_fp": _fingerprint(normalized),
            "strings": cleaned_strings,
        }


@dataclass
class _ClassBlock:
    functions: list[_FunctionBlock] = field(default_factory=list)

    def to_feature(self) -> dict[str, Any] | None:
        function_features = []
        class_strings: set[str] = set()
        for function in self.functions:
            feature = function.to_feature()
            if feature is None:
                continue
            function_features.append(feature)
            class_strings.update(feature["strings"])
        if not function_features:
            return None
        return {
            "class_strings": sorted(class_strings),
            "functions": function_features,
        }


def extract_flutter_structural_features(asm_dir: str | Path) -> list[dict[str, Any]]:
    root = Path(asm_dir)
    if not root.is_dir():
        return []

    features: list[dict[str, Any]] = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        for class_block in _parse_file(path):
            feature = class_block.to_feature()
            if feature is not None:
                features.append(feature)
    return features


def _parse_file(path: Path) -> list[_ClassBlock]:
    classes: list[_ClassBlock] = []
    current_class: _ClassBlock | None = None
    current_function: _FunctionBlock | None = None
    class_depth = 0
    function_depth = 0

    with path.open(encoding="utf-8", errors="replace") as handle:
        for raw_line in handle:
            line = raw_line.rstrip("\n")
            open_count = line.count("{")
            close_count = line.count("}")

            if current_class is None:
                if CLASS_RE.match(line):
                    current_class = _ClassBlock()
                    class_depth = open_count - close_count
                continue

            if current_function is None and FUNCTION_RE.match(line):
                current_function = _FunctionBlock()
                current_class.functions.append(current_function)
                function_depth = open_count - close_count
                continue

            if current_function is not None:
                _collect_function_line(current_function, line)
                function_depth += open_count - close_count
                if function_depth <= 0:
                    current_function = None
                continue

            class_depth += open_count - close_count
            if class_depth <= 0:
                classes.append(current_class)
                current_class = None

    if current_class is not None:
        classes.append(current_class)
    return classes


def _collect_function_line(function: _FunctionBlock, line: str) -> None:
    function.strings.update(_extract_strings(line))
    match = ADDRESS_LINE_RE.match(line)
    if not match:
        return
    instruction = match.group(2).split(";", 1)[0].strip()
    if instruction and not GENERIC_IL_RE.match(instruction):
        function.instructions.append(instruction)


def _extract_strings(line: str) -> set[str]:
    values: set[str] = set()
    for quoted in QUOTED_RE.findall(line):
        value = _decode_quoted(quoted).strip()
        if _is_business_string(value):
            values.add(value)
    return values


def _decode_quoted(value: str) -> str:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            decoded = ast.literal_eval(value)
    except (SyntaxError, ValueError):
        return value[1:-1]
    return decoded if isinstance(decoded, str) else str(decoded)


def _is_business_string(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    if text in COMMON_STRING_EXACT:
        return False
    if any(text.startswith(prefix) for prefix in COMMON_STRING_PREFIXES):
        return False
    if text.startswith(("dart:", "package:flutter/")):
        return False
    return True


def _normalize_instruction(instruction: str) -> str:
    text = ADDR_PREFIX_RE.sub("", instruction)
    text = text.split(";", 1)[0].strip().lower()
    if not text:
        return ""
    text = PP_OFFSET_RE.sub("[pp+off]", text)
    text = STACK_MEM_RE.sub("[stack]", text)
    text = re.sub(r"\bx27\b", "pp", text)
    text = re.sub(r"\bx26\b", "thr", text)
    text = REGISTER_RE.sub("reg", text)
    text = HEX_RE.sub("imm", text)
    text = re.sub(r"#-?\d+\b", "#imm", text)
    text = re.sub(r"\b\d+\b", "imm", text)
    text = re.sub(r"\s+", " ", text)
    text = re.sub(r"\s*,\s*", ",", text)
    return text.strip()


def _fingerprint(normalized_instructions: list[str]) -> str:
    payload = "\n".join(normalized_instructions).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()[:16]
