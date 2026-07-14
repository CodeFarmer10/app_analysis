from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


MAX_RESOLVE_DEPTH = 8
MAX_RESOLVED_VALUE_CHARS = 512
MAX_DEFINITION_EVIDENCE_CHARS = 300
MAX_JAVA_SOURCE_BYTES = 5 * 1024 * 1024
JAVA_IDENTIFIER = r"[A-Za-z_$][A-Za-z0-9_$]*"
JAVA_REFERENCE_PATTERN = re.compile(rf"^{JAVA_IDENTIFIER}(?:\.{JAVA_IDENTIFIER})*$")
PACKAGE_PATTERN = re.compile(rf"(?m)^\s*package\s+(?P<name>{JAVA_IDENTIFIER}(?:\.{JAVA_IDENTIFIER})*)\s*;")
IMPORT_PATTERN = re.compile(
    rf"(?m)^\s*import\s+(?P<static>static\s+)?(?P<name>{JAVA_IDENTIFIER}(?:\.{JAVA_IDENTIFIER})*)\s*;"
)
CLASS_PATTERN = re.compile(rf"\b(?:class|interface|enum|record)\s+(?P<name>{JAVA_IDENTIFIER})\b")
STRING_FIELD_PATTERN = re.compile(
    rf"(?P<declaration>"
    rf"(?P<modifiers>(?:(?:public|protected|private|static|final|transient|volatile)\s+)*)"
    rf"(?:java\.lang\.)?String\s+"
    rf"(?P<name>{JAVA_IDENTIFIER})\s*=\s*"
    rf"(?P<expression>.*?)"
    rf";)",
    re.DOTALL,
)


@dataclass(frozen=True)
class JavaSourceUnit:
    source_file: str
    package_name: str
    class_name: str
    imports: dict[str, str]
    static_imports: dict[str, str]

    @property
    def qualified_class_name(self) -> str:
        return f"{self.package_name}.{self.class_name}" if self.package_name else self.class_name


@dataclass(frozen=True)
class JavaConstantDefinition:
    qualified_name: str
    expression: str
    source_file: str
    line: int
    evidence: str
    unit: JavaSourceUnit


@dataclass(frozen=True)
class ResolvedJavaString:
    value: str
    definitions: tuple[JavaConstantDefinition, ...] = ()


class JavaSourceIndex:
    def __init__(self, source_root: str | Path) -> None:
        self._root = Path(source_root).resolve()
        self._source_roots = _source_roots(self._root)
        self._units: dict[str, JavaSourceUnit] = {}
        self._constants: dict[str, JavaConstantDefinition] = {}
        self._loaded_classes: set[str] = set()

    def register_source(self, source_file: str, text: str) -> JavaSourceUnit:
        existing = self._units.get(source_file)
        if existing is not None:
            return existing
        unit = _parse_source_unit(source_file, text)
        self._units[source_file] = unit
        self._loaded_classes.add(unit.qualified_class_name)
        self._index_constants(unit, text)
        return unit

    def unit_for(self, source_file: str) -> JavaSourceUnit | None:
        return self._units.get(source_file)

    def resolve(self, expression: str, unit: JavaSourceUnit | None) -> ResolvedJavaString | None:
        return self._resolve(expression, unit, seen=set(), depth=0)

    def _resolve(
        self,
        expression: str,
        unit: JavaSourceUnit | None,
        *,
        seen: set[str],
        depth: int,
    ) -> ResolvedJavaString | None:
        if depth > MAX_RESOLVE_DEPTH:
            return None
        normalized = _strip_wrapping_parentheses(expression.strip())
        normalized = re.sub(r"^\(\s*(?:java\.lang\.)?String\s*\)\s*", "", normalized)
        if not normalized:
            return None

        literal = _decode_java_string_literal(normalized)
        if literal is not None:
            if len(literal) <= MAX_RESOLVED_VALUE_CHARS:
                return ResolvedJavaString(literal)
            return None

        parts = _split_top_level(normalized, "+")
        if len(parts) > 1:
            resolved_parts = [self._resolve(part, unit, seen=set(seen), depth=depth + 1) for part in parts]
            if any(item is None for item in resolved_parts):
                return None
            values = [item.value for item in resolved_parts if item is not None]
            value = "".join(values)
            if len(value) > MAX_RESOLVED_VALUE_CHARS:
                return None
            definitions = tuple(
                definition
                for item in resolved_parts
                if item is not None
                for definition in item.definitions
            )
            return ResolvedJavaString(value, _deduplicate_definitions(definitions))

        qualified_name = self._resolve_reference(normalized, unit)
        if not qualified_name or qualified_name in seen:
            return None
        definition = self._constants.get(qualified_name)
        if definition is None:
            return None
        nested = self._resolve(
            definition.expression,
            definition.unit,
            seen={*seen, qualified_name},
            depth=depth + 1,
        )
        if nested is None:
            return None
        return ResolvedJavaString(
            nested.value,
            _deduplicate_definitions((definition, *nested.definitions)),
        )

    def _resolve_reference(self, reference: str, unit: JavaSourceUnit | None) -> str | None:
        compact = re.sub(r"\s+", "", reference)
        if not JAVA_REFERENCE_PATTERN.fullmatch(compact):
            return None
        if self._ensure_constant(compact):
            return compact
        if unit is None:
            return None

        static_import = unit.static_imports.get(compact)
        if static_import and self._ensure_constant(static_import):
            return static_import
        if "." not in compact:
            same_class = f"{unit.qualified_class_name}.{compact}"
            if self._ensure_constant(same_class):
                return same_class

        first, separator, remainder = compact.partition(".")
        imported_class = unit.imports.get(first)
        if separator and imported_class:
            imported_reference = f"{imported_class}.{remainder}"
            if self._ensure_constant(imported_reference):
                return imported_reference

        package_reference = f"{unit.package_name}.{compact}" if unit.package_name else compact
        if self._ensure_constant(package_reference):
            return package_reference
        return None

    def _ensure_constant(self, qualified_name: str) -> bool:
        if qualified_name in self._constants:
            return True
        class_name, separator, _field_name = qualified_name.rpartition(".")
        if not separator:
            return False
        self._load_class(class_name)
        return qualified_name in self._constants

    def _load_class(self, qualified_class_name: str) -> None:
        if qualified_class_name in self._loaded_classes:
            return
        self._loaded_classes.add(qualified_class_name)
        outer_class_name = qualified_class_name.split("$", 1)[0]
        relative_path = Path(*outer_class_name.split(".")).with_suffix(".java")
        for source_root in self._source_roots:
            file_path = source_root / relative_path
            try:
                if not file_path.is_file() or file_path.stat().st_size > MAX_JAVA_SOURCE_BYTES:
                    continue
                text = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            self.register_source(_relative_source_file(file_path, self._root), text)
            return

    def _index_constants(self, unit: JavaSourceUnit, text: str) -> None:
        if "String" not in text or "static" not in text or "final" not in text:
            return
        searchable_text = _mask_java_comments(text)
        for match in STRING_FIELD_PATTERN.finditer(searchable_text):
            modifiers = set(match.group("modifiers").split())
            if not {"static", "final"}.issubset(modifiers):
                continue
            field_name = match.group("name")
            qualified_name = f"{unit.qualified_class_name}.{field_name}"
            declaration = text[match.start("declaration") : match.end("declaration")]
            expression = searchable_text[match.start("expression") : match.end("expression")]
            evidence = re.sub(r"\s+", " ", declaration).strip()
            self._constants[qualified_name] = JavaConstantDefinition(
                qualified_name=qualified_name,
                expression=expression.strip(),
                source_file=unit.source_file,
                line=text.count("\n", 0, match.start()) + 1,
                evidence=evidence[:MAX_DEFINITION_EVIDENCE_CHARS],
                unit=unit,
            )


def _parse_source_unit(source_file: str, text: str) -> JavaSourceUnit:
    package_match = PACKAGE_PATTERN.search(text)
    package_name = package_match.group("name") if package_match else ""
    class_match = CLASS_PATTERN.search(text)
    class_name = class_match.group("name") if class_match else Path(source_file).stem
    imports: dict[str, str] = {}
    static_imports: dict[str, str] = {}
    for match in IMPORT_PATTERN.finditer(text):
        qualified_name = match.group("name")
        short_name = qualified_name.rsplit(".", 1)[-1]
        if match.group("static"):
            static_imports[short_name] = qualified_name
        else:
            imports[short_name] = qualified_name
    return JavaSourceUnit(source_file, package_name, class_name, imports, static_imports)


def _source_roots(root: Path) -> tuple[Path, ...]:
    sources_dir = root / "sources"
    if sources_dir.is_dir():
        return sources_dir, root
    return (root,)


def _relative_source_file(file_path: Path, root: Path) -> str:
    try:
        return file_path.relative_to(root).as_posix()
    except ValueError:
        return file_path.as_posix()


def _decode_java_string_literal(expression: str) -> str | None:
    if len(expression) < 2 or expression[0] != '"' or expression[-1] != '"':
        return None
    body = expression[1:-1]
    result: list[str] = []
    index = 0
    escapes = {
        "b": "\b",
        "t": "\t",
        "n": "\n",
        "f": "\f",
        "r": "\r",
        '"': '"',
        "'": "'",
        "\\": "\\",
    }
    while index < len(body):
        char = body[index]
        if char != "\\":
            result.append(char)
            index += 1
            continue
        index += 1
        if index >= len(body):
            return None
        escaped = body[index]
        if escaped == "u":
            while index < len(body) and body[index] == "u":
                index += 1
            digits = body[index : index + 4]
            if len(digits) != 4 or not re.fullmatch(r"[0-9A-Fa-f]{4}", digits):
                return None
            result.append(chr(int(digits, 16)))
            index += 4
            continue
        if escaped in "01234567":
            octal_match = re.match(r"[0-7]{1,3}", body[index:])
            if octal_match is None:
                return None
            result.append(chr(int(octal_match.group(0), 8)))
            index += len(octal_match.group(0))
            continue
        result.append(escapes.get(escaped, escaped))
        index += 1
    return "".join(result)


def _strip_wrapping_parentheses(expression: str) -> str:
    normalized = expression
    while normalized.startswith("(") and normalized.endswith(")"):
        closing = _matching_closing_parenthesis(normalized, 0)
        if closing != len(normalized) - 1:
            break
        normalized = normalized[1:-1].strip()
    return normalized


def _matching_closing_parenthesis(text: str, opening: int) -> int | None:
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(opening, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _split_top_level(text: str, delimiter: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depths = {"(": 0, "[": 0, "{": 0}
    closing = {")": "(", "]": "[", "}": "{"}
    quote: str | None = None
    escaped = False
    for index, char in enumerate(text):
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in {'"', "'"}:
            quote = char
        elif char in depths:
            depths[char] += 1
        elif char in closing:
            opener = closing[char]
            depths[opener] = max(0, depths[opener] - 1)
        elif char == delimiter and not any(depths.values()):
            parts.append(text[start:index].strip())
            start = index + 1
    parts.append(text[start:].strip())
    return parts


def _deduplicate_definitions(
    definitions: tuple[JavaConstantDefinition, ...],
) -> tuple[JavaConstantDefinition, ...]:
    seen: set[str] = set()
    result: list[JavaConstantDefinition] = []
    for definition in definitions:
        if definition.qualified_name in seen:
            continue
        seen.add(definition.qualified_name)
        result.append(definition)
    return tuple(result)


def _mask_java_comments(text: str) -> str:
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
        elif char in {'"', "'"}:
            quote = char
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
