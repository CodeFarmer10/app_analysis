from __future__ import annotations

import logging
import re
from typing import Any, Iterable


logger = logging.getLogger(__name__)

CONTENT_INCLUDE_PATTERN = re.compile(
    r"""^content_include\(\s*(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*(?P<quote>['"])(?P<values>.*)(?P=quote)\s*\)$""",
    re.DOTALL,
)
CONTENT_INCLUDE_MISSING_CLOSING_QUOTE_PATTERN = re.compile(
    r"""^content_include\(\s*(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*(?P<quote>['"])(?P<values>.*)\s*\)$""",
    re.DOTALL,
)
KEYWORDS_CONTAINS_PATTERN = re.compile(
    r"""^keywords_contains\(\s*(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*,\s*(?P<quote>['"])(?P<regex>.*)(?P=quote)\s*,\s*(?P<count>\d+)\s*\)$""",
    re.DOTALL,
)
REGEX_MATCH_PATTERN = re.compile(
    r"""^(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*=~\s*/(?P<regex>.*)/$""",
    re.DOTALL,
)
EQUALS_PATTERN = re.compile(
    r"""^(?P<field>[A-Za-z_][A-Za-z0-9_]*)\s*==\s*(?P<quote>['"])(?P<value>.*)(?P=quote)$""",
    re.DOTALL,
)


def _camel_to_snake(value: str) -> str:
    first_pass = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", value)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", first_pass).lower()


def _field_value(static_result: dict[str, Any], field: str) -> str:
    value = static_result.get(_camel_to_snake(field))
    if value is None:
        value = static_result.get(field)
    if value is None:
        return ""
    if isinstance(value, (list, tuple, set)):
        return ",".join(str(item).strip() for item in value if str(item).strip())
    return str(value)


def _split_comma_values(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def _split_field_values(field: str, value: str) -> list[str]:
    if _camel_to_snake(field) == "components":
        return [item.strip() for item in re.split(r"[,\s]+", value) if item.strip()]
    return _split_comma_values(value)


def _regex_field_value(static_result: dict[str, Any], field: str) -> str:
    value = _field_value(static_result, field)
    if _camel_to_snake(field) == "components":
        return ",".join(_split_field_values(field, value))
    return value


def _like_pattern_to_regex(pattern: str) -> re.Pattern[str]:
    regex = "^" + re.escape(pattern).replace("%", ".*") + "$"
    return re.compile(regex)


def _content_include(expression: str, static_result: dict[str, Any]) -> bool | None:
    match = CONTENT_INCLUDE_PATTERN.match(expression)
    if not match:
        match = CONTENT_INCLUDE_MISSING_CLOSING_QUOTE_PATTERN.match(expression)
    if not match:
        return None

    actual_values = _split_field_values(match.group("field"), _field_value(static_result, match.group("field")))
    expected_values = _split_comma_values(match.group("values"))
    if not expected_values:
        return False

    for expected in expected_values:
        if "%" in expected:
            expected_regex = _like_pattern_to_regex(expected)
            if not any(expected_regex.match(actual) for actual in actual_values):
                return False
        elif expected not in actual_values:
            return False
    return True


def _keywords_contains(expression: str, static_result: dict[str, Any]) -> bool | None:
    match = KEYWORDS_CONTAINS_PATTERN.match(expression)
    if not match:
        return None

    try:
        pattern = re.compile(match.group("regex"))
    except re.error as exc:
        logger.warning("invalid keywords_contains regex expression=%s err=%s", expression, exc)
        return False
    count = int(match.group("count"))
    actual = _regex_field_value(static_result, match.group("field"))
    return len(pattern.findall(actual)) >= count


def _regex_match(expression: str, static_result: dict[str, Any]) -> bool | None:
    match = REGEX_MATCH_PATTERN.match(expression)
    if not match:
        return None

    try:
        pattern = re.compile(match.group("regex"))
    except re.error as exc:
        logger.warning("invalid regex model expression=%s err=%s", expression, exc)
        return False
    return bool(pattern.search(_field_value(static_result, match.group("field"))))


def _equals(expression: str, static_result: dict[str, Any]) -> bool | None:
    match = EQUALS_PATTERN.match(expression)
    if not match:
        return None
    return _field_value(static_result, match.group("field")) == match.group("value")


def _evaluate_atom(expression: str, static_result: dict[str, Any]) -> bool:
    stripped = expression.strip()
    for evaluator in (_content_include, _keywords_contains, _regex_match, _equals):
        result = evaluator(stripped, static_result)
        if result is not None:
            return result
    logger.warning("unsupported model expression atom=%s", stripped)
    return False


def evaluate_model_expression(expression: str | None, static_result: dict[str, Any]) -> bool:
    text = str(expression or "").strip()
    if not text:
        return False

    has_and = "&&" in text
    has_or = "||" in text
    if has_and and has_or:
        logger.warning("mixed boolean model expression is unsupported expression=%s", text)
        return False
    if has_and:
        return all(_evaluate_atom(part, static_result) for part in text.split("&&"))
    if has_or:
        return any(_evaluate_atom(part, static_result) for part in text.split("||"))
    return _evaluate_atom(text, static_result)


def find_first_matching_model(
    static_result: dict[str, Any],
    models: Iterable[dict[str, Any]],
) -> dict[str, str | None]:
    for model in models:
        if evaluate_model_expression(model.get("model_expression"), static_result):
            return {
                "model_id": model.get("model_id"),
                "model_name": model.get("model_name"),
                "model_type_name": model.get("model_type_name"),
            }
    return {"model_id": None, "model_name": None, "model_type_name": None}
