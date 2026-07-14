from __future__ import annotations

import copy
import json
from typing import Any
from uuid import uuid4

from core.database import fetch_all, get_connection


SDK_RESULT_INSERT_SQL = """
    INSERT INTO sdk_results (
        id,
        task_id,
        sdk_id,
        sdk_name,
        sdk_type,
        vendor,
        package_prefix,
        source_file,
        evidence,
        param_name,
        param_value,
        credential_source_file,
        credential_line,
        credential_evidence,
        raw_finding
    )
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
"""


def _first_dict(value: Any) -> dict:
    if not isinstance(value, list):
        return {}
    return next((item for item in value if isinstance(item, dict)), {})


def _first_text(value: Any) -> str | None:
    if not isinstance(value, list):
        return None
    for item in value:
        text = str(item or "").strip()
        if text:
            return text
    return None


def flatten_sdk_finding(task_id: str, finding: dict) -> dict:
    recognition = _first_dict(finding.get("recognition_evidence"))
    credential = _first_dict(finding.get("credentials"))
    occurrence = _first_dict(credential.get("occurrences"))
    line = occurrence.get("line")
    try:
        credential_line = int(line) if line is not None else None
    except (TypeError, ValueError):
        credential_line = None

    return {
        "id": str(uuid4()),
        "task_id": task_id,
        "sdk_id": str(finding.get("sdk_id") or "").strip(),
        "sdk_name": str(finding.get("sdk_name") or "").strip() or None,
        "sdk_type": str(finding.get("sdk_type") or "").strip() or None,
        "vendor": str(finding.get("vendor") or "").strip() or None,
        "package_prefix": _first_text(finding.get("matched_package_prefixes")),
        "source_file": str(recognition.get("source_file") or "").strip() or None,
        "evidence": str(recognition.get("evidence") or "").strip() or None,
        "param_name": str(credential.get("param_name") or "").strip() or None,
        "param_value": str(credential.get("value") or "").strip() or None,
        "credential_source_file": str(occurrence.get("source_file") or "").strip() or None,
        "credential_line": credential_line,
        "credential_evidence": str(occurrence.get("evidence") or "").strip() or None,
        "raw_finding": copy.deepcopy(finding),
    }


def sdk_row_to_finding(row: dict) -> dict:
    raw_finding = row.get("raw_finding")
    if isinstance(raw_finding, str):
        try:
            raw_finding = json.loads(raw_finding)
        except json.JSONDecodeError:
            raw_finding = None
    if isinstance(raw_finding, dict):
        return copy.deepcopy(raw_finding)

    package_prefix = str(row.get("package_prefix") or "").strip()
    source_file = str(row.get("source_file") or "").strip()
    evidence = str(row.get("evidence") or "").strip()
    param_name = str(row.get("param_name") or "").strip()
    param_value = str(row.get("param_value") or "").strip()
    credential_source_file = str(row.get("credential_source_file") or "").strip()
    credential_evidence = str(row.get("credential_evidence") or "").strip()

    recognition_evidence = []
    if source_file or evidence:
        recognition_evidence.append({"source_file": source_file, "evidence": evidence})

    credentials = []
    if param_name or param_value:
        occurrences = []
        if credential_source_file or row.get("credential_line") is not None or credential_evidence:
            occurrences.append(
                {
                    "source_file": credential_source_file,
                    "line": row.get("credential_line"),
                    "evidence": credential_evidence,
                }
            )
        credentials.append(
            {
                "param_name": param_name,
                "value": param_value,
                "occurrences": occurrences,
            }
        )

    return {
        "sdk_id": str(row.get("sdk_id") or "").strip(),
        "sdk_name": str(row.get("sdk_name") or "").strip(),
        "sdk_type": str(row.get("sdk_type") or "").strip(),
        "vendor": str(row.get("vendor") or "").strip(),
        "matched_package_prefixes": [package_prefix] if package_prefix else [],
        "recognition_evidence": recognition_evidence,
        "credentials": credentials,
    }


def get_sdk_results(task_id: str) -> list[dict]:
    return fetch_all(
        """
        SELECT
            id,
            task_id,
            sdk_id,
            sdk_name,
            sdk_type,
            vendor,
            package_prefix,
            source_file,
            evidence,
            param_name,
            param_value,
            credential_source_file,
            credential_line,
            credential_evidence,
            raw_finding,
            created_at,
            updated_at
        FROM sdk_results
        WHERE task_id = %s
        ORDER BY sdk_id ASC
        """,
        (task_id,),
    )


def get_sdk_findings(task_id: str) -> list[dict]:
    return [sdk_row_to_finding(row) for row in get_sdk_results(task_id)]


def replace_sdk_results(task_id: str, findings: list[dict] | None) -> int:
    rows = []
    seen_sdk_ids: set[str] = set()
    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        row = flatten_sdk_finding(task_id, finding)
        sdk_id = row["sdk_id"]
        if not sdk_id or sdk_id in seen_sdk_ids:
            continue
        seen_sdk_ids.add(sdk_id)
        rows.append(row)

    with get_connection() as conn:
        with conn.cursor() as cursor:
            try:
                conn.begin()
                cursor.execute("DELETE FROM sdk_results WHERE task_id = %s", (task_id,))
                if rows:
                    cursor.executemany(
                        SDK_RESULT_INSERT_SQL,
                        [
                            (
                                row["id"],
                                row["task_id"],
                                row["sdk_id"],
                                row["sdk_name"],
                                row["sdk_type"],
                                row["vendor"],
                                row["package_prefix"],
                                row["source_file"],
                                row["evidence"],
                                row["param_name"],
                                row["param_value"],
                                row["credential_source_file"],
                                row["credential_line"],
                                row["credential_evidence"],
                                json.dumps(row["raw_finding"], ensure_ascii=False),
                            )
                            for row in rows
                        ],
                    )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
    return len(rows)
