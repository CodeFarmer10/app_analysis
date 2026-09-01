from __future__ import annotations

import argparse
import csv
import gzip
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from analyzers.flutter_aot_features import classify_flutter_raw_strings, has_valid_url_host, is_framework_url  # noqa: E402
from core.database import execute, fetch_all  # noqa: E402


def read_lines_gz(path: Path) -> list[str]:
    if not path.exists():
        return []
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
        return [line.rstrip("\n") for line in handle if line.strip()]


def read_feature_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def read_onecol_tsv(path: Path, column: str) -> list[str]:
    if not path.exists():
        return []
    values: list[str] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        for row in reader:
            value = str(row.get(column) or "").strip()
            if value:
                values.append(value)
    return sorted(set(values))


def read_business_tsv(path: Path) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {"camelCase": [], "structured_key": []}
    if not path.exists():
        return values
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        for row in reader:
            subtype = str(row.get("subtype") or "").strip()
            value = str(row.get("string") or "").strip()
            if subtype in values and value:
                values[subtype].append(value)
    return {key: sorted(set(items)) for key, items in values.items()}


def load_categorized_strings(app_dir: Path) -> dict[str, Any] | None:
    required = [
        app_dir / "api_routes.tsv",
        app_dir / "urls.tsv",
        app_dir / "library_uri_like.tsv",
        app_dir / "chinese_text.tsv",
        app_dir / "business_strings.tsv",
    ]
    if not all(path.exists() for path in required):
        return None
    urls = [
        value
        for value in read_onecol_tsv(app_dir / "urls.tsv", "url")
        if has_valid_url_host(value) and not is_framework_url(value)
    ]
    return {
        "api_route": read_onecol_tsv(app_dir / "api_routes.tsv", "api_route"),
        "url": sorted(set(urls)),
        "library_uri_like": read_onecol_tsv(app_dir / "library_uri_like.tsv", "library_uri_like"),
        "chinese_text": read_onecol_tsv(app_dir / "chinese_text.tsv", "chinese_text"),
        "business_string": read_business_tsv(app_dir / "business_strings.tsv"),
    }


def load_md5_payload(app_dir: Path) -> dict[str, Any]:
    md5 = app_dir.name.lower()
    feature_json = read_feature_json(app_dir / "features.json")
    aot_grams = read_lines_gz(app_dir / "aot_opcode_4gram.u64.txt.gz")
    string_features = load_categorized_strings(app_dir)
    if string_features is None:
        raw_strings = read_lines_gz(app_dir / "raw_strings_all.txt.gz")
    else:
        raw_strings = []
    if string_features is None and raw_strings:
        string_features = classify_flutter_raw_strings(raw_strings)
    elif string_features is None:
        string_features = ((feature_json.get("strings") or {}).get("categories") or classify_flutter_raw_strings([]))
        string_features["url"] = sorted(
            value
            for value in string_features.get("url", [])
            if has_valid_url_host(value) and not is_framework_url(value)
        )
    return {
        "md5": md5,
        "status": feature_json.get("status") or "",
        "aot_grams": aot_grams,
        "string_features": string_features,
    }


def ensure_columns() -> None:
    statements = [
        """
        ALTER TABLE static_results
        ADD COLUMN flutter_aot_opcode_4grams LONGTEXT NULL
        """,
        """
        ALTER TABLE static_results
        MODIFY COLUMN flutter_aot_opcode_4grams LONGTEXT NULL
        """,
        """
        ALTER TABLE static_results
        ADD COLUMN flutter_string_features JSON NULL
        """,
    ]
    for statement in statements:
        try:
            execute(statement)
        except Exception as exc:
            text = str(exc)
            if "Duplicate column name" not in text and "1060" not in text:
                raise


def update_by_md5(payload: dict[str, Any], dry_run: bool = False) -> int:
    rows = fetch_all(
        """
        SELECT sr.task_id
        FROM static_results sr
        JOIN tasks t ON t.id = sr.task_id
        WHERE LOWER(t.file_md5) = %s
          AND sr.framework_name = 'Flutter'
        """,
        (payload["md5"],),
    )
    if dry_run or not rows:
        return len(rows)
    execute(
        """
        UPDATE static_results sr
        JOIN tasks t ON t.id = sr.task_id
        SET sr.flutter_aot_opcode_4grams = %s,
            sr.flutter_string_features = %s
        WHERE LOWER(t.file_md5) = %s
          AND sr.framework_name = 'Flutter'
        """,
        (
            ",".join(payload["aot_grams"]),
            json.dumps(payload["string_features"], ensure_ascii=False),
            payload["md5"],
        ),
    )
    return len(rows)


def backfill(source_root: Path, limit: int | None = None, dry_run: bool = False, quiet: bool = False) -> dict[str, Any]:
    if not source_root.is_dir():
        raise FileNotFoundError(f"source root not found: {source_root}")
    if not dry_run:
        ensure_columns()
    app_dirs = sorted(path for path in source_root.iterdir() if path.is_dir() and len(path.name) == 32)
    if limit is not None:
        app_dirs = app_dirs[: max(0, limit)]

    stats: Counter[str] = Counter()
    updated_rows = 0
    for index, app_dir in enumerate(app_dirs, start=1):
        payload = load_md5_payload(app_dir)
        matched_rows = update_by_md5(payload, dry_run=dry_run)
        updated_rows += matched_rows
        stats[payload["status"] or "unknown"] += 1
        if not quiet:
            print(
                json.dumps(
                    {
                        "index": index,
                        "total": len(app_dirs),
                        "md5": payload["md5"],
                        "status": payload["status"],
                        "aot_grams": len(payload["aot_grams"]),
                        "matched_rows": matched_rows,
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )

    return {
        "source_root": str(source_root),
        "app_dirs": len(app_dirs),
        "updated_rows": updated_rows,
        "dry_run": dry_run,
        "status_counts": dict(stats),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Backfill Flutter AOT opcode 4-gram and categorized string features into static_results.")
    parser.add_argument("--source-root", type=Path, default=Path("outputs/flutter_aot_4gram_features"))
    parser.add_argument("--limit", type=int)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    result = backfill(args.source_root, limit=args.limit, dry_run=args.dry_run, quiet=args.quiet)
    print(json.dumps({"event": "complete", **result}, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
