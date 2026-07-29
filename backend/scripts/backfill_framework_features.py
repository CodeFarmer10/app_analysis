from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
import threading
import time
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from core.config import settings  # noqa: E402
from core.database import fetch_all  # noqa: E402
from repositories.task_repo import update_static_result_fields  # noqa: E402
from services.storage_service import storage_service  # noqa: E402
from workers.static_analysis import _extract_dcloud_fields, _extract_flutter_fields  # noqa: E402


DCLOUD_FRAMEWORK = "uni-app/DCloud"
FLUTTER_FRAMEWORK = "Flutter"


@dataclass
class Candidate:
    md5: str
    apk_path: str
    task_ids: list[str]
    is_obfuscated: bool = False


_print_lock = threading.Lock()


def _emit(event: str, **fields: Any) -> None:
    payload = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "event": event,
        **fields,
    }
    with _print_lock:
        print(json.dumps(payload, ensure_ascii=False), flush=True)


def _load_candidates(
    framework: str,
    limit: int | None,
    target_md5s: set[str] | None = None,
) -> list[Candidate]:
    if framework == DCLOUD_FRAMEWORK:
        missing_sql = """
            sr.dcloud_tech_type IS NULL OR sr.dcloud_tech_type = ''
            OR sr.dcloud_pages IS NULL OR sr.dcloud_api_routes IS NULL
            OR sr.dcloud_remote_service_urls IS NULL
            OR sr.dcloud_remote_service_domains IS NULL
        """
    else:
        missing_sql = """
            sr.flutter_primary_package IS NULL OR sr.flutter_primary_package = ''
            OR sr.flutter_library_uris IS NULL
            OR JSON_LENGTH(sr.flutter_library_uris) = 0
            OR sr.flutter_primary_package_classes IS NULL
        """

    target_sql = ""
    params: list[Any] = [framework]
    if target_md5s:
        placeholders = ", ".join(["%s"] * len(target_md5s))
        target_sql = f" AND LOWER(t.file_md5) IN ({placeholders})"
        params.extend(sorted(target_md5s))

    rows = fetch_all(
        f"""
        SELECT
            t.id AS task_id,
            t.file_md5,
            t.apk_path,
            t.created_at,
            COALESCE(sr.is_obfuscated, 0) AS is_obfuscated
        FROM tasks t
        JOIN static_results sr ON sr.task_id = t.id
        WHERE sr.framework_name = %s
          AND t.file_md5 IS NOT NULL
          AND t.file_md5 <> ''
          AND ({missing_sql})
          {target_sql}
        ORDER BY t.created_at DESC
        """,
        tuple(params),
    )

    grouped: dict[str, Candidate] = {}
    for row in rows:
        md5 = str(row.get("file_md5") or "").strip().lower()
        if not md5:
            continue
        candidate = grouped.get(md5)
        if candidate is None:
            candidate = Candidate(
                md5=md5,
                apk_path=str(row.get("apk_path") or "").strip(),
                task_ids=[],
                is_obfuscated=bool(row.get("is_obfuscated")),
            )
            grouped[md5] = candidate
        elif not candidate.apk_path:
            candidate.apk_path = str(row.get("apk_path") or "").strip()
        candidate.task_ids.append(str(row["task_id"]))
        candidate.is_obfuscated = candidate.is_obfuscated or bool(row.get("is_obfuscated"))

    candidates = [item for item in grouped.values() if item.apk_path]
    if limit is not None:
        candidates = candidates[: max(0, limit)]
    return candidates


def _download_verified(candidate: Candidate) -> str:
    local_path = storage_service.download_to_temp(candidate.apk_path)
    digest = hashlib.md5()
    with Path(local_path).open("rb") as apk_file:
        for chunk in iter(lambda: apk_file.read(1024 * 1024), b""):
            digest.update(chunk)
    actual_md5 = digest.hexdigest()
    if actual_md5 != candidate.md5:
        _cleanup_download(local_path)
        raise RuntimeError(f"APK MD5不匹配: expected={candidate.md5} actual={actual_md5}")
    return local_path


def _cleanup_download(local_path: str) -> None:
    if not local_path:
        return
    path = Path(local_path)
    path.unlink(missing_ok=True)
    if path.parent.exists():
        shutil.rmtree(path.parent, ignore_errors=True)


def _update_tasks(candidate: Candidate, fields: dict[str, Any]) -> int:
    updated = 0
    for task_id in candidate.task_ids:
        updated += update_static_result_fields(task_id, fields)
    return updated


def _process_dcloud(candidate: Candidate) -> dict[str, Any]:
    local_path = ""
    started = time.monotonic()
    try:
        local_path = _download_verified(candidate)
        fields = _extract_dcloud_fields(
            local_path,
            DCLOUD_FRAMEWORK,
            candidate.is_obfuscated,
        )
        if fields.get("dcloud_tech_type") == "error":
            raise RuntimeError("DCloud资源分析返回error")
        updated_rows = _update_tasks(candidate, fields)
        return {
            "status": "success",
            "md5": candidate.md5,
            "updated_rows": updated_rows,
            "elapsed_seconds": round(time.monotonic() - started, 2),
            "tech_type": fields.get("dcloud_tech_type"),
            "page_count": len(fields.get("dcloud_pages") or []),
            "api_route_count": len(fields.get("dcloud_api_routes") or []),
            "remote_url_count": len(fields.get("dcloud_remote_service_urls") or []),
            "remote_domain_count": len(fields.get("dcloud_remote_service_domains") or []),
        }
    except Exception as exc:
        return {
            "status": "failed",
            "md5": candidate.md5,
            "updated_rows": 0,
            "elapsed_seconds": round(time.monotonic() - started, 2),
            "error": f"{type(exc).__name__}: {exc}"[:1000],
        }
    finally:
        _cleanup_download(local_path)


def _process_flutter(candidate: Candidate) -> dict[str, Any]:
    local_path = ""
    started = time.monotonic()
    try:
        local_path = _download_verified(candidate)
        fields = _extract_flutter_fields(local_path, candidate.md5, FLUTTER_FRAMEWORK)
        library_uris = fields.get("flutter_library_uris") or []
        if not library_uris:
            raise RuntimeError(
                "Flutter分析未生成有效特征"
                f" dart={fields.get('flutter_dart_version') or '-'}"
                f" backend={fields.get('flutter_blutter_backend_version') or '-'}"
                f" libraries={len(library_uris)}"
            )
        updated_rows = _update_tasks(candidate, fields)
        return {
            "status": "success",
            "md5": candidate.md5,
            "updated_rows": updated_rows,
            "elapsed_seconds": round(time.monotonic() - started, 2),
            "dart_version": fields.get("flutter_dart_version"),
            "backend_version": fields.get("flutter_blutter_backend_version"),
            "primary_package": fields.get("flutter_primary_package"),
            "library_uri_count": len(library_uris),
            "primary_class_count": len(fields.get("flutter_primary_package_classes") or []),
            "remote_url_count": len(fields.get("flutter_remote_service_urls") or []),
            "remote_domain_count": len(fields.get("flutter_remote_service_domains") or []),
        }
    except Exception as exc:
        return {
            "status": "failed",
            "md5": candidate.md5,
            "updated_rows": 0,
            "elapsed_seconds": round(time.monotonic() - started, 2),
            "error": f"{type(exc).__name__}: {exc}"[:1000],
        }
    finally:
        _cleanup_download(local_path)
        shutil.rmtree(
            Path(settings.FLUTTER_BLUTTER_OUTPUT_ROOT) / candidate.md5,
            ignore_errors=True,
        )


def _run_framework(
    framework: str,
    *,
    workers: int,
    limit: int | None,
    target_md5s: set[str] | None,
) -> dict[str, int]:
    candidates = _load_candidates(framework, limit, target_md5s)
    _emit("framework_start", framework=framework, candidates=len(candidates), workers=workers)
    stats = {"total": len(candidates), "success": 0, "failed": 0, "updated_rows": 0}
    processor = _process_dcloud if framework == DCLOUD_FRAMEWORK else _process_flutter
    executor_type = ThreadPoolExecutor if framework == DCLOUD_FRAMEWORK else ProcessPoolExecutor

    with executor_type(max_workers=max(1, workers)) as executor:
        futures = {executor.submit(processor, candidate): candidate for candidate in candidates}
        for completed, future in enumerate(as_completed(futures), start=1):
            result = future.result()
            stats[result["status"]] += 1
            stats["updated_rows"] += int(result.get("updated_rows") or 0)
            _emit(
                "item_complete",
                framework=framework,
                completed=completed,
                total=len(candidates),
                **result,
            )

    _emit("framework_complete", framework=framework, **stats)
    return stats


def main() -> int:
    parser = argparse.ArgumentParser(description="回填 DCloud 和 Flutter 静态框架特征")
    parser.add_argument(
        "--framework",
        choices=("dcloud", "flutter", "both"),
        default="both",
    )
    parser.add_argument("--limit", type=int)
    parser.add_argument("--md5-file", type=Path)
    parser.add_argument("--dcloud-workers", type=int, default=12)
    parser.add_argument("--flutter-workers", type=int, default=6)
    args = parser.parse_args()
    target_md5s: set[str] | None = None
    if args.md5_file is not None:
        target_md5s = {
            value
            for line in args.md5_file.read_text(encoding="utf-8").splitlines()
            if (value := line.strip().lower()) and re.fullmatch(r"[0-9a-f]{32}", value)
        }
        if not target_md5s:
            parser.error("--md5-file 中没有有效的 MD5")

    started = time.monotonic()
    summary: dict[str, dict[str, int]] = {}
    if args.framework in ("dcloud", "both"):
        summary["dcloud"] = _run_framework(
            DCLOUD_FRAMEWORK,
            workers=args.dcloud_workers,
            limit=args.limit,
            target_md5s=target_md5s,
        )
    if args.framework in ("flutter", "both"):
        summary["flutter"] = _run_framework(
            FLUTTER_FRAMEWORK,
            workers=args.flutter_workers,
            limit=args.limit,
            target_md5s=target_md5s,
        )
    _emit(
        "backfill_complete",
        elapsed_seconds=round(time.monotonic() - started, 2),
        summary=summary,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
