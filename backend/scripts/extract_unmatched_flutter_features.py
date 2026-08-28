from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from zipfile import ZipFile

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from analyzers.flutter_blutter_runner import run_flutter_blutter  # noqa: E402
from analyzers.flutter_structural_features import extract_flutter_structural_features  # noqa: E402
from analyzers.flutter_analyzer import resolve_flutter_asm_dir  # noqa: E402
from core.config import settings  # noqa: E402
from core.database import fetch_all  # noqa: E402
from services.storage_service import storage_service  # noqa: E402


@dataclass
class Candidate:
    md5: str
    apk_path: str
    task_ids: list[str]


def _emit(event: str, **fields: Any) -> None:
    print(
        json.dumps(
            {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "event": event, **fields},
            ensure_ascii=False,
        ),
        flush=True,
    )


def _load_candidates(limit: int | None) -> list[Candidate]:
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
            candidate = Candidate(md5=md5, apk_path=apk_path, task_ids=[])
            grouped[md5] = candidate
        candidate.task_ids.append(str(row["task_id"]))
    return list(grouped.values())


def _md5_file(path: Path) -> str:
    digest = hashlib.md5()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _download_verified(candidate: Candidate) -> Path:
    local_path = Path(storage_service.download_to_temp(candidate.apk_path))
    actual = _md5_file(local_path)
    if actual != candidate.md5:
        _cleanup_path(local_path)
        raise RuntimeError(f"APK MD5 mismatch: expected={candidate.md5} actual={actual}")
    return local_path


def _has_arm64_v8a(apk_path: Path) -> bool:
    with ZipFile(apk_path) as apk:
        names = apk.namelist()
    return "lib/arm64-v8a/libapp.so" in names and "lib/arm64-v8a/libflutter.so" in names


def _cleanup_path(path: Path | None) -> None:
    if path is None:
        return
    try:
        path.unlink(missing_ok=True)
    except IsADirectoryError:
        pass
    if path.parent.exists() and path.parent.name.startswith("fraud_app_"):
        shutil.rmtree(path.parent, ignore_errors=True)


def _extract_candidate(candidate: Candidate, keep_blutter_output: bool) -> dict[str, Any]:
    local_apk: Path | None = None
    generated_output_dir = ""
    started = time.monotonic()
    try:
        asm_dir, _ = resolve_flutter_asm_dir(
            candidate.md5,
            [settings.FLUTTER_BLUTTER_OUTPUT_ROOT],
        )
        if asm_dir is None:
            local_apk = _download_verified(candidate)
            if not _has_arm64_v8a(local_apk):
                return {
                    "md5": candidate.md5,
                    "task_ids": candidate.task_ids,
                    "status": "skipped",
                    "reason": "missing arm64-v8a libapp.so/libflutter.so",
                }
            run_result = run_flutter_blutter(
                str(local_apk),
                candidate.md5,
                tool_root=settings.FLUTTER_BLUTTER_TOOL_ROOT,
                output_root=settings.FLUTTER_BLUTTER_OUTPUT_ROOT,
                timeout_seconds=settings.FLUTTER_BLUTTER_TIMEOUT_SECONDS,
                build_docker_image=settings.FLUTTER_BLUTTER_BUILD_DOCKER_IMAGE,
            )
            generated_output_dir = run_result.output_dir
            if run_result.asm_dir:
                asm_dir = Path(run_result.asm_dir)
            if asm_dir is None or not asm_dir.is_dir():
                raise RuntimeError(run_result.error or "Blutter did not produce asm output")

        classes = extract_flutter_structural_features(asm_dir)
        return {
            "md5": candidate.md5,
            "task_ids": candidate.task_ids,
            "status": "success",
            "class_count": len(classes),
            "function_count": sum(len(item["functions"]) for item in classes),
            "features": classes,
            "elapsed_seconds": round(time.monotonic() - started, 2),
        }
    except Exception as exc:
        return {
            "md5": candidate.md5,
            "task_ids": candidate.task_ids,
            "status": "failed",
            "error": f"{type(exc).__name__}: {exc}"[:1000],
            "elapsed_seconds": round(time.monotonic() - started, 2),
        }
    finally:
        _cleanup_path(local_apk)
        if generated_output_dir and not keep_blutter_output:
            shutil.rmtree(generated_output_dir, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract Flutter ClassStringSet + Function(AOT_FP, StringSet) features for unmatched Flutter apps."
    )
    parser.add_argument("--limit", type=int)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(tempfile.gettempdir()) / "unmatched_flutter_structural_features.jsonl",
    )
    parser.add_argument("--keep-blutter-output", action="store_true")
    parser.add_argument("--workers", type=int, default=1)
    args = parser.parse_args()

    candidates = _load_candidates(args.limit)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    _emit("start", candidates=len(candidates), output=str(args.output))

    stats = {"success": 0, "failed": 0, "skipped": 0}
    with args.output.open("w", encoding="utf-8") as output:
        workers = max(1, args.workers)
        if workers == 1:
            iterator = (
                (index, candidate, _extract_candidate(candidate, args.keep_blutter_output))
                for index, candidate in enumerate(candidates, start=1)
            )
        else:
            executor = ProcessPoolExecutor(max_workers=workers)
            futures = {
                executor.submit(_extract_candidate, candidate, args.keep_blutter_output): candidate
                for candidate in candidates
            }
            iterator = (
                (index, futures[future], future.result())
                for index, future in enumerate(as_completed(futures), start=1)
            )
        try:
            for index, candidate, result in iterator:
                status = str(result.get("status") or "failed")
                if status in stats:
                    stats[status] += 1
                output.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")) + "\n")
                output.flush()
                _emit("item", index=index, total=len(candidates), md5=candidate.md5, status=status)
        finally:
            if "executor" in locals():
                executor.shutdown(cancel_futures=True)

    _emit("complete", **stats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
