from __future__ import annotations

import hashlib
import logging
import mimetypes
import os
import tempfile
from datetime import datetime
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import HTTPException, UploadFile, status
try:
    import magic
except ImportError:  # pragma: no cover - depends on runtime system library
    magic = None

from repositories.task_repo import (
    create_task,
    get_static_result,
    get_task_by_id,
    get_task_by_md5,
    list_dynamic_results,
    list_tasks,
    list_traffic_logs,
    update_task,
)
from services.storage_service import storage_service
from workers.download import download_apk
from workers.static_analysis import analyze_apk


logger = logging.getLogger(__name__)

MAX_APK_SIZE = 500 * 1024 * 1024
STATIC_READY_STATUSES = {"waiting_device", "dynamic_tracing", "dynamic_failed", "completed"}
DYNAMIC_READY_STATUSES = {"dynamic_tracing", "dynamic_failed", "completed"}


def _is_valid_url(url: str) -> bool:
    parsed = urlparse(url.strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _is_apk_mime(mime_type: str, file_name: str) -> bool:
    normalized_name = (file_name or "").lower()
    if mime_type == "application/vnd.android.package-archive":
        return True
    if mime_type in {"application/zip", "application/java-archive", "application/octet-stream"}:
        return normalized_name.endswith(".apk")
    return False


def _detect_mime(sniff_bytes: bytes, file_name: str) -> str:
    if magic is not None:
        return magic.from_buffer(sniff_bytes, mime=True)
    guessed, _ = mimetypes.guess_type(file_name)
    return guessed or "application/octet-stream"


def _read_upload_to_temp(upload: UploadFile) -> tuple[str, str, int, bytes]:
    md5 = hashlib.md5()
    total_size = 0
    sniff_bytes = bytearray()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
        temp_path = tmp.name
        upload.file.seek(0)

        while True:
            chunk = upload.file.read(1024 * 1024)
            if not chunk:
                break
            total_size += len(chunk)
            if total_size > MAX_APK_SIZE:
                tmp.flush()
                os.remove(temp_path)
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"文件大小超过500MB限制: {upload.filename}",
                )
            if len(sniff_bytes) < 8192:
                need = 8192 - len(sniff_bytes)
                sniff_bytes.extend(chunk[:need])
            md5.update(chunk)
            tmp.write(chunk)

    upload.file.seek(0)
    return temp_path, md5.hexdigest(), total_size, bytes(sniff_bytes)


def _dispatch_static_analysis(task_id: str) -> None:
    try:
        analyze_apk.delay(task_id)
    except Exception as exc:
        logger.warning("dispatch static task failed for task_id=%s: %s", task_id, exc)


def _dispatch_download(task_id: str, url: str) -> None:
    try:
        download_apk.delay(task_id, url)
    except Exception as exc:
        logger.warning("dispatch download task failed for task_id=%s: %s", task_id, exc)


def create_upload_tasks(files: list[UploadFile], user_id: str) -> list[dict[str, Any]]:
    if not files:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="至少上传一个文件",
        )

    results: list[dict[str, Any]] = []

    for upload in files:
        temp_path = ""
        filename = upload.filename or "unknown.apk"
        try:
            temp_path, file_md5, file_size, sniff_bytes = _read_upload_to_temp(upload)
            mime_type = _detect_mime(sniff_bytes, filename)
            if not _is_apk_mime(mime_type, filename):
                results.append(
                    {
                        "filename": filename,
                        "success": False,
                        "reason": f"文件不是APK，检测到MIME类型: {mime_type}",
                    }
                )
                continue

            existed = get_task_by_md5(file_md5)
            if existed:
                results.append(
                    {
                        "filename": filename,
                        "success": False,
                        "reason": "检测到重复样本",
                        "duplicate_task_id": existed["id"],
                        "md5": file_md5,
                    }
                )
                continue

            task_id = str(uuid4())
            create_task(
                {
                    "id": task_id,
                    "source_type": "apk_upload",
                    "source_name": filename,
                    "user_id": user_id,
                    "status": "static_analyzing",
                }
            )

            object_path = storage_service.build_task_object_name(task_id, "apk", f"{file_md5}.apk")
            storage_service.upload_file(object_name=object_path, file_path=temp_path)
            update_task(
                task_id,
                {
                    "apk_path": object_path,
                    "file_md5": file_md5,
                    "file_size": file_size,
                    "error_message": None,
                },
            )
            _dispatch_static_analysis(task_id)

            results.append(
                {
                    "filename": filename,
                    "success": True,
                    "task_id": task_id,
                    "md5": file_md5,
                    "file_size": file_size,
                    "status": "static_analyzing",
                }
            )
        except HTTPException as exc:
            results.append(
                {
                    "filename": filename,
                    "success": False,
                    "reason": str(exc.detail),
                }
            )
        except Exception as exc:
            logger.exception("create upload task failed: %s", exc)
            results.append(
                {
                    "filename": filename,
                    "success": False,
                    "reason": "文件处理失败",
                }
            )
        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)

    return results


def create_url_tasks(urls: list[str], user_id: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for url in urls:
        source = url.strip()
        if not _is_valid_url(source):
            results.append(
                {
                    "url": source,
                    "success": False,
                    "reason": "URL格式无效，必须是http/https地址",
                }
            )
            continue

        task_id = str(uuid4())
        create_task(
            {
                "id": task_id,
                "source_type": "url_download",
                "source_name": source,
                "user_id": user_id,
                "status": "downloading",
            }
        )
        _dispatch_download(task_id, source)
        results.append(
            {
                "url": source,
                "success": True,
                "task_id": task_id,
                "status": "downloading",
            }
        )
    return results


def get_task_list(
    filters: dict[str, Any],
    page: int,
    size: int,
) -> tuple[list[dict], int, int, int]:
    normalized_page = max(page, 1)
    normalized_size = min(max(size, 1), 100)

    normalized_filters = {
        "md5": filters.get("md5"),
        "name": filters.get("name"),
        "package": filters.get("package"),
        "status": filters.get("status"),
        "start": filters.get("start"),
        "end": filters.get("end"),
    }
    items, total = list_tasks(normalized_filters, normalized_page, normalized_size)
    return items, total, normalized_page, normalized_size


def get_task_detail(task_id: str) -> dict[str, Any]:
    task = get_task_by_id(task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="任务不存在",
        )

    data: dict[str, Any] = {"task": task}
    status_value = task["status"]

    if status_value in STATIC_READY_STATUSES:
        data["static_result"] = get_static_result(task_id)

    if status_value in DYNAMIC_READY_STATUSES:
        data["dynamic_results"] = list_dynamic_results(task_id)
        data["traffic_logs"] = list_traffic_logs(task_id)

    return data


def get_task_status(task_id: str) -> dict[str, Any]:
    task = get_task_by_id(task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="任务不存在",
        )
    return {
        "id": task["id"],
        "status": task["status"],
        "device_id": task.get("device_id"),
        "error_message": task.get("error_message"),
    }


def parse_datetime_filter(value: str | None, field_name: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} 时间格式无效，需使用 ISO8601 格式",
        ) from exc
