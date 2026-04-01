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
    get_dynamic_result_by_seq,
    get_dynamic_results,
    get_static_result,
    get_task_by_id,
    get_task_by_md5,
    get_traffic_logs_by_dynamic_result_ids,
    get_traffic_logs_by_seqs,
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
DOWNLOAD_FIELD_MAP = {
    "apk": "apk_path",
    "report": "report_path",
    "pcap": "pcap_path",
}
APK_MIME_TYPES = {
    "application/vnd.android.package-archive",
    "application/zip",
    "application/x-zip",
    "application/x-zip-compressed",
    "application/java-archive",
    "application/x-java-archive",
    "application/jar",
    "application/x-jar",
}


def _is_valid_url(url: str) -> bool:
    parsed = urlparse(url.strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _is_apk_mime(mime_type: str, file_name: str) -> bool:
    normalized_mime = (mime_type or "").lower()
    normalized_name = (file_name or "").lower()
    if normalized_mime == "application/vnd.android.package-archive":
        return True
    if normalized_mime in APK_MIME_TYPES:
        return normalized_name.endswith(".apk")
    if normalized_mime == "application/octet-stream":
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

    enriched_items: list[dict[str, Any]] = []
    for item in items:
        row = dict(item)
        icon_path = row.pop("icon_path", None)
        row["can_download_apk"] = bool(row.pop("apk_path", None))
        row["can_download_report"] = bool(row.pop("report_path", None))
        row["can_download_pcap"] = bool(row.pop("pcap_path", None))
        row["icon_url"] = None
        if icon_path:
            try:
                row["icon_url"] = storage_service.get_presigned_url(icon_path)
            except Exception as exc:  # pragma: no cover - depends on storage runtime
                logger.warning(
                    "build task list icon url failed task_id=%s: %s",
                    row.get("id"),
                    exc,
                )
        enriched_items.append(row)

    return enriched_items, total, normalized_page, normalized_size


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


def get_task_static_result(task_id: str) -> dict[str, Any]:
    task = get_task_by_id(task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="任务不存在",
        )

    static_result = get_static_result(task_id)
    if not static_result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="静态分析结果不存在",
        )

    icon_path = static_result.get("icon_path")
    icon_url = None
    if icon_path:
        try:
            icon_url = storage_service.get_presigned_url(icon_path)
        except Exception as exc:  # pragma: no cover - depends on storage runtime
            logger.warning("build icon url failed for task_id=%s: %s", task_id, exc)

    return {
        "task_id": task_id,
        "status": task["status"],
        "static_result": {
            **static_result,
            "icon_url": icon_url,
        },
    }


def get_task_dynamic_result(
    task_id: str,
    dynamic_page: int,
    dynamic_size: int,
) -> dict[str, Any]:
    task = get_task_by_id(task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="任务不存在",
        )

    normalized_dynamic_page = max(dynamic_page, 1)
    normalized_dynamic_size = min(max(dynamic_size, 1), 200)

    dynamic_items, dynamic_total = get_dynamic_results(
        task_id,
        normalized_dynamic_page,
        normalized_dynamic_size,
    )
    dynamic_id_to_seq: dict[str, int] = {}
    dynamic_seqs: list[int] = []
    for item in dynamic_items:
        dynamic_id = str(item.get("id") or "").strip()
        seq_value = item.get("seq")
        try:
            seq_num = int(seq_value)
        except (TypeError, ValueError):
            continue
        if seq_num > 0:
            if dynamic_id:
                dynamic_id_to_seq[dynamic_id] = seq_num
            dynamic_seqs.append(seq_num)

    step_traffic_items = get_traffic_logs_by_dynamic_result_ids(task_id, list(dynamic_id_to_seq.keys()))
    seq_fallback_items = get_traffic_logs_by_seqs(task_id, dynamic_seqs)

    step_traffic_logs: dict[int, list[dict]] = {}
    for packet in step_traffic_items:
        dynamic_result_id = str(packet.get("dynamic_result_id") or "").strip()
        seq_value = dynamic_id_to_seq.get(dynamic_result_id)
        if seq_value is None:
            continue
        step_traffic_logs.setdefault(seq_value, []).append(packet)

    for packet in seq_fallback_items:
        dynamic_result_id = str(packet.get("dynamic_result_id") or "").strip()
        if dynamic_result_id and dynamic_result_id in dynamic_id_to_seq:
            continue
        seq_value = packet.get("seq")
        try:
            seq_num = int(seq_value)
        except (TypeError, ValueError):
            continue
        if seq_num <= 0:
            continue
        step_traffic_logs.setdefault(seq_num, []).append(packet)

    for item in dynamic_items:
        before_path = item.get("screenshot_before")
        after_path = item.get("screenshot_after")
        try:
            item["screenshot_before_url"] = (
                storage_service.get_presigned_url(before_path) if before_path else None
            )
        except Exception as exc:  # pragma: no cover - depends on storage runtime
            logger.warning("build screenshot_before url failed task_id=%s seq=%s: %s", task_id, item.get("seq"), exc)
            item["screenshot_before_url"] = None
        try:
            item["screenshot_after_url"] = (
                storage_service.get_presigned_url(after_path) if after_path else None
            )
        except Exception as exc:  # pragma: no cover - depends on storage runtime
            logger.warning("build screenshot_after url failed task_id=%s seq=%s: %s", task_id, item.get("seq"), exc)
            item["screenshot_after_url"] = None

    return {
        "task_id": task_id,
        "status": task["status"],
        "dynamic_results": {
            "items": dynamic_items,
            "total": dynamic_total,
            "page": normalized_dynamic_page,
            "size": normalized_dynamic_size,
        },
        "step_traffic_logs": step_traffic_logs,
    }


def get_task_screenshot_redirect_url(task_id: str, seq: int) -> str:
    task = get_task_by_id(task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="任务不存在",
        )

    row = get_dynamic_result_by_seq(task_id, seq)
    if not row:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="动态步骤不存在",
        )

    screenshot_path = row.get("screenshot_after") or row.get("screenshot_before")
    if not screenshot_path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="截图不存在",
        )
    try:
        return storage_service.get_presigned_url(screenshot_path)
    except Exception as exc:  # pragma: no cover - depends on storage runtime
        logger.warning("build screenshot redirect url failed task_id=%s seq=%s: %s", task_id, seq, exc)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="截图不存在",
        ) from exc


def get_task_file_download_url(task_id: str, file_type: str) -> dict[str, Any]:
    task = get_task_by_id(task_id)
    if not task:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="任务不存在",
        )

    target_type = file_type.strip().lower()
    field_name = DOWNLOAD_FIELD_MAP.get(target_type)
    if not field_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="不支持的文件类型",
        )

    object_path = task.get(field_name)
    if not object_path:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{target_type.upper()}文件不存在",
        )

    try:
        download_url = storage_service.get_presigned_url(object_path)
    except Exception as exc:  # pragma: no cover - depends on storage runtime
        logger.warning("build %s download url failed task_id=%s: %s", target_type, task_id, exc)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{target_type.upper()}文件不存在",
        ) from exc

    return {
        "task_id": task_id,
        "file_type": target_type,
        "file_path": object_path,
        "download_url": download_url,
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
