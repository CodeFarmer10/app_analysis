from __future__ import annotations

import imghdr
import logging
import shutil
from pathlib import Path

from analyzers.apk_parser import parse_apk
from repositories.task_repo import get_task_by_id, update_task, upsert_static_result
from services.storage_service import storage_service
from workers.celery_app import celery_app


logger = logging.getLogger(__name__)


def _build_error_message(exc: Exception) -> str:
    text = str(exc).strip()
    return f"静态分析失败: {text}" if text else "静态分析失败: 未知错误"


def _guess_icon_extension(icon_name: str | None, icon_bytes: bytes) -> str:
    suffix = Path(icon_name or "").suffix.lower()
    if suffix in {".png", ".jpg", ".jpeg", ".webp", ".gif"}:
        return suffix.lstrip(".")

    guessed = imghdr.what(None, h=icon_bytes)
    if guessed == "jpeg":
        return "jpg"
    if guessed:
        return guessed
    return "png"


def _guess_icon_content_type(extension: str) -> str:
    if extension == "jpg":
        return "image/jpeg"
    if extension == "png":
        return "image/png"
    if extension == "gif":
        return "image/gif"
    if extension == "webp":
        return "image/webp"
    return "application/octet-stream"


@celery_app.task(name="workers.static_analysis.analyze_apk")
def analyze_apk(task_id: str):
    task = get_task_by_id(task_id)
    if not task:
        logger.warning("static analyze ignored: task_id=%s not found", task_id)
        return {"task_id": task_id, "accepted": False, "reason": "task_not_found"}

    apk_object_path = task.get("apk_path")
    if not apk_object_path:
        update_task(
            task_id,
            {
                "status": "static_failed",
                "error_message": "静态分析失败: 任务缺少APK存储路径",
            },
        )
        return {"task_id": task_id, "status": "static_failed"}

    local_apk_path = ""
    try:
        local_apk_path = storage_service.download_to_temp(apk_object_path)
        parsed = parse_apk(local_apk_path)

        icon_path = None
        icon_bytes = parsed.get("icon_bytes")
        if isinstance(icon_bytes, (bytes, bytearray)) and icon_bytes:
            extension = _guess_icon_extension(parsed.get("icon_name"), bytes(icon_bytes))
            icon_file_name = f"{task_id}.{extension}"
            icon_path = storage_service.upload_task_bytes(
                task_id=task_id,
                file_type="icon",
                file_name=icon_file_name,
                data=bytes(icon_bytes),
                content_type=_guess_icon_content_type(extension),
            )

        upsert_static_result(
            task_id,
            {
                "app_name": parsed.get("app_name"),
                "package_name": parsed.get("package_name"),
                "version_name": parsed.get("version_name"),
                "version_code": str(parsed.get("version_code")) if parsed.get("version_code") is not None else None,
                "icon_path": icon_path,
                "cert_md5": parsed.get("cert_md5"),
                "cert_sha1": parsed.get("cert_sha1"),
                "cert_sha256": parsed.get("cert_sha256"),
                "permissions": parsed.get("permissions") or [],
                "activities": parsed.get("activities") or [],
                "services": parsed.get("services") or [],
                "providers": parsed.get("providers") or [],
                "so_files": parsed.get("so_files") or [],
            },
        )
        update_task(
            task_id,
            {
                "status": "waiting_device",
                "error_message": None,
            },
        )
        return {"task_id": task_id, "status": "waiting_device"}
    except Exception as exc:  # pragma: no cover - depends on APK and runtime
        logger.exception("static analyze failed task_id=%s", task_id)
        update_task(
            task_id,
            {
                "status": "static_failed",
                "error_message": _build_error_message(exc),
            },
        )
        return {"task_id": task_id, "status": "static_failed"}
    finally:
        if local_apk_path:
            local_path = Path(local_apk_path)
            if local_path.exists():
                local_path.unlink(missing_ok=True)
            if local_path.parent.exists():
                shutil.rmtree(local_path.parent, ignore_errors=True)
