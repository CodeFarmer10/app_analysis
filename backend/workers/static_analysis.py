from __future__ import annotations

import logging
import re
import shutil
from pathlib import Path

import pymysql
from analyzers.apk_parser import parse_apk
from celery import Task
from repositories.task_repo import get_task_by_id, update_task, upsert_static_result
from services.storage_service import storage_service
from workers.celery_app import celery_app


logger = logging.getLogger(__name__)
DB_EXCEPTIONS = (pymysql.err.MySQLError,)
APP_NAME_INVISIBLE_CHAR_PATTERN = re.compile(
    r"[\u0000-\u001F\u007F-\u009F\u00AD\u200B\u200E-\u200F\u202A-\u202E\u2060-\u206F\uFEFF\uFFF9-\uFFFB]"
)


def _build_error_message(exc: Exception) -> str:
    text = str(exc).strip()
    return f"静态分析失败: {text}" if text else "静态分析失败: 未知错误"


def _normalize_optional_text(value: object) -> str | None:
    text = str(value or "").strip()
    return text or None


def _normalize_app_name(value: object) -> str | None:
    text = _normalize_optional_text(value)
    if text is None:
        return None
    sanitized = APP_NAME_INVISIBLE_CHAR_PATTERN.sub("", text).strip()
    return sanitized or None


def _guess_icon_extension(icon_name: str | None, icon_bytes: bytes) -> str:
    suffix = Path(icon_name or "").suffix.lower()
    if suffix in {".png", ".jpg", ".jpeg", ".webp", ".gif"}:
        return suffix.lstrip(".")

    guessed = _detect_image_type(icon_bytes)
    if guessed == "jpg":
        return "jpg"
    if guessed:
        return guessed
    return "png"


def _detect_image_type(content: bytes) -> str | None:
    if len(content) >= 8 and content.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if len(content) >= 3 and content[:3] == b"\xff\xd8\xff":
        return "jpg"
    if len(content) >= 6 and content[:6] in {b"GIF87a", b"GIF89a"}:
        return "gif"
    if len(content) >= 12 and content[:4] == b"RIFF" and content[8:12] == b"WEBP":
        return "webp"
    return None


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


class StaticAnalysisTaskBase(Task):
    autoretry_for = DB_EXCEPTIONS
    retry_backoff = True
    retry_backoff_max = 30
    retry_jitter = True
    retry_kwargs = {"max_retries": 3}

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        _ = task_id, einfo
        task_id_value = kwargs.get("task_id") if kwargs else None
        if task_id_value is None and args:
            task_id_value = args[0]
        if task_id_value:
            try:
                update_task(
                    str(task_id_value),
                    {
                        "status": "static_failed",
                        "error_message": _build_error_message(exc),
                    },
                )
            except Exception:  # pragma: no cover - best effort failure fallback
                logger.exception("static analyze failure status update failed task_id=%s", task_id_value)


@celery_app.task(
    bind=True,
    base=StaticAnalysisTaskBase,
    name="workers.static_analysis.analyze_apk",
)
def analyze_apk(self, task_id: str):
    task = get_task_by_id(task_id)
    if not task:
        if self.request.retries < self.max_retries:
            logger.warning("static analyze task missing, retrying task_id=%s retries=%s", task_id, self.request.retries)
            raise self.retry(exc=RuntimeError("静态分析任务不存在，准备重试"), countdown=2)
        raise RuntimeError("静态分析任务不存在")

    apk_object_path = task.get("apk_path")
    if not apk_object_path:
        if self.request.retries < self.max_retries:
            logger.warning("static analyze apk path missing, retrying task_id=%s retries=%s", task_id, self.request.retries)
            raise self.retry(exc=RuntimeError("静态分析任务缺少APK存储路径，准备重试"), countdown=2)
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
        app_name = _normalize_app_name(parsed.get("app_name"))
        package_name = _normalize_optional_text(parsed.get("package_name"))
        if not app_name and not package_name:
            raise ValueError("静态结果缺少应用名称和包名")

        icon_path = None
        icon_bytes = parsed.get("icon_bytes")
        if isinstance(icon_bytes, (bytes, bytearray)) and icon_bytes:
            try:
                extension = _guess_icon_extension(parsed.get("icon_name"), bytes(icon_bytes))
                icon_file_name = f"{task_id}.{extension}"
                icon_path = storage_service.upload_task_bytes(
                    task_id=task_id,
                    file_type="icon",
                    file_name=icon_file_name,
                    data=bytes(icon_bytes),
                    content_type=_guess_icon_content_type(extension),
                )
            except Exception as icon_exc:  # pragma: no cover - runtime/storage dependent
                logger.warning("icon upload failed task_id=%s: %s", task_id, icon_exc)
                icon_path = None

        upsert_static_result(
            task_id,
            {
                "app_name": app_name,
                "package_name": package_name,
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
                "component_string": parsed.get("component_string"),
                "component_md5": parsed.get("component_md5"),
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
    except DB_EXCEPTIONS:
        raise
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
