from __future__ import annotations

import hashlib
import logging
import mimetypes
from pathlib import Path
from urllib.parse import urlparse

import httpx
from celery import Task
try:
    import magic
except ImportError:  # pragma: no cover - depends on runtime system library
    magic = None

from repositories.task_repo import get_task_by_id, update_task
from services.storage_service import storage_service
from workers.celery_app import celery_app
from workers.static_analysis import analyze_apk


logger = logging.getLogger(__name__)

MAX_APK_SIZE = 500 * 1024 * 1024
DOWNLOAD_TIMEOUT = httpx.Timeout(timeout=120.0, connect=15.0)
NETWORK_EXCEPTIONS = (httpx.TimeoutException, httpx.RequestError)


class DownloadTaskBase(Task):
    autoretry_for = NETWORK_EXCEPTIONS
    retry_backoff = True
    retry_backoff_max = 60
    retry_jitter = True
    retry_kwargs = {"max_retries": 3}

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        _ = task_id, einfo
        task_id_value = kwargs.get("task_id") if kwargs else None
        if task_id_value is None and args:
            task_id_value = args[0]
        if task_id_value:
            update_task(
                str(task_id_value),
                {
                    "status": "download_failed",
                    "error_message": _build_error_message(exc),
                },
            )


def _build_error_message(exc: Exception) -> str:
    text = str(exc).strip()
    return f"下载失败: {text}" if text else "下载失败: 未知错误"


def _is_apk_mime(mime_type: str, file_name: str) -> bool:
    normalized_name = file_name.lower()
    if mime_type == "application/vnd.android.package-archive":
        return True
    if mime_type in {"application/zip", "application/java-archive", "application/octet-stream"}:
        return normalized_name.endswith(".apk")
    return False


def _detect_mime(file_path: Path, file_name: str) -> str:
    if magic is not None:
        return magic.from_file(str(file_path), mime=True)
    guessed, _ = mimetypes.guess_type(file_name)
    return guessed or "application/octet-stream"


def _tmp_dir() -> Path:
    path = Path(__file__).resolve().parents[1] / "tmp"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _safe_filename_from_url(url: str, task_id: str) -> str:
    parsed = urlparse(url)
    name = Path(parsed.path).name
    if not name:
        return f"{task_id}.apk"
    return name


def _download_file(url: str, local_path: Path) -> tuple[str, int]:
    md5 = hashlib.md5()
    total_size = 0
    with httpx.stream("GET", url, timeout=DOWNLOAD_TIMEOUT, follow_redirects=True) as response:
        response.raise_for_status()
        with local_path.open("wb") as file_obj:
            for chunk in response.iter_bytes(chunk_size=1024 * 1024):
                if not chunk:
                    continue
                total_size += len(chunk)
                if total_size > MAX_APK_SIZE:
                    raise ValueError("文件大小超过500MB限制")
                md5.update(chunk)
                file_obj.write(chunk)
    if total_size <= 0:
        raise ValueError("下载文件为空")
    return md5.hexdigest(), total_size


@celery_app.task(
    bind=True,
    base=DownloadTaskBase,
    name="workers.download.download_apk",
)
def download_apk(self, task_id: str, url: str):  # pylint: disable=unused-argument
    task = get_task_by_id(task_id)
    if not task:
        logger.warning("download task ignored: task_id=%s not found", task_id)
        return {"task_id": task_id, "accepted": False, "reason": "task_not_found"}

    temp_file = _tmp_dir() / f"{task_id}_download.apk"
    file_name = _safe_filename_from_url(url, task_id)

    try:
        file_md5, file_size = _download_file(url, temp_file)
        mime_type = _detect_mime(temp_file, file_name)
        if not _is_apk_mime(mime_type, file_name):
            update_task(
                task_id,
                {
                    "status": "download_failed",
                    "error_message": f"下载文件不是APK，检测到MIME类型: {mime_type}",
                },
            )
            return {"task_id": task_id, "status": "download_failed"}

        object_name = storage_service.build_task_object_name(task_id, "apk", f"{file_md5}.apk")
        storage_service.upload_file(object_name=object_name, file_path=str(temp_file))
        object_url = storage_service.build_object_url(object_name)
        update_task(
            task_id,
            {
                "apk_path": object_url,
                "file_md5": file_md5,
                "file_size": file_size,
                "status": "static_analyzing",
                "error_message": None,
            },
        )
        analyze_apk.delay(task_id)
        return {"task_id": task_id, "status": "static_analyzing"}
    except NETWORK_EXCEPTIONS as exc:
        logger.warning("download network error task_id=%s retry=%s err=%s", task_id, self.request.retries, exc)
        raise
    except Exception as exc:  # pragma: no cover - runtime dependent
        logger.exception("download failed task_id=%s", task_id)
        update_task(
            task_id,
            {
                "status": "download_failed",
                "error_message": _build_error_message(exc),
            },
        )
        return {"task_id": task_id, "status": "download_failed"}
    finally:
        if temp_file.exists():
            temp_file.unlink(missing_ok=True)
