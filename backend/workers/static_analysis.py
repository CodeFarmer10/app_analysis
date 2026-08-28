from __future__ import annotations

import logging
import re
import shutil
from pathlib import Path

import pymysql
from analyzers.apk_parser import parse_apk
from analyzers.dcloud_analyzer import analyze_dcloud_apk
from analyzers.framework_detector import detect_framework
from analyzers.flutter_blutter_runner import run_flutter_blutter
from analyzers.flutter_analyzer import analyze_flutter_asm_dir, missing_flutter_asm_result, resolve_flutter_asm_dir
from analyzers.ioc_extractor import extract_source_iocs
from analyzers.jadx_workspace import open_jadx_workspace
from analyzers.model_matcher import find_first_matching_model
from analyzers.sdk_detector import SdkDetectResult, detect_sdks
from analyzers.source_artifact_scanner import scan_source_artifacts
from protection import detect_protection
from celery import Task
from repositories.task_repo import get_task_by_id, update_task, upsert_static_result
from repositories.model_repo import get_active_models_ordered
from repositories.sdk_repo import replace_sdk_results
from core.config import settings
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


def _detect_protection_fields(local_apk_path: str) -> dict:
    try:
        return detect_protection(local_apk_path).to_static_fields()
    except Exception as exc:  # pragma: no cover - depends on apkid/runtime
        logger.warning("apk protection detect failed path=%s err=%s", local_apk_path, exc)
        return {
            "is_packed": 0,
            "packer_vendor": None,
            "packer_vendors": [],
            "packer_details": [],
            "is_obfuscated": 0,
            "obfuscation_vendor": None,
            "obfuscation_vendors": [],
            "obfuscator_details": [],
            "protection_detect_error": str(exc)[:1000],
        }


def _detect_framework_fields(local_apk_path: str) -> dict:
    try:
        return detect_framework(local_apk_path).to_static_fields()
    except Exception as exc:  # pragma: no cover - depends on APK structure
        logger.warning("apk framework detect failed path=%s err=%s", local_apk_path, exc)
        return {
            "framework_name": None,
            "framework_matches": [],
        }


def _extract_dcloud_fields(local_apk_path: str, framework_name: object, is_obfuscated: bool) -> dict:
    if str(framework_name or "").strip() != "uni-app/DCloud":
        return {}
    try:
        info = analyze_dcloud_apk(local_apk_path).to_static_field()
        return {
            "dcloud_tech_type": info.get("tech_type"),
            "dcloud_appids": info.get("appids"),
            "dcloud_pages": info.get("pages"),
            "dcloud_api_routes": info.get("api_routes"),
            "dcloud_remote_service_urls": info.get("remote_service_urls"),
            "dcloud_remote_service_domains": info.get("remote_service_domains"),
            "dcloud_is_confused": info.get("is_confused"),
        }
    except Exception as exc:  # pragma: no cover - depends on APK structure
        logger.warning("dcloud asset analysis failed path=%s err=%s", local_apk_path, exc)
        return {
            "dcloud_tech_type": "error",
            "dcloud_appids": [],
            "dcloud_pages": [],
            "dcloud_api_routes": [],
            "dcloud_remote_service_urls": [],
            "dcloud_remote_service_domains": [],
            "dcloud_is_confused": bool(is_obfuscated),
        }


def _flutter_asm_roots() -> list[str | Path]:
    return [
        settings.FLUTTER_BLUTTER_ROOT,
        settings.FLUTTER_BLUTTER_OUTPUT_ROOT,
    ]


def _flutter_static_fields(info: dict) -> dict:
    return {
        "flutter_primary_package": info.get("primary_package"),
        "flutter_primary_entry_uri": info.get("primary_entry_uri"),
        "flutter_library_uris": info.get("library_uris"),
        "flutter_primary_package_classes": info.get("primary_package_classes"),
        "flutter_remote_service_urls": info.get("remote_service_urls"),
        "flutter_remote_service_domains": info.get("remote_service_domains"),
        "flutter_primary_remote_service_urls": info.get("primary_remote_service_urls"),
        "flutter_primary_remote_service_domains": info.get("primary_remote_service_domains"),
        "flutter_dart_version": info.get("dart_version"),
        "flutter_blutter_backend_version": info.get("blutter_backend_version"),
    }


def _cleanup_generated_flutter_output(output_dir: str, output_root: str, file_md5: object) -> None:
    if not output_dir:
        return
    candidate = Path(output_dir).resolve()
    root = Path(output_root).expanduser().resolve()
    expected_md5 = str(file_md5 or "").strip().lower()
    shutil.rmtree(candidate, ignore_errors=True)
    if expected_md5 and candidate.parent.parent == root and candidate.parent.name.lower() == expected_md5:
        try:
            candidate.parent.rmdir()
        except OSError:
            pass


def _extract_flutter_fields(local_apk_path: str, file_md5: object, framework_name: object) -> dict:
    if str(framework_name or "").strip() != "Flutter":
        return {}

    roots = _flutter_asm_roots()
    asm_dir, candidates = resolve_flutter_asm_dir(str(file_md5 or ""), roots)
    blutter_fields: dict = {}
    generated_output_dir = ""
    if asm_dir is None and settings.FLUTTER_BLUTTER_ENABLED:
        run_result = run_flutter_blutter(
            local_apk_path,
            str(file_md5 or ""),
            tool_root=settings.FLUTTER_BLUTTER_TOOL_ROOT,
            output_root=settings.FLUTTER_BLUTTER_OUTPUT_ROOT,
            timeout_seconds=settings.FLUTTER_BLUTTER_TIMEOUT_SECONDS,
            build_docker_image=settings.FLUTTER_BLUTTER_BUILD_DOCKER_IMAGE,
        )
        blutter_fields = run_result.to_static_fields()
        generated_output_dir = run_result.output_dir
        if run_result.asm_dir and Path(run_result.asm_dir).is_dir():
            asm_dir = Path(run_result.asm_dir)
        else:
            asm_dir, candidates = resolve_flutter_asm_dir(str(file_md5 or ""), roots)
        if asm_dir is None:
            missing = missing_flutter_asm_result(candidates)
            missing.update(blutter_fields)
            if generated_output_dir:
                _cleanup_generated_flutter_output(
                    generated_output_dir,
                    settings.FLUTTER_BLUTTER_OUTPUT_ROOT,
                    file_md5,
                )
            return _flutter_static_fields(missing)

    if asm_dir is None:
        return _flutter_static_fields(missing_flutter_asm_result(candidates))

    try:
        result = analyze_flutter_asm_dir(asm_dir).to_static_field()
        result.update(blutter_fields)
        return _flutter_static_fields(result)
    except Exception as exc:  # pragma: no cover - depends on blutter output shape
        logger.warning("flutter asm analysis failed md5=%s asm_dir=%s err=%s", file_md5, asm_dir, exc)
        result = {
            "status": "error",
            "asm_dir": str(asm_dir),
            "primary_package": "",
            "primary_entry_uri": "",
            "primary_entry_method": "",
            "primary_entry_confidence": "none",
            "root_widget_class": "",
            "root_widget_library_uri": "",
            "library_uris": [],
            "primary_package_classes": [],
            "class_count": 0,
            "error": str(exc)[:1000],
        }
        result.update(blutter_fields)
        return _flutter_static_fields(result)
    finally:
        if generated_output_dir:
            _cleanup_generated_flutter_output(
                generated_output_dir,
                settings.FLUTTER_BLUTTER_OUTPUT_ROOT,
                file_md5,
            )


def _extract_source_ioc_fields(
    local_apk_path: str,
    *,
    is_packed: bool,
    jadx_sources_dir: str | None = None,
    jadx_enabled: bool = True,
) -> dict:
    try:
        return extract_source_iocs(
            local_apk_path,
            is_packed=is_packed,
            jadx_sources_dir=jadx_sources_dir,
            jadx_enabled=jadx_enabled,
        ).to_static_fields()
    except Exception as exc:  # pragma: no cover - depends on APK/jadx/runtime
        logger.warning("source ioc extract failed path=%s err=%s", local_apk_path, exc)
        return {
            "source_urls": [],
            "source_emails": [],
            "source_phones": [],
        }


def _extract_sdk_result(
    local_apk_path: str,
    *,
    jadx_output_dir: str | None = None,
) -> SdkDetectResult:
    try:
        return detect_sdks(local_apk_path, jadx_output_dir=jadx_output_dir)
    except Exception as exc:  # pragma: no cover - depends on fingerprint/jadx/runtime
        logger.warning("sdk detect failed path=%s err=%s", local_apk_path, exc)
        return SdkDetectResult(findings=[])


def _extract_source_artifact_fields(
    local_apk_path: str,
    *,
    is_packed: bool,
) -> tuple[dict, SdkDetectResult]:
    if is_packed:
        try:
            result = scan_source_artifacts(local_apk_path, is_packed=True)
            return result.iocs.to_static_fields(), result.sdks
        except Exception as exc:  # pragma: no cover - depends on APK structure
            logger.warning("shared packed artifact scan failed path=%s err=%s", local_apk_path, exc)
            return (
                _extract_source_ioc_fields(local_apk_path, is_packed=True),
                _extract_sdk_result(local_apk_path),
            )

    try:
        with open_jadx_workspace(local_apk_path) as workspace:
            result = scan_source_artifacts(
                local_apk_path,
                is_packed=False,
                jadx_output_dir=workspace.output_dir,
                jadx_sources_dir=workspace.sources_dir,
            )
            return result.iocs.to_static_fields(), result.sdks
    except Exception as exc:  # pragma: no cover - depends on jadx/runtime
        logger.warning("shared jadx analysis failed path=%s err=%s", local_apk_path, exc)
        return (
            _extract_source_ioc_fields(
                local_apk_path,
                is_packed=False,
                jadx_enabled=False,
            ),
            _extract_sdk_result(local_apk_path),
        )


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
        protection_fields = _detect_protection_fields(local_apk_path)
        framework_fields = _detect_framework_fields(local_apk_path)
        dcloud_fields = _extract_dcloud_fields(
            local_apk_path,
            framework_fields.get("framework_name"),
            bool(protection_fields.get("is_obfuscated")),
        )
        flutter_fields = _extract_flutter_fields(
            local_apk_path,
            task.get("file_md5"),
            framework_fields.get("framework_name"),
        )
        source_artifact_fields, sdk_result = _extract_source_artifact_fields(
            local_apk_path,
            is_packed=bool(protection_fields.get("is_packed")),
        )
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

        static_result_data = {
            "app_name": app_name,
            "package_name": package_name,
            "version_name": parsed.get("version_name"),
            "version_code": str(parsed.get("version_code")) if parsed.get("version_code") is not None else None,
            "icon_path": icon_path,
            "cert_md5": parsed.get("cert_md5"),
            "cert_sha1": parsed.get("cert_sha1"),
            "cert_sha256": parsed.get("cert_sha256"),
            "code_md5": task.get("file_md5"),
            "cert_info": parsed.get("cert_info"),
            "permissions": parsed.get("permissions") or [],
            "activities": parsed.get("activities") or [],
            "services": parsed.get("services") or [],
            "providers": parsed.get("providers") or [],
            "receivers": parsed.get("receivers") or [],
            "so_libraries": parsed.get("so_files") or [],
            "components": parsed.get("component_string"),
            "component_md5": parsed.get("component_md5"),
            **framework_fields,
            **protection_fields,
            **source_artifact_fields,
            **dcloud_fields,
            **flutter_fields,
        }
        static_result_data.update(
            find_first_matching_model(static_result_data, get_active_models_ordered())
        )

        upsert_static_result(task_id, static_result_data)
        replace_sdk_results(task_id, sdk_result.findings)
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
