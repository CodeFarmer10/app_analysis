from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from androguard.core.apk import APK

try:
    from loguru import logger as loguru_logger

    loguru_logger.disable("androguard")
except Exception:  # pragma: no cover - optional runtime dependency behavior
    pass


ANDROID_DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.BODY_SENSORS",
    "android.permission.BODY_SENSORS_BACKGROUND",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_MEDIA_LOCATION",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.ACCEPT_HANDOVER",
    "android.permission.READ_CELL_BROADCASTS",
}


def _pick_certificate_der(apk: APK) -> bytes | None:
    for getter_name in ("get_certificates_der_v3", "get_certificates_der_v2"):
        getter = getattr(apk, getter_name, None)
        if getter is None:
            continue
        try:
            certs = getter() or []
        except Exception:
            certs = []
        for cert in certs:
            if isinstance(cert, (bytes, bytearray)) and cert:
                return bytes(cert)
    return None


def _build_permissions(permission_names: list[str]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    normalized: list[dict[str, Any]] = []

    for permission in permission_names:
        if not permission or permission in seen:
            continue
        seen.add(permission)
        normalized.append(
            {
                "name": permission,
                "is_dangerous": permission in ANDROID_DANGEROUS_PERMISSIONS,
            }
        )
    return normalized


def _build_activities(activity_names: list[str], launcher_activities: set[str]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    activities: list[dict[str, Any]] = []

    for activity in activity_names:
        if not activity or activity in seen:
            continue
        seen.add(activity)
        activities.append(
            {
                "name": activity,
                "is_launcher": activity in launcher_activities,
            }
        )
    return activities


def _safe_android_version(apk: APK, key: str) -> str | None:
    android_version = getattr(apk, "androidversion", {}) or {}
    value = android_version.get(key)
    if value:
        return str(value)
    return None


def parse_apk(apk_path: str) -> dict[str, Any]:
    path = Path(apk_path)
    if not path.is_file():
        raise FileNotFoundError(f"APK文件不存在: {apk_path}")

    apk = APK(str(path))
    cert_der = _pick_certificate_der(apk)

    app_icon_name = apk.get_app_icon()
    icon_bytes: bytes | None = None
    if app_icon_name:
        try:
            icon_bytes = bytes(apk.get_file(app_icon_name))
        except Exception:
            icon_bytes = None

    permissions = _build_permissions(apk.get_permissions() or [])
    launcher_activities = set(apk.get_main_activities() or set())
    activities = _build_activities(apk.get_activities() or [], launcher_activities)
    services = sorted({item for item in (apk.get_services() or []) if item})
    providers = sorted({item for item in (apk.get_providers() or []) if item})
    so_files = sorted({item for item in apk.get_files() if item.lower().endswith(".so")})
    version_name = _safe_android_version(apk, "Name")
    version_code = _safe_android_version(apk, "Code")

    return {
        "app_name": apk.get_app_name() or None,
        "package_name": apk.get_package() or None,
        "version_name": version_name,
        "version_code": version_code,
        "cert_md5": hashlib.md5(cert_der).hexdigest() if cert_der else None,
        "cert_sha1": hashlib.sha1(cert_der).hexdigest() if cert_der else None,
        "cert_sha256": hashlib.sha256(cert_der).hexdigest() if cert_der else None,
        "permissions": permissions,
        "activities": activities,
        "services": services,
        "providers": providers,
        "so_files": so_files,
        "icon_bytes": icon_bytes,
        "icon_name": app_icon_name or None,
    }
