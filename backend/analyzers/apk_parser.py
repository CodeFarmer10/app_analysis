from __future__ import annotations

import hashlib
import logging
import re
import shutil
import subprocess
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from androguard.core.apk import APK
try:
    from apkInspector.axml import parse_apk_for_manifest
except Exception:  # pragma: no cover - optional runtime dependency behavior
    parse_apk_for_manifest = None

try:
    from loguru import logger as loguru_logger

    loguru_logger.disable("androguard")
except Exception:  # pragma: no cover - optional runtime dependency behavior
    pass

logger = logging.getLogger(__name__)


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

    getter_v1 = getattr(apk, "get_certificates_v1", None)
    if getter_v1 is not None:
        try:
            certs_v1 = getter_v1() or []
        except Exception:
            certs_v1 = []
        for cert in certs_v1:
            if cert is None:
                continue
            dump = getattr(cert, "dump", None)
            if callable(dump):
                try:
                    cert_der = dump()
                except Exception:
                    cert_der = None
                if isinstance(cert_der, (bytes, bytearray)) and cert_der:
                    return bytes(cert_der)
    return None


# X.509 DN 属性短名映射，用于将 subject/issuer 拼成 "CN=..., OU=..., O=..." 形态。
_DN_SHORT_NAMES = {
    "common_name": "CN",
    "organizational_unit_name": "OU",
    "organization_name": "O",
    "locality_name": "L",
    "state_or_province_name": "ST",
    "country_name": "C",
    "email_address": "E",
    "serial_number": "SERIALNUMBER",
    "domain_component": "DC",
    "organization_identifier": "OID",
}


def _format_distinguished_name(name: Any) -> str | None:
    try:
        native = name.native or {}
    except Exception:
        return None
    parts: list[str] = []
    for key, value in native.items():
        short = _DN_SHORT_NAMES.get(key, key)
        if isinstance(value, (list, tuple)):
            value = ", ".join(str(item) for item in value)
        parts.append(f"{short}={value}")
    return ", ".join(parts) or None


def _build_certificate_entry(cert: Any) -> dict[str, Any]:
    """从 asn1crypto x509.Certificate 解析出图片所示的全部证书字段。"""
    der = cert.dump()
    validity = cert["tbs_certificate"]["validity"]
    public_key = cert.public_key

    def _safe(getter: Any, default: Any = None) -> Any:
        try:
            return getter()
        except Exception:
            return default

    return {
        "subject": _safe(lambda: _format_distinguished_name(cert.subject)),
        "issuer": _safe(lambda: _format_distinguished_name(cert.issuer)),
        "signature_algorithm": _safe(lambda: cert["signature_algorithm"].signature_algo),
        "hash_algorithm": _safe(lambda: cert["signature_algorithm"].hash_algo),
        "serial_number": _safe(lambda: hex(cert.serial_number)),
        "not_before": _safe(lambda: str(validity["not_before"].native)),
        "not_after": _safe(lambda: str(validity["not_after"].native)),
        "md5": hashlib.md5(der).hexdigest(),
        "sha1": hashlib.sha1(der).hexdigest(),
        "sha256": hashlib.sha256(der).hexdigest(),
        "sha512": hashlib.sha512(der).hexdigest(),
        "public_key_algorithm": _safe(lambda: str(public_key.algorithm).upper()),
        "public_key_bits": _safe(lambda: public_key.bit_size),
        "public_key_fingerprint": _safe(lambda: public_key.sha256.hex()),
    }


def _build_certificate_info(apk: APK) -> dict[str, Any] | None:
    """组装完整证书信息：签名状态、签名方案版本、各证书详情。"""
    try:
        certs = apk.get_certificates() or []
    except Exception:
        certs = []
    entries: list[dict[str, Any]] = []
    for cert in certs:
        try:
            entries.append(_build_certificate_entry(cert))
        except Exception as exc:  # pragma: no cover - depends on cert structure
            logger.warning("certificate entry parse failed: %s", exc)
    if not entries:
        return None

    def _safe_flag(method_name: str) -> bool:
        method = getattr(apk, method_name, None)
        if not callable(method):
            return False
        try:
            return bool(method())
        except Exception:
            return False

    return {
        "is_signed": _safe_flag("is_signed"),
        "cert_count": len(entries),
        "schemes": {
            "v1": _safe_flag("is_signed_v1"),
            "v2": _safe_flag("is_signed_v2"),
            "v3": _safe_flag("is_signed_v3"),
            # androguard 无法仅凭 APK 判定 v4（v4 签名存于独立的 .idsig 文件）
            "v4": False,
        },
        "certificates": entries,
    }


def _extract_certificate_digests(apk_path: str | None = None, apk: APK | None = None) -> dict[str, Any]:
    effective_apk = apk or APK(str(apk_path))
    cert_der = _pick_certificate_der(effective_apk)
    try:
        cert_info = _build_certificate_info(effective_apk)
    except Exception as exc:  # pragma: no cover - depends on cert structure
        logger.warning("certificate info parse failed: %s", exc)
        cert_info = None
    return {
        "cert_md5": hashlib.md5(cert_der).hexdigest() if cert_der else None,
        "cert_sha1": hashlib.sha1(cert_der).hexdigest() if cert_der else None,
        "cert_sha256": hashlib.sha256(cert_der).hexdigest() if cert_der else None,
        "cert_info": cert_info,
    }


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


def _safe_call(func, default=None):
    try:
        return func()
    except Exception:
        return default


def _detect_build_tool(tool_name: str) -> str | None:
    found = shutil.which(tool_name)
    if found:
        return found

    root_dir = Path(__file__).resolve().parents[2]
    build_tools_dir = root_dir / "tools" / "android-sdk" / "build-tools"
    if build_tools_dir.is_dir():
        for version_dir in sorted(build_tools_dir.iterdir(), reverse=True):
            candidate = version_dir / tool_name
            if candidate.is_file():
                return str(candidate)
    return None


def _run_tool(cmd: list[str]) -> str:
    completed = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"命令执行失败: {' '.join(cmd)}: {completed.stderr.strip()}")
    return completed.stdout or ""


def _default_result() -> dict[str, Any]:
    return {
        "app_name": None,
        "package_name": None,
        "version_name": None,
        "version_code": None,
        "cert_md5": None,
        "cert_sha1": None,
        "cert_sha256": None,
        "cert_info": None,
        "permissions": [],
        "activities": [],
        "services": [],
        "providers": [],
        "so_files": [],
        "icon_bytes": None,
        "icon_name": None,
        "component_string": None,
        "component_md5": None,
        "_receivers": [],
        "_libraries": [],
        "_features": [],
        "_declared_permissions": [],
    }


def _is_image_bytes(data: bytes | None) -> bool:
    if not data:
        return False
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return True
    if data.startswith(b"\xff\xd8\xff"):
        return True
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return True
    if data[:6] in {b"GIF87a", b"GIF89a"}:
        return True
    return False


def _normalize_zip_entry(entry: str | None) -> str | None:
    normalized = str(entry or "").strip()
    if not normalized:
        return None
    return normalized.lstrip("/")


def _extract_zip_entry_bytes(apk_path: str, entry: str | None) -> bytes | None:
    normalized = _normalize_zip_entry(entry)
    if not normalized:
        return None
    try:
        with zipfile.ZipFile(apk_path) as archive:
            return archive.read(normalized)
    except Exception:
        return None


def _extract_so_files(apk_path: str) -> list[str]:
    try:
        with zipfile.ZipFile(apk_path) as archive:
            return sorted({name for name in archive.namelist() if name.lower().endswith(".so")})
    except Exception:
        return []


def _extract_icon_bytes_with_get_icon_from_apk(apk_path: str, icon_path: str | None) -> tuple[bytes | None, str | None]:
    normalized_icon_path = _normalize_zip_entry(icon_path)
    if not normalized_icon_path:
        return None, None
    icon_bytes = _extract_zip_entry_bytes(apk_path, normalized_icon_path)
    if not _is_image_bytes(icon_bytes):
        return None, None
    return icon_bytes, normalized_icon_path


def _extract_icon_resource_ids_from_xmltree(xmltree_output: str) -> list[str]:
    matches = re.findall(r":icon\([^)]+\)=@(0x[0-9a-fA-F]+)", xmltree_output)
    deduped: list[str] = []
    seen: set[str] = set()
    for match in matches:
        normalized = match.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(normalized)
    return deduped


def _parse_badging_output(output: str) -> dict[str, Any]:
    info: dict[str, Any] = {}

    package_match = re.search(
        r"package:\s+name='([^']*)'(?:\s+versionCode='([^']*)')?(?:\s+versionName='([^']*)')?",
        output,
    )
    if package_match:
        info["package_name"] = package_match.group(1) or None
        info["version_code"] = package_match.group(2) or None
        info["version_name"] = package_match.group(3) or None

    label_match = re.search(r"application-label(?:-[^:]+)?:'([^']*)'", output)
    if label_match:
        info["app_name"] = label_match.group(1) or None

    icon_candidates: list[tuple[int, str]] = []
    for density, icon_path in re.findall(r"application-icon-(\d+):'([^']+)'", output):
        try:
            density_value = int(density)
        except Exception:
            density_value = 0
        icon_candidates.append((density_value, icon_path))
    if icon_candidates:
        icon_candidates.sort(key=lambda item: item[0], reverse=True)
        info["icon_name"] = icon_candidates[0][1]
    else:
        icon_match = re.search(r"\bicon='([^']+)'", output)
        if icon_match:
            info["icon_name"] = icon_match.group(1)

    permission_names = re.findall(r"uses-permission:\s+name='([^']+)'", output)
    if permission_names:
        info["permission_names"] = permission_names
    return info


def _collect_block(lines: list[str], start_index: int) -> tuple[list[str], int]:
    start_line = lines[start_index]
    start_indent = len(start_line) - len(start_line.lstrip(" "))
    block_lines: list[str] = []
    index = start_index + 1
    while index < len(lines):
        line = lines[index]
        if re.match(r"^\s*E:\s+", line):
            indent = len(line) - len(line.lstrip(" "))
            if indent <= start_indent:
                break
        block_lines.append(line)
        index += 1
    return block_lines, index


def _extract_android_attr(block_lines: list[str], attr_name: str) -> str | None:
    namespace_pattern = r"(?:android:|http://schemas\.android\.com/apk/res/android:)"
    quoted_pattern = re.compile(rf"{namespace_pattern}{re.escape(attr_name)}\([^)]+\)=\"([^\"]+)\"")
    bool_pattern = re.compile(rf"{namespace_pattern}{re.escape(attr_name)}\([^)]+\)=([^\s]+)")
    for line in block_lines:
        quoted_match = quoted_pattern.search(line)
        if quoted_match:
            value = quoted_match.group(1).strip()
            if value:
                return value
        bool_match = bool_pattern.search(line)
        if bool_match:
            value = bool_match.group(1).strip()
            if value and value != "false":
                return value
    return None


def _parse_manifest_xmltree(xmltree_output: str) -> dict[str, Any]:
    lines = xmltree_output.splitlines()
    permission_names: list[str] = []
    activity_names: list[str] = []
    launcher_activities: set[str] = set()
    service_names: list[str] = []
    provider_names: list[str] = []
    receiver_names: list[str] = []
    library_names: list[str] = []
    feature_names: list[str] = []
    declared_permission_names: list[str] = []

    index = 0
    while index < len(lines):
        line = lines[index]
        element_match = re.match(r"^\s*E:\s+([^\s]+)", line)
        if not element_match:
            index += 1
            continue

        tag = element_match.group(1)
        relevant = (
            tag.startswith("uses-permission")
            or tag in {"activity", "activity-alias", "service", "provider", "receiver", "uses-library", "uses-feature", "permission"}
        )
        if not relevant:
            index += 1
            continue

        block_lines, next_index = _collect_block(lines, index)
        name = _extract_android_attr(block_lines, "name")

        if tag.startswith("uses-permission"):
            if name:
                permission_names.append(name)
        elif tag in {"activity", "activity-alias"}:
            if name:
                activity_names.append(name)
                block_text = "\n".join(block_lines)
                if "android.intent.action.MAIN" in block_text and "android.intent.category.LAUNCHER" in block_text:
                    launcher_activities.add(name)
        elif tag == "service":
            if name:
                service_names.append(name)
        elif tag == "provider":
            if name:
                provider_names.append(name)
        elif tag == "receiver":
            if name:
                receiver_names.append(name)
        elif tag == "uses-library":
            if name:
                library_names.append(name)
        elif tag == "uses-feature":
            if name:
                feature_names.append(name)
        elif tag == "permission":
            if name:
                declared_permission_names.append(name)

        index = next_index

    return {
        "permission_names": permission_names,
        "activity_names": activity_names,
        "launcher_activities": launcher_activities,
        "service_names": service_names,
        "provider_names": provider_names,
        "receiver_names": receiver_names,
        "library_names": library_names,
        "feature_names": feature_names,
        "declared_permission_names": declared_permission_names,
    }


def _extract_drawable_refs_from_xmltree(xmltree_output: str) -> list[str]:
    foreground_refs: list[str] = []
    normal_refs: list[str] = []
    background_refs: list[str] = []
    context = ""
    ref_pattern = re.compile(r"@0x([0-9a-fA-F]{8})")

    for line in xmltree_output.splitlines():
        if "E: foreground" in line:
            context = "foreground"
        elif "E: background" in line:
            context = "background"
        elif re.match(r"^\s*E:\s+", line):
            context = ""

        for match in ref_pattern.finditer(line):
            ref = "0x" + match.group(1).lower()
            if context == "foreground":
                foreground_refs.append(ref)
            elif context == "background":
                background_refs.append(ref)
            else:
                normal_refs.append(ref)

    deduped: list[str] = []
    seen: set[str] = set()
    for ref in [*foreground_refs, *normal_refs, *background_refs]:
        if ref in seen:
            continue
        seen.add(ref)
        deduped.append(ref)
    return deduped


def _density_score(line: str) -> int:
    if "(xxxhdpi)" in line:
        return 5
    if "(xxhdpi)" in line:
        return 4
    if "(xhdpi)" in line:
        return 3
    if "(hdpi)" in line:
        return 2
    if "(mdpi)" in line:
        return 1
    return 0


def _looks_like_resource_entry_path(value: str | None) -> bool:
    normalized = str(value or "").strip().strip("\"'")
    if not normalized:
        return False
    if "/" not in normalized:
        return False
    if normalized.startswith(("@", "#")):
        return False
    return True


def _extract_resource_entry_by_id(resources_output: str, resource_id: str) -> str | None:
    normalized_id = resource_id.lower()
    lines = resources_output.splitlines()
    candidates: list[tuple[int, str]] = []
    in_target = False
    target_indent = 0

    for line in lines:
        resource_match = re.search(r"resource\s+(0x[0-9a-fA-F]+)\b", line)
        if resource_match:
            line_indent = len(line) - len(line.lstrip(" "))
            in_target = resource_match.group(1).lower() == normalized_id
            target_indent = line_indent
            continue

        if not in_target:
            continue

        line_indent = len(line) - len(line.lstrip(" "))
        if re.search(r"\bresource\s+0x[0-9a-fA-F]+\b", line) and line_indent <= target_indent:
            in_target = False
            continue

        path_match = re.search(r"\(file\)\s+([^\s\"']+)", line, flags=re.IGNORECASE)
        if path_match and _looks_like_resource_entry_path(path_match.group(1)):
            candidates.append((_density_score(line), path_match.group(1)))
            continue

        quoted_match = re.search(r'"([^"]+)"', line)
        if quoted_match and _looks_like_resource_entry_path(quoted_match.group(1)):
            candidates.append((_density_score(line), quoted_match.group(1)))
            continue

        string8_match = re.search(r"\(string8\)\s+\"([^\"]+)\"", line, flags=re.IGNORECASE)
        if string8_match and _looks_like_resource_entry_path(string8_match.group(1)):
            candidates.append((_density_score(line), string8_match.group(1)))

    if not candidates:
        return None
    candidates.sort(key=lambda item: item[0], reverse=True)
    return candidates[0][1]


def _extract_resource_entry_from_arsc_output(arsc_output: str) -> str | None:
    path_candidates: list[str] = []
    for line in arsc_output.splitlines():
        value_match = re.search(r"=\s*'([^']+)'", line, flags=re.IGNORECASE)
        if not value_match:
            continue
        if not _looks_like_resource_entry_path(value_match.group(1)):
            continue
        path_candidates.append(line.strip())

    if not path_candidates:
        return None

    chosen = path_candidates[0]
    for candidate in path_candidates:
        if "mdpi =" in candidate or "mdpi-v4 =" in candidate:
            chosen = candidate
            break

    path_match = re.search(r"=\s*'([^']+)'", chosen, flags=re.IGNORECASE)
    if not path_match:
        return None
    if not _looks_like_resource_entry_path(path_match.group(1)):
        return None
    return _normalize_zip_entry(path_match.group(1))


def _resolve_resource_id_with_androguard_arsc(
    apk_path: str,
    resource_id: str,
    *,
    androguard_path: str | None,
) -> str | None:
    if not androguard_path:
        return None

    try:
        arsc_output = _run_tool([androguard_path, "arsc", apk_path, "--id", resource_id])
    except Exception:
        return None
    return _extract_resource_entry_from_arsc_output(arsc_output)


def _resolve_resource_id_to_entry(
    apk_path: str,
    resource_id: str,
    *,
    aapt2_path: str | None,
    androguard_path: str | None = None,
) -> str | None:
    if aapt2_path:
        try:
            aapt2_resources = _run_tool([aapt2_path, "dump", "resources", apk_path])
            from_aapt2 = _extract_resource_entry_by_id(aapt2_resources, resource_id)
            if from_aapt2:
                return from_aapt2
        except Exception:
            pass
    return _resolve_resource_id_with_androguard_arsc(
        apk_path,
        resource_id,
        androguard_path=androguard_path,
    )


def _extract_icon_bytes_from_entry(
    apk_path: str,
    entry: str | None,
    *,
    aapt2_path: str | None,
    androguard_path: str | None = None,
    depth: int = 0,
    visited: set[str] | None = None,
) -> tuple[bytes | None, str | None]:
    normalized_entry = _normalize_zip_entry(entry)
    if not normalized_entry or depth > 3:
        return None, None

    if visited is None:
        visited = set()
    if normalized_entry in visited:
        return None, None
    visited.add(normalized_entry)

    entry_bytes = _extract_zip_entry_bytes(apk_path, normalized_entry)
    if entry_bytes is None:
        return None, None

    if _is_image_bytes(entry_bytes):
        return entry_bytes, normalized_entry

    if not normalized_entry.lower().endswith(".xml") or not aapt2_path:
        return None, None

    try:
        xmltree_output = _run_tool([aapt2_path, "dump", "xmltree", apk_path, "--file", normalized_entry])
    except Exception:
        return None, None

    resource_refs = _extract_drawable_refs_from_xmltree(xmltree_output)
    for ref in resource_refs:
        resolved_entry = _resolve_resource_id_to_entry(
            apk_path,
            ref,
            aapt2_path=aapt2_path,
            androguard_path=androguard_path,
        )
        if not resolved_entry:
            continue
        nested_bytes, nested_entry = _extract_icon_bytes_from_entry(
            apk_path,
            resolved_entry,
            aapt2_path=aapt2_path,
            androguard_path=androguard_path,
            depth=depth + 1,
            visited=visited,
        )
        if nested_bytes:
            return nested_bytes, nested_entry
    return None, None


def _parse_with_aapt2(apk_path: str, aapt2_path: str) -> dict[str, Any]:
    parsed = _default_result()
    androguard_path = shutil.which("androguard")

    badging_output = _run_tool([aapt2_path, "dump", "badging", apk_path])
    badging_info = _parse_badging_output(badging_output)
    parsed["app_name"] = badging_info.get("app_name")
    parsed["package_name"] = badging_info.get("package_name")
    parsed["version_name"] = badging_info.get("version_name")
    parsed["version_code"] = badging_info.get("version_code")
    parsed["icon_name"] = badging_info.get("icon_name")

    manifest_output = _run_tool([aapt2_path, "dump", "xmltree", apk_path, "--file", "AndroidManifest.xml"])
    manifest_info = _parse_manifest_xmltree(manifest_output)

    permission_names = manifest_info["permission_names"] or badging_info.get("permission_names", [])
    parsed["permissions"] = _build_permissions(permission_names)
    parsed["activities"] = _build_activities(manifest_info["activity_names"], manifest_info["launcher_activities"])
    parsed["services"] = sorted({item for item in manifest_info["service_names"] if item})
    parsed["providers"] = sorted({item for item in manifest_info["provider_names"] if item})
    parsed["_receivers"] = sorted({item for item in manifest_info["receiver_names"] if item})
    parsed["_libraries"] = sorted({item for item in manifest_info["library_names"] if item})
    parsed["_features"] = sorted({item for item in manifest_info["feature_names"] if item})
    parsed["_declared_permissions"] = sorted({item for item in manifest_info["declared_permission_names"] if item})

    icon_bytes, resolved_icon_name = _extract_icon_bytes_from_entry(
        apk_path,
        parsed.get("icon_name"),
        aapt2_path=aapt2_path,
        androguard_path=androguard_path,
    )
    if icon_bytes:
        parsed["icon_bytes"] = icon_bytes
        parsed["icon_name"] = resolved_icon_name or parsed.get("icon_name")
    else:
        for resource_id in _extract_icon_resource_ids_from_xmltree(manifest_output):
            resolved_entry = _resolve_resource_id_to_entry(
                apk_path,
                resource_id,
                aapt2_path=aapt2_path,
                androguard_path=androguard_path,
            )
            if not resolved_entry:
                continue
            fallback_icon_bytes, fallback_resolved_icon_name = _extract_icon_bytes_with_get_icon_from_apk(
                apk_path,
                resolved_entry,
            )
            if fallback_icon_bytes:
                parsed["icon_bytes"] = fallback_icon_bytes
                parsed["icon_name"] = fallback_resolved_icon_name or resolved_entry
                break

    parsed["so_files"] = _extract_so_files(apk_path)
    return parsed


def _parse_with_androguard(apk_path: str) -> dict[str, Any]:
    parsed = _default_result()
    apk = APK(apk_path)
    androguard_path = shutil.which("androguard")

    app_icon_name = _safe_call(apk.get_app_icon)
    icon_bytes: bytes | None = None
    if app_icon_name:
        raw_icon = _safe_call(lambda: apk.get_file(app_icon_name))
        if isinstance(raw_icon, (bytes, bytearray)):
            icon_bytes = bytes(raw_icon)

    if not _is_image_bytes(icon_bytes):
        aapt2_path = _detect_build_tool("aapt2")
        if aapt2_path:
            try:
                manifest_output = _run_tool([aapt2_path, "dump", "xmltree", apk_path, "--file", "AndroidManifest.xml"])
            except Exception:
                manifest_output = ""

            for resource_id in _extract_icon_resource_ids_from_xmltree(manifest_output):
                resolved_entry = _resolve_resource_id_to_entry(
                    apk_path,
                    resource_id,
                    aapt2_path=aapt2_path,
                    androguard_path=androguard_path,
                )
                if not resolved_entry:
                    continue
                fallback_icon_bytes, fallback_resolved_icon_name = _extract_icon_bytes_with_get_icon_from_apk(
                    apk_path,
                    resolved_entry,
                )
                if fallback_icon_bytes:
                    icon_bytes = fallback_icon_bytes
                    app_icon_name = fallback_resolved_icon_name or resolved_entry or app_icon_name
                    break

    permissions = _build_permissions(_safe_call(apk.get_permissions, []) or [])
    launcher_activities = set(_safe_call(apk.get_main_activities, set()) or set())
    activities = _build_activities(_safe_call(apk.get_activities, []) or [], launcher_activities)
    services = sorted({item for item in (_safe_call(apk.get_services, []) or []) if item})
    providers = sorted({item for item in (_safe_call(apk.get_providers, []) or []) if item})
    receivers = sorted({item for item in (_safe_call(apk.get_receivers, []) or []) if item})
    cert_result = _extract_certificate_digests(apk=apk)

    parsed.update(
        {
            "app_name": _safe_call(apk.get_app_name),
            "package_name": _safe_call(apk.get_package),
            "version_name": _safe_android_version(apk, "Name"),
            "version_code": _safe_android_version(apk, "Code"),
            "cert_md5": cert_result.get("cert_md5"),
            "cert_sha1": cert_result.get("cert_sha1"),
            "cert_sha256": cert_result.get("cert_sha256"),
            "cert_info": cert_result.get("cert_info"),
            "permissions": permissions,
            "activities": activities,
            "services": services,
            "providers": providers,
            "_receivers": receivers,
            "so_files": _extract_so_files(apk_path),
            "icon_bytes": icon_bytes if _is_image_bytes(icon_bytes) else None,
            "icon_name": app_icon_name or None,
        }
    )
    return parsed


def _merge_result(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    list_like_fields = {
        "permissions",
        "activities",
        "services",
        "providers",
        "so_files",
        "_receivers",
        "_libraries",
        "_features",
        "_declared_permissions",
    }
    for key, value in patch.items():
        if key in list_like_fields:
            if not merged.get(key) and value:
                merged[key] = value
            continue
        if merged.get(key) in (None, "", []):
            if value not in (None, "", []):
                merged[key] = value
    return merged


def _has_core_fields(parsed: dict[str, Any]) -> bool:
    return bool(parsed.get("app_name")) and bool(parsed.get("package_name"))


def _has_component_fields(parsed: dict[str, Any]) -> bool:
    return bool(parsed.get("activities") or parsed.get("services") or parsed.get("providers"))


def _normalize_component_name(name: str | None, package_name: str | None) -> str | None:
    text = str(name or "").strip()
    if not text:
        return None
    package = str(package_name or "").strip()
    if text.startswith(".") and package:
        return f"{package}{text}"
    return text


def _parse_manifest_with_apkinspector(apk_path: str, package_name: str | None) -> dict[str, Any]:
    if parse_apk_for_manifest is None:
        return {}

    manifest_xml = parse_apk_for_manifest(apk_path)
    root = ET.fromstring(manifest_xml)
    android_ns = "{http://schemas.android.com/apk/res/android}"
    manifest_package = str(root.attrib.get("package") or "").strip() or None
    effective_package = manifest_package or package_name
    app_name = None
    application_node = root.find("application")
    if application_node is not None:
        app_name = str(application_node.attrib.get(f"{android_ns}label") or "").strip() or None

    permission_names: list[str] = []
    activity_names: list[str] = []
    service_names: list[str] = []
    provider_names: list[str] = []
    receiver_names: list[str] = []
    library_names: list[str] = []
    feature_names: list[str] = []
    declared_permission_names: list[str] = []

    for node in root.iter():
        tag = str(node.tag).split("}", 1)[-1]
        name = _normalize_component_name(node.attrib.get(f"{android_ns}name"), effective_package)
        if tag == "uses-permission":
            if name:
                permission_names.append(name)
        elif tag in {"activity", "activity-alias"}:
            if name:
                activity_names.append(name)
        elif tag == "service":
            if name:
                service_names.append(name)
        elif tag == "provider":
            if name:
                provider_names.append(name)
        elif tag == "receiver":
            if name:
                receiver_names.append(name)
        elif tag == "uses-library":
            if name:
                library_names.append(name)
        elif tag == "uses-feature":
            if name:
                feature_names.append(name)
        elif tag == "permission":
            if name:
                declared_permission_names.append(name)

    return {
        "app_name": app_name,
        "package_name": effective_package,
        "permissions": _build_permissions(permission_names),
        "activities": _build_activities(activity_names, set()),
        "services": sorted(set(service_names)),
        "providers": sorted(set(provider_names)),
        "_receivers": sorted(set(receiver_names)),
        "_libraries": sorted(set(library_names)),
        "_features": sorted(set(feature_names)),
        "_declared_permissions": sorted(set(declared_permission_names)),
    }


def _build_component_fingerprint(
    package_name: str | None,
    *,
    permissions: list[dict[str, Any]],
    activities: list[dict[str, Any]],
    services: list[str],
    providers: list[str],
    receivers: list[str],
    libraries: list[str],
    features: list[str],
    declared_permissions: list[str],
) -> tuple[str | None, str | None]:
    package = (package_name or "").strip()
    permission_names = [str(item.get("name") or "").strip() for item in permissions if isinstance(item, dict)]
    activity_names = [str(item.get("name") or "").strip() for item in activities if isinstance(item, dict)]

    all_components: list[str] = [
        *permission_names,
        *activity_names,
        *[str(item).strip() for item in services],
        *[str(item).strip() for item in providers],
        *[str(item).strip() for item in receivers],
        *[str(item).strip() for item in libraries],
        *[str(item).strip() for item in features],
        *[str(item).strip() for item in declared_permissions],
    ]

    normalized_components: list[str] = []
    for item in all_components:
        if not item:
            continue
        if package:
            item = item.replace(package, "")
        item = item.strip()
        if not item:
            continue
        normalized_components.append(item)

    if not normalized_components:
        return None, None

    component_string = " ".join(sorted(set(normalized_components)))
    component_md5 = hashlib.md5(component_string.encode("utf-8")).hexdigest()
    return component_string, component_md5


def parse_apk(apk_path: str) -> dict[str, Any]:
    path = Path(apk_path)
    if not path.is_file():
        raise FileNotFoundError(f"APK文件不存在: {apk_path}")

    result = _default_result()
    aapt2_path = _detect_build_tool("aapt2")
    used_aapt2 = False

    if aapt2_path:
        try:
            result = _merge_result(result, _parse_with_aapt2(str(path), aapt2_path))
            used_aapt2 = True
        except Exception:
            pass

    if not (result.get("cert_md5") and result.get("cert_sha1") and result.get("cert_sha256")):
        try:
            result = _merge_result(result, _extract_certificate_digests(str(path)))
        except Exception as exc:
            logger.warning("certificate extract failed for %s: %s", path, exc)

    need_androguard_fallback = (
        not _has_core_fields(result)
        or not result.get("icon_bytes")
        or (used_aapt2 and not _has_component_fields(result))
    )
    if need_androguard_fallback:
        try:
            result = _merge_result(result, _parse_with_androguard(str(path)))
        except Exception as exc:
            logger.warning("androguard parse failed for %s: %s", path, exc)

    apkinspector_attempted = False
    need_apkinspector_component_fallback = used_aapt2 and not _has_component_fields(result)
    if need_apkinspector_component_fallback:
        try:
            apkinspector_result = _parse_manifest_with_apkinspector(str(path), result.get("package_name"))
            result = _merge_result(result, apkinspector_result)
            apkinspector_attempted = True
        except Exception as fallback_exc:
            logger.warning("apkinspector parse failed for %s: %s", path, fallback_exc)

    if not _has_core_fields(result) and not apkinspector_attempted:
        try:
            apkinspector_result = _parse_manifest_with_apkinspector(str(path), result.get("package_name"))
            result = _merge_result(result, apkinspector_result)
        except Exception as fallback_exc:
            logger.warning("apkinspector parse failed for %s: %s", path, fallback_exc)

    if not result.get("app_name") and result.get("package_name"):
        result["app_name"] = str(result.get("package_name"))

    component_string, component_md5 = _build_component_fingerprint(
        result.get("package_name"),
        permissions=result.get("permissions") or [],
        activities=result.get("activities") or [],
        services=result.get("services") or [],
        providers=result.get("providers") or [],
        receivers=result.get("_receivers") or [],
        libraries=result.get("_libraries") or [],
        features=result.get("_features") or [],
        declared_permissions=result.get("_declared_permissions") or [],
    )
    result["component_string"] = component_string
    result["component_md5"] = component_md5

    if not result.get("so_files"):
        result["so_files"] = _extract_so_files(str(path))

    return {
        "app_name": result.get("app_name"),
        "package_name": result.get("package_name"),
        "version_name": result.get("version_name"),
        "version_code": result.get("version_code"),
        "cert_md5": result.get("cert_md5"),
        "cert_sha1": result.get("cert_sha1"),
        "cert_sha256": result.get("cert_sha256"),
        "cert_info": result.get("cert_info"),
        "permissions": result.get("permissions") or [],
        "activities": result.get("activities") or [],
        "services": result.get("services") or [],
        "providers": result.get("providers") or [],
        "receivers": result.get("_receivers") or [],
        "so_files": result.get("so_files") or [],
        "icon_bytes": result.get("icon_bytes"),
        "icon_name": result.get("icon_name"),
        "component_string": result.get("component_string"),
        "component_md5": result.get("component_md5"),
    }
