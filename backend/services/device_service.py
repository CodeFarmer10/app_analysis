from __future__ import annotations

import lzma
import logging
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from uuid import uuid4

from fastapi import HTTPException, status

from phone_agent.adb.device import install_apk
from repositories.device_repo import (
    count_in_progress_tasks,
    create_device as create_device_record,
    delete_device as delete_device_record,
    get_device_by_id,
    get_device_by_serial,
    list_devices,
    update_device,
    update_idle_device_snapshot,
)

ADB_COMMAND_TIMEOUT_SECONDS = 10
ADB_HEARTBEAT_TIMEOUT_SECONDS = 3
HEARTBEAT_REFRESH_INTERVAL_SECONDS = 60
MIN_DATA_AVAILABLE_KIB = 5 * 1024 * 1024
ADB_PUSH_TIMEOUT_SECONDS = 120
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEVICE_BOOTSTRAP_DIR = PROJECT_ROOT / "tools" / "device_bootstrap"
ADB_KEYBOARD_APK_PATH = DEVICE_BOOTSTRAP_DIR / "ADBKeyboard.apk"
ADB_KEYBOARD_PACKAGE = "com.android.adbkeyboard"
ADB_KEYBOARD_IME = "com.android.adbkeyboard/.AdbIME"
FRIDA_SERVER_DIR = PROJECT_ROOT / "tools" / "frida"
FRIDA_SERVER_REMOTE_PATH = "/data/local/tmp/frida-server"
FRIDA_SERVER_START_WAIT_SECONDS = 1.0

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class DeviceHealthResult:
    state: str
    reason: str | None = None
    available_kib: int | None = None


def _run_command(command: list[str], timeout: int = ADB_COMMAND_TIMEOUT_SECONDS) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="ignore",
        )
    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="未找到 adb 命令，请先在运行环境安装 adb",
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"设备响应超时: {' '.join(command)}",
        ) from exc

    if result.returncode != 0:
        message = (result.stderr or result.stdout or "").strip()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message or f"命令执行失败: {' '.join(command)}",
        )
    return (result.stdout or "").strip()


def _run_command_optional(command: list[str], timeout: int = ADB_HEARTBEAT_TIMEOUT_SECONDS) -> str | None:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="ignore",
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None
    value = (result.stdout or "").strip()
    return value or None


def _try_connect_device(serial: str) -> None:
    if ":" not in serial:
        return
    _run_command(["adb", "connect", serial], timeout=ADB_COMMAND_TIMEOUT_SECONDS)


def _ensure_device_reachable(serial: str) -> None:
    _try_connect_device(serial)
    state = _run_command(["adb", "-s", serial, "get-state"]).strip().lower()
    if state != "device":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"设备不可用，当前状态: {state or 'unknown'}",
        )


def _run_adb_shell_optional(serial: str, shell_args: list[str]) -> str | None:
    try:
        output = _run_command(["adb", "-s", serial, "shell", *shell_args])
    except HTTPException:
        return None
    value = output.strip()
    return value or None


def _try_connect_device_optional(serial: str) -> None:
    if ":" not in serial:
        return
    _ = _run_command_optional(["adb", "connect", serial])


def _detect_device_online(serial: str) -> bool | None:
    if not serial:
        return False
    _try_connect_device_optional(serial)
    state = _run_command_optional(["adb", "-s", serial, "get-state"])
    if state is None:
        return None
    normalized = state.strip().lower()
    if normalized == "device":
        return True
    if normalized in {"offline", "unauthorized", "unknown"}:
        return False
    return False


def _parse_data_available_kib(df_output: str | None) -> int | None:
    if not df_output:
        return None

    for line in df_output.splitlines():
        fields = line.split()
        if len(fields) < 6 or fields[-1] != "/data":
            continue
        try:
            return int(fields[3])
        except ValueError:
            return None
    return None


def check_device_health(serial: str) -> DeviceHealthResult:
    """Run the heartbeat probe without raising runtime errors to callers."""
    normalized_serial = serial.strip()
    if not normalized_serial:
        return DeviceHealthResult("offline", "adb serial is empty")

    _try_connect_device_optional(normalized_serial)
    state = _run_command_optional(
        ["adb", "-s", normalized_serial, "get-state"],
        timeout=ADB_HEARTBEAT_TIMEOUT_SECONDS,
    )
    normalized_state = str(state or "").strip().lower()
    if normalized_state != "device":
        detail = normalized_state or "unavailable"
        return DeviceHealthResult("offline", f"adb get-state returned {detail}")

    marker = _run_command_optional(
        ["adb", "-s", normalized_serial, "shell", "echo", "__device_health_ok__"],
        timeout=ADB_HEARTBEAT_TIMEOUT_SECONDS,
    )
    if marker != "__device_health_ok__":
        return DeviceHealthResult("quarantined", "adb shell marker check failed")

    package_path = _run_command_optional(
        ["adb", "-s", normalized_serial, "shell", "cmd", "package", "path", "android"],
        timeout=ADB_HEARTBEAT_TIMEOUT_SECONDS,
    )
    if not package_path or not package_path.startswith("package:"):
        return DeviceHealthResult("quarantined", "package manager check failed")

    data_free_kib = _parse_data_available_kib(
        _run_command_optional(
            ["adb", "-s", normalized_serial, "shell", "df", "-k", "/data"],
            timeout=ADB_HEARTBEAT_TIMEOUT_SECONDS,
        )
    )
    if data_free_kib is None:
        return DeviceHealthResult("quarantined", "storage check failed")
    if data_free_kib < MIN_DATA_AVAILABLE_KIB:
        return DeviceHealthResult(
            "quarantined",
            f"storage below 5 GiB ({data_free_kib} KiB available)",
            data_free_kib,
        )
    return DeviceHealthResult("healthy", available_kib=data_free_kib)


def _parse_resolution(raw_value: str | None) -> str | None:
    if not raw_value:
        return None
    for line in raw_value.splitlines():
        text = line.strip()
        if "Physical size:" in text:
            return text.split("Physical size:", 1)[1].strip() or None
    return raw_value.strip() or None


def _collect_device_info(serial: str) -> dict[str, str | None]:
    model = _run_adb_shell_optional(serial, ["getprop", "ro.product.model"])
    android_version = _run_adb_shell_optional(serial, ["getprop", "ro.build.version.release"])
    resolution_raw = _run_adb_shell_optional(serial, ["wm", "size"])
    return {
        "model": model,
        "android_version": android_version,
        "resolution": _parse_resolution(resolution_raw),
    }


def _is_valid_apk_file(path: Path) -> bool:
    if not path.exists() or not path.is_file():
        return False
    try:
        with path.open("rb") as file_obj:
            magic = file_obj.read(4)
    except OSError:
        return False
    return magic == b"PK\x03\x04"


def _ensure_adb_keyboard_apk_file() -> Path:
    if _is_valid_apk_file(ADB_KEYBOARD_APK_PATH):
        return ADB_KEYBOARD_APK_PATH

    if not ADB_KEYBOARD_APK_PATH.exists():
        detail = f"缺少文件: {ADB_KEYBOARD_APK_PATH}"
    else:
        detail = f"文件格式无效: {ADB_KEYBOARD_APK_PATH}"
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=f"ADBKeyboard.apk 未打包或损坏，请补充本地文件后重试: {detail}",
    )


def _get_device_primary_abi(serial: str) -> str:
    abi = _run_command_optional(["adb", "-s", serial, "shell", "getprop", "ro.product.cpu.abi"])
    normalized = str(abi or "").strip().lower()
    if normalized:
        return normalized
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail="读取设备 CPU ABI 失败，无法匹配 frida-server",
    )


def _frida_abi_keywords(abi: str) -> list[str]:
    normalized = abi.lower()
    if normalized.startswith("arm64"):
        return ["android-arm64", "android-aarch64"]
    if normalized.startswith("armeabi") or normalized.startswith("arm"):
        return ["android-arm"]
    if normalized.startswith("x86_64"):
        return ["android-x86_64"]
    if normalized.startswith("x86"):
        return ["android-x86"]
    return []


def _decompress_xz_file(source_path: Path, target_path: Path) -> Path:
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with lzma.open(source_path, "rb") as src, target_path.open("wb") as dst:
        shutil.copyfileobj(src, dst)
    return target_path


def _resolve_frida_server_binary(serial: str) -> Path:
    if not FRIDA_SERVER_DIR.exists():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"frida-server 目录不存在: {FRIDA_SERVER_DIR}",
        )

    candidates = sorted(
        path
        for path in FRIDA_SERVER_DIR.iterdir()
        if path.is_file() and path.name.startswith("frida-server-") and "android" in path.name
    )
    if not candidates:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"未找到 frida-server 文件: {FRIDA_SERVER_DIR}",
        )

    abi = _get_device_primary_abi(serial)
    keywords = _frida_abi_keywords(abi)

    def _pick(prefer_xz: bool) -> Path | None:
        for keyword in keywords:
            for candidate in candidates:
                is_xz = candidate.suffix == ".xz"
                if keyword in candidate.name and is_xz == prefer_xz:
                    return candidate
        return None

    binary = _pick(prefer_xz=False)
    if binary is None:
        xz_binary = _pick(prefer_xz=True)
        if xz_binary is not None:
            extracted = xz_binary.with_suffix("")
            binary = extracted if extracted.exists() else _decompress_xz_file(xz_binary, extracted)

    if binary is None:
        fallback = next((candidate for candidate in candidates if candidate.suffix != ".xz"), None)
        if fallback is None:
            xz_fallback = next((candidate for candidate in candidates if candidate.suffix == ".xz"), None)
            if xz_fallback is not None:
                extracted = xz_fallback.with_suffix("")
                fallback = extracted if extracted.exists() else _decompress_xz_file(xz_fallback, extracted)
        binary = fallback

    if binary is None or not binary.exists():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"未找到可用 frida-server，可用目录: {FRIDA_SERVER_DIR}",
        )

    return binary


def _ensure_adb_keyboard_installed(serial: str) -> None:
    apk_path = _ensure_adb_keyboard_apk_file()
    package_path = _run_command_optional(["adb", "-s", serial, "shell", "pm", "path", ADB_KEYBOARD_PACKAGE])
    if not package_path:
        installed, install_msg = install_apk(str(apk_path), device_id=serial, replace_existing=True)
        if not installed:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"安装 ADBKeyboard 失败: {install_msg}",
            )

    try:
        _run_command(["adb", "-s", serial, "shell", "ime", "enable", ADB_KEYBOARD_IME])
    except HTTPException as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"启用 ADBKeyboard 输入法失败: {exc.detail}",
        ) from exc


def _is_frida_server_running(serial: str) -> bool:
    output = _run_command_optional(["adb", "-s", serial, "shell", "su", "-c", "pidof frida-server"])
    return bool(str(output or "").strip())


def _ensure_frida_server_ready(serial: str) -> None:
    frida_binary = _resolve_frida_server_binary(serial)
    _run_command(
        ["adb", "-s", serial, "push", str(frida_binary), FRIDA_SERVER_REMOTE_PATH],
        timeout=ADB_PUSH_TIMEOUT_SECONDS,
    )
    _run_command(
        ["adb", "-s", serial, "shell", "su", "-c", f"chmod 755 {FRIDA_SERVER_REMOTE_PATH}"],
    )
    if _is_frida_server_running(serial):
        return

    _run_command(
        [
            "adb",
            "-s",
            serial,
            "shell",
            "su",
            "-c",
            f"nohup {FRIDA_SERVER_REMOTE_PATH} >/dev/null 2>&1 &",
        ],
    )
    if FRIDA_SERVER_START_WAIT_SECONDS > 0:
        time.sleep(FRIDA_SERVER_START_WAIT_SECONDS)

    if not _is_frida_server_running(serial):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="frida-server 启动失败，请确认设备已 root 且 su 可用",
        )


def _bootstrap_device_tools(serial: str) -> None:
    _ensure_adb_keyboard_installed(serial)
    _ensure_frida_server_ready(serial)


def _refresh_device_runtime(device: dict) -> dict:
    serial = str(device.get("serial") or "").strip()
    has_current_task = bool(device.get("current_task_id"))
    current_status = str(device.get("status") or "").strip() or "offline"

    # Recovery lifecycle states are owned by the recovery worker, not heartbeat probes.
    if current_status in {"quarantined", "recovering", "error"}:
        return device

    health = check_device_health(serial)
    if health.state != "healthy":
        if current_status == "busy" or has_current_task:
            logger.warning(
                "busy device health check failed serial=%s state=%s reason=%s",
                serial or "unknown",
                health.state,
                health.reason,
            )
            return device

        if health.state == "offline":
            fields_to_update: dict[str, object] = {"status": "offline"}
        else:
            quarantined_at = datetime.now()
            fields_to_update = {
                "status": "quarantined",
                "quarantine_reason": health.reason,
                "quarantined_at": quarantined_at,
                "quarantine_task_id": None,
                "quarantine_package_name": None,
            }
        if device.get("id") and update_idle_device_snapshot(
            str(device["id"]),
            current_status,
            fields_to_update,
        ):
            device.update(fields_to_update)
        return device

    if current_status != "busy" and not has_current_task:
        heartbeat_at = datetime.now()
        fields_to_update = {
            "status": "online",
            "last_heartbeat_at": heartbeat_at,
        }
        if device.get("id") and update_idle_device_snapshot(
            str(device["id"]),
            current_status,
            fields_to_update,
        ):
            device.update(fields_to_update)
        return device

    heartbeat_at = datetime.now()
    device["last_heartbeat_at"] = heartbeat_at
    if device.get("id"):
        update_device(str(device["id"]), {"last_heartbeat_at": heartbeat_at})

    return device


def refresh_all_device_heartbeats() -> None:
    devices = list_devices()
    for device in devices:
        try:
            _refresh_device_runtime(device)
        except Exception as exc:  # pragma: no cover - runtime dependent
            logger.warning(
                "refresh device heartbeat failed serial=%s err=%s",
                str(device.get("serial") or "").strip() or "unknown",
                exc,
            )


def list_device_items() -> list[dict]:
    return list_devices()


def get_device_detail(device_id: str) -> dict:
    device = get_device_by_id(device_id)
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="设备不存在",
        )
    return device


def create_new_device(serial: str, name: str | None = None) -> dict:
    normalized_serial = serial.strip()
    if not normalized_serial:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="设备序列号不能为空",
        )

    existed = get_device_by_serial(normalized_serial)
    if existed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="设备 serial 已存在",
        )

    _ensure_device_reachable(normalized_serial)
    _bootstrap_device_tools(normalized_serial)
    device_info = _collect_device_info(normalized_serial)
    health = check_device_health(normalized_serial)
    normalized_name = (name or "").strip() or device_info.get("model") or normalized_serial
    device_id = str(uuid4())

    heartbeat_at: datetime | None = None
    quarantine_reason: str | None = None
    quarantined_at: datetime | None = None
    if health.state == "healthy":
        device_status = "online"
        heartbeat_at = datetime.now()
    elif health.state == "offline":
        device_status = "offline"
    else:
        device_status = "quarantined"
        quarantine_reason = health.reason
        quarantined_at = datetime.now()

    create_device_record(
        {
            "id": device_id,
            "name": normalized_name,
            "serial": normalized_serial,
            "android_version": device_info.get("android_version"),
            "model": device_info.get("model"),
            "resolution": device_info.get("resolution"),
            "status": device_status,
            "last_heartbeat_at": heartbeat_at,
            "quarantine_reason": quarantine_reason,
            "quarantined_at": quarantined_at,
        }
    )
    return get_device_detail(device_id)


def update_device_name(device_id: str, name: str) -> dict:
    _ = get_device_detail(device_id)
    normalized_name = name.strip()
    if not normalized_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="设备名称不能为空",
        )

    update_device(device_id, {"name": normalized_name})
    return get_device_detail(device_id)


def remove_device(device_id: str) -> None:
    device = get_device_detail(device_id)
    if device.get("current_task_id"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="设备存在进行中任务，无法删除",
        )
    if count_in_progress_tasks(device_id) > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="设备存在进行中任务，无法删除",
        )

    deleted_rows = delete_device_record(device_id)
    if deleted_rows == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="设备不存在",
        )
