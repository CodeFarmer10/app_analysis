from __future__ import annotations

import logging
import subprocess
from datetime import datetime
from uuid import uuid4

from fastapi import HTTPException, status

from repositories.device_repo import (
    count_in_progress_tasks,
    create_device as create_device_record,
    delete_device as delete_device_record,
    get_device_by_id,
    get_device_by_serial,
    list_devices,
    update_device,
)

ADB_COMMAND_TIMEOUT_SECONDS = 10
ADB_HEARTBEAT_TIMEOUT_SECONDS = 3
HEARTBEAT_REFRESH_INTERVAL_SECONDS = 5 * 60

logger = logging.getLogger(__name__)


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


def _refresh_device_runtime(device: dict) -> dict:
    serial = str(device.get("serial") or "").strip()
    online_state = _detect_device_online(serial)
    has_current_task = bool(device.get("current_task_id"))
    current_status = str(device.get("status") or "").strip() or "offline"

    if online_state is True:
        next_status = "busy" if has_current_task else "online"
    elif online_state is False:
        next_status = "offline"
    else:
        next_status = "busy" if (current_status == "online" and has_current_task) else current_status

    fields_to_update: dict[str, object] = {}
    if device.get("status") != next_status:
        fields_to_update["status"] = next_status
    device["status"] = next_status

    should_refresh_heartbeat = online_state is True or (
        online_state is None and next_status in {"online", "busy"}
    )
    if should_refresh_heartbeat:
        heartbeat_at = datetime.now()
        fields_to_update["last_heartbeat_at"] = heartbeat_at
        device["last_heartbeat_at"] = heartbeat_at

    if fields_to_update and device.get("id"):
        update_device(str(device["id"]), fields_to_update)

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
    device_info = _collect_device_info(normalized_serial)
    normalized_name = (name or "").strip() or device_info.get("model") or normalized_serial
    device_id = str(uuid4())

    create_device_record(
        {
            "id": device_id,
            "name": normalized_name,
            "serial": normalized_serial,
            "android_version": device_info.get("android_version"),
            "model": device_info.get("model"),
            "resolution": device_info.get("resolution"),
            "status": "online",
            "last_heartbeat_at": datetime.now(),
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
