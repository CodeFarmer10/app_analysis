from __future__ import annotations

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
