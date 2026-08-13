from __future__ import annotations

import hashlib
import hmac
import re
import subprocess
import time
from pathlib import Path

from androguard.core.apk import APK

from core.config import settings
from phone_agent.adb.device import install_apk, uninstall_apk
from services.device_service import (
    ADB_COMMAND_TIMEOUT_SECONDS,
    ADB_HEARTBEAT_TIMEOUT_SECONDS,
    check_device_health,
)

BOOT_MARKER = "__device_recovery_ok__"
HEALTH_APK_SHA256 = "e7de8cb3adc219b2c95ed931bcd075203a4fde46f3050446cf8cc18e8db1e985"
RESOURCE_ERROR_MARKERS = (
    "resource temporarily unavailable",
    "fork failed",
    "cannot fork",
    "can't fork",
)
PACKAGE_NAME_PATTERN = re.compile(r"[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+")


def recovery_timeout_budget_seconds() -> int:
    """Return the legal worst-case command budget for one recovery attempt.

    This includes reboot, the shared boot/connect deadline, four package checks,
    project-owned temporary file cleanup, two stable health windows, the process
    check, the optional residual uninstall, and the health APK install/uninstall
    round trip.
    """
    return (
        ADB_COMMAND_TIMEOUT_SECONDS
        + settings.DEVICE_RECOVERY_REBOOT_TIMEOUT_SECONDS
        + (4 * ADB_COMMAND_TIMEOUT_SECONDS)
        + ADB_COMMAND_TIMEOUT_SECONDS
        + (2 * settings.DEVICE_RECOVERY_STABLE_HEALTH_TIMEOUT_SECONDS)
        + ADB_COMMAND_TIMEOUT_SECONDS
        + settings.DEVICE_RECOVERY_UNINSTALL_TIMEOUT_SECONDS
        + settings.DEVICE_RECOVERY_DATA_CLEANUP_TIMEOUT_SECONDS
        + settings.DEVICE_RECOVERY_INSTALL_TIMEOUT_SECONDS
        + settings.DEVICE_RECOVERY_UNINSTALL_TIMEOUT_SECONDS
    )


class RecoveryStepError(RuntimeError):
    def __init__(self, step: str, detail: str) -> None:
        self.step = step
        self.detail = detail
        super().__init__(f"{step}: {detail}")


def run_adb(
    serial: str | None,
    args: list[str],
    *,
    step: str = "reboot",
    timeout_seconds: int = ADB_COMMAND_TIMEOUT_SECONDS,
) -> str:
    command = ["adb", *args] if serial is None else ["adb", "-s", serial, *args]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            encoding="utf-8",
            errors="ignore",
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RecoveryStepError(
            step, f"adb command timeout after {timeout_seconds} seconds"
        ) from exc
    except FileNotFoundError as exc:
        raise RecoveryStepError(step, "adb command not found") from exc
    except OSError as exc:
        raise RecoveryStepError(step, f"unable to execute adb: {exc}") from exc

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    if result.returncode != 0:
        detail = stderr or stdout or f"adb exited with status {result.returncode}"
        raise RecoveryStepError(step, detail)
    return stdout


def validate_health_apk(path: Path, expected_package: str) -> None:
    try:
        apk_bytes = path.read_bytes()
    except OSError as exc:
        raise RecoveryStepError("verify_install", f"unable to read health APK: {exc}") from exc

    actual_digest = hashlib.sha256(apk_bytes).hexdigest()
    if not hmac.compare_digest(actual_digest, HEALTH_APK_SHA256):
        raise RecoveryStepError(
            "verify_install",
            f"health APK SHA-256 mismatch: expected {HEALTH_APK_SHA256}, got {actual_digest}",
        )

    try:
        apk = APK(apk_bytes, raw=True)
    except Exception as exc:
        raise RecoveryStepError("verify_install", f"invalid health APK: {exc}") from exc

    if apk.get_package() != expected_package:
        raise RecoveryStepError(
            "verify_install",
            f"health APK package is {apk.get_package() or 'missing'}, expected {expected_package}",
        )
    if not apk.is_signed_v2():
        raise RecoveryStepError(
            "verify_install", "health APK is not signed with APK Signature Scheme v2"
        )

    component_getters = (
        apk.get_activities,
        apk.get_services,
        apk.get_receivers,
        apk.get_providers,
    )
    if apk.get_permissions() or any(getter() for getter in component_getters):
        raise RecoveryStepError(
            "verify_install", "health APK declares permissions or Android components"
        )
    if any(name.endswith(".dex") for name in apk.get_files()):
        raise RecoveryStepError("verify_install", "health APK unexpectedly contains code")


def wait_for_device_boot(serial: str, timeout_seconds: int) -> None:
    deadline = time.monotonic() + timeout_seconds
    last_detail = "device did not become ready"

    def run_boot_command(args: list[str]) -> str:
        remaining_seconds = deadline - time.monotonic()
        if remaining_seconds <= 0:
            raise TimeoutError
        return run_adb(
            serial,
            args,
            step="wait_boot",
            timeout_seconds=remaining_seconds,
        )

    def connect_network_device() -> None:
        if ":" not in serial:
            return
        remaining_seconds = deadline - time.monotonic()
        if remaining_seconds <= 0:
            raise TimeoutError
        run_adb(
            None,
            ["connect", serial],
            step="wait_boot",
            timeout_seconds=remaining_seconds,
        )

    while True:
        try:
            connect_network_device()
            state = run_boot_command(["get-state"])
            if state.strip().lower() != "device":
                last_detail = f"adb get-state returned {state or 'unavailable'}"
            else:
                boot_completed = run_boot_command(
                    ["shell", "getprop", "sys.boot_completed"]
                )
                if boot_completed.strip() != "1":
                    last_detail = (
                        "sys.boot_completed returned "
                        f"{boot_completed or 'unavailable'}"
                    )
                else:
                    marker = run_boot_command(["shell", "echo", BOOT_MARKER])
                    if marker.strip() == BOOT_MARKER:
                        return
                    last_detail = "adb shell recovery marker check failed"
        except TimeoutError:
            break
        except RecoveryStepError as exc:
            last_detail = exc.detail

        remaining_seconds = deadline - time.monotonic()
        if remaining_seconds <= 0:
            break
        time.sleep(min(1, remaining_seconds))

    raise RecoveryStepError(
        "wait_boot", f"device boot timeout after {timeout_seconds} seconds: {last_detail}"
    )


def _contains_resource_error(output: str) -> bool:
    normalized = output.casefold()
    return any(marker in normalized for marker in RESOURCE_ERROR_MARKERS)


def package_exists(serial: str, package_name: str, *, step: str) -> bool:
    try:
        output = run_adb(
            serial,
            ["shell", "cmd", "package", "path", package_name],
            step=step,
        )
    except RecoveryStepError as exc:
        if exc.detail == "adb exited with status 1":
            return False
        raise
    if _contains_resource_error(output):
        raise RecoveryStepError(step, output)
    return any(line.strip().startswith("package:") for line in output.splitlines())


def remove_residual_package(serial: str, package_name: str | None) -> None:
    normalized_package = str(package_name or "").strip()
    if not normalized_package:
        return
    if not package_exists(serial, normalized_package, step="cleanup_app"):
        return

    try:
        removed, detail = uninstall_apk(
            normalized_package,
            device_id=serial,
            timeout=settings.DEVICE_RECOVERY_UNINSTALL_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        raise RecoveryStepError("cleanup_app", str(exc)) from exc
    if not removed:
        raise RecoveryStepError(
            "cleanup_app", detail or f"failed to remove {normalized_package}"
        )
    if package_exists(serial, normalized_package, step="cleanup_app"):
        raise RecoveryStepError(
            "cleanup_app", f"quarantine package remains after uninstall: {normalized_package}"
        )


def remove_residual_package_data(serial: str, package_name: str | None) -> None:
    normalized_package = str(package_name or "").strip()
    if not normalized_package:
        return
    if len(normalized_package) > 255 or not PACKAGE_NAME_PATTERN.fullmatch(
        normalized_package
    ):
        raise RecoveryStepError(
            "cleanup_app_data", f"invalid package name: {normalized_package}"
        )

    data_path = f"/data/media/0/Android/data/{normalized_package}"
    command = (
        f"path={data_path}; "
        'if [ -e "$path" ]; then rm -rf -- "$path"; fi; '
        'test ! -e "$path"'
    )
    run_adb(
        serial,
        ["shell", "su", "-c", command],
        step="cleanup_app_data",
        timeout_seconds=settings.DEVICE_RECOVERY_DATA_CLEANUP_TIMEOUT_SECONDS,
    )


def cleanup_project_temp_files(serial: str) -> None:
    run_adb(
        serial,
        [
            "shell",
            "rm",
            "-f",
            "/sdcard/tmp.png",
            "/sdcard/capture.pcap",
            "/sdcard/capture-*.pcap",
        ],
        step="cleanup_temp",
    )


def require_device_health(serial: str) -> None:
    try:
        health = check_device_health(serial)
    except Exception as exc:
        raise RecoveryStepError("storage", str(exc)) from exc
    if health.state != "healthy":
        raise RecoveryStepError(
            "storage", health.reason or f"device health state is {health.state}"
        )


def require_device_health_stable(
    serial: str,
    *,
    timeout_seconds: int | None = None,
    interval_seconds: int | None = None,
) -> None:
    timeout = (
        settings.DEVICE_RECOVERY_STABLE_HEALTH_TIMEOUT_SECONDS
        if timeout_seconds is None
        else timeout_seconds
    )
    interval = (
        settings.DEVICE_RECOVERY_STABLE_HEALTH_INTERVAL_SECONDS
        if interval_seconds is None
        else interval_seconds
    )
    deadline = time.monotonic() + max(0, timeout)
    last_error: RecoveryStepError | None = None

    while True:
        try:
            require_device_health(serial)
            return
        except RecoveryStepError as exc:
            last_error = exc

        remaining_seconds = deadline - time.monotonic()
        if remaining_seconds <= 0:
            detail = last_error.detail if last_error else "device health check failed"
            raise RecoveryStepError("storage", detail)
        time.sleep(min(max(1, interval), remaining_seconds))


def require_process_command(serial: str) -> None:
    output = run_adb(serial, ["shell", "ps", "-A"], step="process")
    if not output.strip():
        raise RecoveryStepError("process", "ps -A returned no output")
    if _contains_resource_error(output):
        raise RecoveryStepError("process", output)


def verify_apk_round_trip(
    serial: str,
    apk_path: Path,
    expected_package: str,
) -> None:
    try:
        installed, install_detail = install_apk(
            str(apk_path),
            device_id=serial,
            replace_existing=True,
            timeout=settings.DEVICE_RECOVERY_INSTALL_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        raise RecoveryStepError("verify_install", str(exc)) from exc
    if not installed:
        raise RecoveryStepError(
            "verify_install", install_detail or "health APK installation failed"
        )
    if not package_exists(serial, expected_package, step="verify_install"):
        raise RecoveryStepError(
            "verify_install", "health APK package absent after installation"
        )

    try:
        removed, uninstall_detail = uninstall_apk(
            expected_package,
            device_id=serial,
            timeout=settings.DEVICE_RECOVERY_UNINSTALL_TIMEOUT_SECONDS,
        )
    except Exception as exc:
        raise RecoveryStepError("verify_uninstall", str(exc)) from exc
    if not removed:
        raise RecoveryStepError(
            "verify_uninstall", uninstall_detail or "health APK uninstall failed"
        )
    if package_exists(serial, expected_package, step="verify_uninstall"):
        raise RecoveryStepError(
            "verify_uninstall", "health APK package remains after uninstall"
        )


def perform_device_recovery(device: dict) -> None:
    serial = str(device.get("serial") or "").strip()
    if not serial:
        raise RecoveryStepError("reboot", "device serial is empty")

    apk_path = Path(settings.DEVICE_RECOVERY_APK_PATH)
    expected_package = settings.DEVICE_RECOVERY_APK_PACKAGE

    validate_health_apk(apk_path, expected_package)
    run_adb(serial, ["reboot"])
    wait_for_device_boot(
        serial,
        timeout_seconds=settings.DEVICE_RECOVERY_REBOOT_TIMEOUT_SECONDS,
    )
    remove_residual_package(serial, device.get("quarantine_package_name"))
    remove_residual_package_data(serial, device.get("quarantine_package_name"))
    cleanup_project_temp_files(serial)
    require_device_health_stable(serial)
    require_process_command(serial)
    verify_apk_round_trip(serial, apk_path, expected_package)
    require_device_health_stable(serial)
