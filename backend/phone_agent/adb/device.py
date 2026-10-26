"""Device control utilities for Android automation."""

import logging
import os
import re
import shlex
import subprocess
import time
from dataclasses import dataclass
from typing import List, Optional, Tuple

from phone_agent.config.apps import APP_PACKAGES
from phone_agent.config.timing import TIMING_CONFIG

logger = logging.getLogger(__name__)


def get_current_app(device_id: str | None = None) -> str:
    """
    Get the currently focused app name.

    Args:
        device_id: Optional ADB device ID for multi-device setups.

    Returns:
        The app name if recognized, otherwise "System Home".
    """
    adb_prefix = _get_adb_prefix(device_id)

    result = subprocess.run(
        adb_prefix + ["shell", "dumpsys", "window"], capture_output=True, text=True, encoding="utf-8"
    )
    output = result.stdout
    if not output:
        raise ValueError("No output from dumpsys window")
    packages = get_package_name(device_id)
    focused_package: str | None = None
    # Parse window focus info
    for line in output.split("\n"):
        if "mCurrentFocus" in line or "mFocusedApp" in line:
            if focused_package is None:
                match = re.search(r"\s([A-Za-z0-9._$]+)/(?:[A-Za-z0-9._$]+)", line)
                if match:
                    focused_package = match.group(1)
            for package in packages:
                if package in line:
                    return package

    if focused_package:
        return focused_package

    return "System Home"

def get_package_name(device_id: str | None = None) -> List[str]:
    """
    Get the package name of the currently focused app.

    Args:
        device_id: Optional ADB device ID for multi-device setups.

    Returns:
        The package names of the apps if recognized.
    """
    adb_prefix = _get_adb_prefix(device_id)

    result = subprocess.run(
        adb_prefix + ["shell", "pm", "list", "packages", "-3"], capture_output=True, text=True, encoding="utf-8"
    )
    output = result.stdout
    if not output:
        raise ValueError("No output from pm list packages")
    pkgs = []
    for line in output.split("\n"):
        s = line.strip()
        if not s:
            continue
        # Strip the "package:" prefix
        if s.startswith("package:"):
            s = s[len("package:"):]
        # If the line contains "=", the right side is the package name
        if "=" in s:
            _, s = s.split("=", 1)
        if s:
            pkgs.append(s)
    return pkgs

def tap(
    x: int, y: int, device_id: str | None = None, delay: float | None = None
) -> None:
    """
    Tap at the specified coordinates.

    Args:
        x: X coordinate.
        y: Y coordinate.
        device_id: Optional ADB device ID.
        delay: Delay in seconds after tap. If None, uses configured default.
    """
    if delay is None:
        delay = TIMING_CONFIG.device.default_tap_delay

    adb_prefix = _get_adb_prefix(device_id)

    subprocess.run(
        adb_prefix + ["shell", "input", "tap", str(x), str(y)], capture_output=True
    )
    time.sleep(delay)


def double_tap(
    x: int, y: int, device_id: str | None = None, delay: float | None = None
) -> None:
    """
    Double tap at the specified coordinates.

    Args:
        x: X coordinate.
        y: Y coordinate.
        device_id: Optional ADB device ID.
        delay: Delay in seconds after double tap. If None, uses configured default.
    """
    if delay is None:
        delay = TIMING_CONFIG.device.default_double_tap_delay

    adb_prefix = _get_adb_prefix(device_id)

    subprocess.run(
        adb_prefix + ["shell", "input", "tap", str(x), str(y)], capture_output=True
    )
    time.sleep(TIMING_CONFIG.device.double_tap_interval)
    subprocess.run(
        adb_prefix + ["shell", "input", "tap", str(x), str(y)], capture_output=True
    )
    time.sleep(delay)


def long_press(
    x: int,
    y: int,
    duration_ms: int = 3000,
    device_id: str | None = None,
    delay: float | None = None,
) -> None:
    """
    Long press at the specified coordinates.

    Args:
        x: X coordinate.
        y: Y coordinate.
        duration_ms: Duration of press in milliseconds.
        device_id: Optional ADB device ID.
        delay: Delay in seconds after long press. If None, uses configured default.
    """
    if delay is None:
        delay = TIMING_CONFIG.device.default_long_press_delay

    adb_prefix = _get_adb_prefix(device_id)

    subprocess.run(
        adb_prefix
        + ["shell", "input", "swipe", str(x), str(y), str(x), str(y), str(duration_ms)],
        capture_output=True,
    )
    time.sleep(delay)


def swipe(
    start_x: int,
    start_y: int,
    end_x: int,
    end_y: int,
    duration_ms: int | None = None,
    device_id: str | None = None,
    delay: float | None = None,
) -> None:
    """
    Swipe from start to end coordinates.

    Args:
        start_x: Starting X coordinate.
        start_y: Starting Y coordinate.
        end_x: Ending X coordinate.
        end_y: Ending Y coordinate.
        duration_ms: Duration of swipe in milliseconds (auto-calculated if None).
        device_id: Optional ADB device ID.
        delay: Delay in seconds after swipe. If None, uses configured default.
    """
    if delay is None:
        delay = TIMING_CONFIG.device.default_swipe_delay

    adb_prefix = _get_adb_prefix(device_id)

    if duration_ms is None:
        # Calculate duration based on distance
        dist_sq = (start_x - end_x) ** 2 + (start_y - end_y) ** 2
        duration_ms = int(dist_sq / 1000)
        duration_ms = max(1000, min(duration_ms, 2000))  # Clamp between 1000-2000ms

    subprocess.run(
        adb_prefix
        + [
            "shell",
            "input",
            "swipe",
            str(start_x),
            str(start_y),
            str(end_x),
            str(end_y),
            str(duration_ms),
        ],
        capture_output=True,
    )
    time.sleep(delay)


def back(device_id: str | None = None, delay: float | None = None) -> None:
    """
    Press the back button.

    Args:
        device_id: Optional ADB device ID.
        delay: Delay in seconds after pressing back. If None, uses configured default.
    """
    if delay is None:
        delay = TIMING_CONFIG.device.default_back_delay

    adb_prefix = _get_adb_prefix(device_id)

    subprocess.run(
        adb_prefix + ["shell", "input", "keyevent", "4"], capture_output=True
    )
    time.sleep(delay)


def home(device_id: str | None = None, delay: float | None = None) -> None:
    """
    Press the home button.

    Args:
        device_id: Optional ADB device ID.
        delay: Delay in seconds after pressing home. If None, uses configured default.
    """
    if delay is None:
        delay = TIMING_CONFIG.device.default_home_delay

    adb_prefix = _get_adb_prefix(device_id)

    subprocess.run(
        adb_prefix + ["shell", "input", "keyevent", "KEYCODE_HOME"], capture_output=True
    )
    time.sleep(delay)


def launch_app(
    app_name: str, device_id: str | None = None, delay: float | None = None
) -> bool:
    """
    Launch an app by name.

    Args:
        app_name: The app name (must be in APP_PACKAGES).
        device_id: Optional ADB device ID.
        delay: Delay in seconds after launching. If None, uses configured default.

    Returns:
        True if app was launched, False if app not found.
    """
    if delay is None:
        delay = TIMING_CONFIG.device.default_launch_delay

    if app_name not in APP_PACKAGES:
        return False

    package = APP_PACKAGES[app_name]
    _launch_package_with_monkey(package, device_id)
    time.sleep(delay)
    return True

def launch_app_by_package(
    package: str, device_id: str | None = None, delay: float | None = None
) -> bool:
    """
    Launch an app by package name.

    Args:
        package_name: The package name of the app.
        device_id: Optional ADB device ID.
        delay: Delay in seconds after launching. If None, uses configured default.

    Returns:
        True if app was launched, False if app not found.
    """
    if delay is None:
        delay = TIMING_CONFIG.device.default_launch_delay

    _launch_package_with_monkey(package, device_id)
    time.sleep(delay)
    return True


def _launch_package_with_monkey(package: str, device_id: str | None) -> None:
    try:
        subprocess.run(
            _get_adb_prefix(device_id)
            + ["shell", "monkey", "-p", package,
               "-c", "android.intent.category.LAUNCHER", "1"],
            capture_output=True,
        )
    finally:
        relock_portrait_after_monkey(device_id)


def relock_portrait_after_monkey(device_id: str | None) -> tuple[bool, str]:
    """Undo Monkey's unconditional rotation thaw after it exits."""
    def apply(args: list[str]) -> tuple[bool, str]:
        ok, detail = run_shell_command(args, device_id=device_id, timeout=10)
        unsupported = any(marker in detail.lower() for marker in (
            "unknown command", "unrecognized command", "not supported",
        ))
        return ok and not unsupported, detail

    locked, detail = apply(["wm", "user-rotation", "lock", "0"])
    if not locked:
        locked, detail = apply(["cmd", "window", "user-rotation", "lock", "0"])
    if not locked:
        accelerator_ok, accelerator_detail = apply(
            ["settings", "put", "system", "accelerometer_rotation", "0"]
        )
        user_ok, user_detail = apply(["settings", "put", "system", "user_rotation", "0"])
        locked = accelerator_ok and user_ok
        detail = f"accelerometer_rotation: {accelerator_detail}; user_rotation: {user_detail}"

    fixed, fixed_detail = apply(["wm", "fixed-to-user-rotation", "enabled"])
    if not fixed:
        fixed, fixed_detail = apply(["cmd", "window", "fixed-to-user-rotation", "enabled"])
    if not fixed and "unknown command" not in fixed_detail.lower():
        logger.warning("fixed-to-user-rotation unavailable device_id=%s detail=%s", device_id, fixed_detail)
    if not locked:
        logger.warning("portrait relock after monkey failed device_id=%s detail=%s", device_id, detail)
    return locked, detail


def install_apk(
    apk_path: str,
    device_id: str | None = None,
    replace_existing: bool = True,
    grant_runtime_permissions: bool = False,
    allow_downgrade: bool = False,
    timeout: int = 300,
) -> Tuple[bool, str]:
    """
    Install APK to Android device.

    Args:
        apk_path: Local APK file path.
        device_id: Optional ADB device ID.
        replace_existing: Whether to replace existing app (-r).
        grant_runtime_permissions: Whether to grant runtime permissions (-g).
        allow_downgrade: Whether to allow version downgrade (-d).
        timeout: Command timeout in seconds.

    Returns:
        A tuple of (success, message).
    """
    if not apk_path or not os.path.isfile(apk_path):
        return False, f"APK file not found: {apk_path}"

    adb_prefix = _get_adb_prefix(device_id)
    command = adb_prefix + ["install"]

    if replace_existing:
        command.append("-r")
    if grant_runtime_permissions:
        command.append("-g")
    if allow_downgrade:
        command.append("-d")

    command.append(os.path.abspath(apk_path))

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
            check=False,
        )
        output = f"{result.stdout}\n{result.stderr}".strip()
        if result.returncode == 0:
            return True, output or "Success"
        return False, output or f"adb install failed with exit code {result.returncode}"
    except subprocess.TimeoutExpired:
        return False, f"adb install timeout after {timeout}s"
    except FileNotFoundError:
        return False, "adb command not found"
    except Exception as exc:
        return False, f"adb install error: {exc}"


def uninstall_apk(
    package_name: str,
    device_id: str | None = None,
    keep_data: bool = False,
    timeout: int = 120,
) -> Tuple[bool, str]:
    """
    Uninstall app by package name.

    Args:
        package_name: Android package name.
        device_id: Optional ADB device ID.
        keep_data: Whether to keep app data/cache (-k).
        timeout: Command timeout in seconds.

    Returns:
        A tuple of (success, message).
    """
    if not package_name or not package_name.strip():
        return False, "Package name is required"

    adb_prefix = _get_adb_prefix(device_id)
    command = adb_prefix + ["uninstall"]
    if keep_data:
        command.append("-k")
    command.append(package_name.strip())

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
            check=False,
        )
        output = f"{result.stdout}\n{result.stderr}".strip()
        if result.returncode == 0:
            return True, output or "Success"
        return False, output or f"adb uninstall failed with exit code {result.returncode}"
    except subprocess.TimeoutExpired:
        return False, f"adb uninstall timeout after {timeout}s"
    except FileNotFoundError:
        return False, "adb command not found"
    except Exception as exc:
        return False, f"adb uninstall error: {exc}"


def run_shell_command(
    shell_args: list[str],
    device_id: str | None = None,
    timeout: int = 30,
) -> Tuple[bool, str]:
    """
    Run an adb shell command.

    Args:
        shell_args: Command arguments after `adb shell`.
        device_id: Optional ADB device ID.
        timeout: Command timeout in seconds.

    Returns:
        A tuple of (success, message).
    """
    if not shell_args:
        return False, "shell command is required"

    adb_prefix = _get_adb_prefix(device_id)
    command = adb_prefix + ["shell", *shell_args]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
            check=False,
        )
        output = f"{result.stdout}\n{result.stderr}".strip()
        if result.returncode == 0:
            return True, output or "Success"
        return False, output or f"adb shell failed with exit code {result.returncode}"
    except subprocess.TimeoutExpired:
        return False, f"adb shell timeout after {timeout}s"
    except FileNotFoundError:
        return False, "adb command not found"
    except Exception as exc:
        return False, f"adb shell error: {exc}"


@dataclass(frozen=True)
class OrientationState:
    """Device rotation preferences saved before a dynamic trace."""

    accelerometer_rotation: str | None
    user_rotation: str | None
    window_rotation: str | None = None
    ignore_orientation_request: str | None = None
    fixed_to_user_rotation: str | None = None

    @property
    def portrait_applied(self) -> bool:
        return self.window_rotation is not None or self.accelerometer_rotation is not None


def lock_portrait_orientation(device_id: str) -> OrientationState:
    """Prefer portrait on every device; override app requests when supported."""
    saved_settings: dict[str, str] = {}
    for name in ("accelerometer_rotation", "user_rotation"):
        ok, value = run_shell_command(
            ["settings", "get", "system", name], device_id=device_id, timeout=10
        )
        if not ok:
            raise RuntimeError(f"读取设备旋转设置失败 ({name}): {value}")
        saved_settings[name] = value.strip()

    rotation_ok, rotation_output = run_shell_command(
        ["cmd", "window", "user-rotation"], device_id=device_id, timeout=10
    )
    ignore_ok, ignore_output = run_shell_command(
        ["cmd", "window", "get-ignore-orientation-request"], device_id=device_id, timeout=10
    )
    fixed_ok, fixed_output = run_shell_command(
        ["cmd", "window", "fixed-to-user-rotation"], device_id=device_id, timeout=10
    )
    fixed_mode = fixed_output.strip() if fixed_ok and fixed_output.strip() in {
        "default", "disabled", "enabled"
    } else None
    rotation = rotation_output.strip() if rotation_ok else ""
    ignore_match = re.search(r"ignoreOrientationRequest\s+(true|false)\b", ignore_output)
    has_window_override = bool(
        re.fullmatch(r"free|lock [0-3]", rotation) and ignore_ok and ignore_match
    )
    if has_window_override:
        if fixed_mode is not None:
            fixed_set_ok, fixed_set_detail = run_shell_command(
                ["cmd", "window", "fixed-to-user-rotation", "enabled"],
                device_id=device_id, timeout=10,
            )
            if not fixed_set_ok or "Unknown command" in fixed_set_detail:
                fixed_mode = None
        window_state = OrientationState(
            accelerometer_rotation=None,
            user_rotation=None,
            window_rotation=rotation,
            ignore_orientation_request=ignore_match.group(1),
            fixed_to_user_rotation=fixed_mode,
        )
        for index, command in enumerate((
            ["cmd", "window", "set-ignore-orientation-request", "true"],
            ["cmd", "window", "user-rotation", "lock", "0"],
        )):
            ok, detail = run_shell_command(command, device_id=device_id, timeout=10)
            unsupported = any(
                marker in detail.lower()
                for marker in ("unknown command", "unrecognized command", "not supported")
            )
            if not ok or unsupported:
                restored, restore_detail = restore_orientation(
                    OrientationState(
                        None, None,
                        ignore_orientation_request=ignore_match.group(1) if index == 1 else None,
                        fixed_to_user_rotation=fixed_mode,
                    ),
                    device_id,
                )
                if not restored:
                    raise RuntimeError(f"恢复设备原旋转方向失败: {restore_detail}")
                break
        else:
            return window_state

    settings_state = OrientationState(
        accelerometer_rotation=saved_settings["accelerometer_rotation"],
        user_rotation=saved_settings["user_rotation"],
    )
    changed: list[str] = []
    for name in ("accelerometer_rotation", "user_rotation"):
        command = ["settings", "put", "system", name, "0"]
        ok, detail = run_shell_command(command, device_id=device_id, timeout=10)
        if not ok:
            rollback = OrientationState(
                accelerometer_rotation=saved_settings["accelerometer_rotation"] if "accelerometer_rotation" in changed else None,
                user_rotation=saved_settings["user_rotation"] if "user_rotation" in changed else None,
            )
            restored, restore_detail = restore_orientation(rollback, device_id)
            if not restored:
                raise RuntimeError(f"恢复设备原旋转设置失败: {restore_detail}")
            if "WRITE_SETTINGS" in detail or "Permission denial" in detail:
                return OrientationState(None, None)
            raise RuntimeError(f"锁定设备竖屏失败 ({' '.join(command)}): {detail}")
        changed.append(name)
    return settings_state


def restore_orientation(state: OrientationState, device_id: str) -> tuple[bool, str]:
    """Restore the device preferences saved by lock_portrait_orientation."""
    commands: list[list[str]] = []
    if state.fixed_to_user_rotation is not None:
        commands.append(
            ["cmd", "window", "fixed-to-user-rotation", state.fixed_to_user_rotation]
        )
    if state.ignore_orientation_request is not None:
        commands.append(
            ["cmd", "window", "set-ignore-orientation-request", state.ignore_orientation_request]
        )
    if state.window_rotation is not None:
        commands.append(["cmd", "window", "user-rotation", *state.window_rotation.split()])
    for name, value in (
        ("accelerometer_rotation", state.accelerometer_rotation),
        ("user_rotation", state.user_rotation),
    ):
        if value is None:
            continue
        if value == "null":
            commands.append(["settings", "delete", "system", name])
        else:
            commands.append(["settings", "put", "system", name, value])

    errors: list[str] = []
    for command in commands:
        ok, detail = run_shell_command(command, device_id=device_id, timeout=10)
        if not ok or "Unknown command" in detail:
            errors.append(f"{' '.join(command)}: {detail}")
    return not errors, " | ".join(errors)


def reassert_portrait_orientation(state: OrientationState, device_id: str) -> tuple[bool, str]:
    """Reapply portrait if a running app or device policy changes the rotation."""
    if not state.portrait_applied:
        return True, "portrait controls unavailable"
    if state.window_rotation is not None:
        checks = [
            ["cmd", "window", "get-ignore-orientation-request"],
            ["cmd", "window", "user-rotation"],
        ]
        if state.fixed_to_user_rotation is not None:
            checks.append(["cmd", "window", "fixed-to-user-rotation"])
        values: list[str] = []
        for command in checks:
            ok, detail = run_shell_command(command, device_id=device_id, timeout=10)
            if not ok:
                return False, f"{' '.join(command)}: {detail}"
            values.append(detail.strip())
        if (
            "ignoreOrientationRequest true" in values[0]
            and values[1] == "lock 0"
            and (state.fixed_to_user_rotation is None or values[2] == "enabled")
        ):
            return True, "already portrait"
        commands = [
            ["cmd", "window", "set-ignore-orientation-request", "true"],
            ["cmd", "window", "user-rotation", "lock", "0"],
        ]
        if state.fixed_to_user_rotation is not None:
            commands.insert(0, ["cmd", "window", "fixed-to-user-rotation", "enabled"])
    else:
        values = []
        for name in ("accelerometer_rotation", "user_rotation"):
            command = ["settings", "get", "system", name]
            ok, detail = run_shell_command(command, device_id=device_id, timeout=10)
            if not ok:
                return False, f"{' '.join(command)}: {detail}"
            values.append(detail.strip())
        if values == ["0", "0"]:
            return True, "already portrait"
        commands = (
            ["settings", "put", "system", "accelerometer_rotation", "0"],
            ["settings", "put", "system", "user_rotation", "0"],
        )
    for command in commands:
        ok, detail = run_shell_command(command, device_id=device_id, timeout=10)
        if not ok:
            return False, f"{' '.join(command)}: {detail}"
    if state.window_rotation is not None:
        ok, detail = run_shell_command(
            ["cmd", "window", "user-rotation"], device_id=device_id, timeout=10
        )
        if not ok or detail.strip() != "lock 0":
            return False, f"portrait lock not retained: {detail}"
        if state.fixed_to_user_rotation is not None:
            ok, detail = run_shell_command(
                ["cmd", "window", "fixed-to-user-rotation"], device_id=device_id, timeout=10
            )
            if not ok or detail.strip() != "enabled":
                return False, f"fixed portrait policy not retained: {detail}"
    return True, "portrait reapplied"


def run_root_shell_command(
    shell_args: list[str],
    device_id: str | None = None,
    timeout: int = 30,
) -> Tuple[bool, str]:
    """
    Run an adb shell command via `su -c`.

    Args:
        shell_args: Command arguments to execute as root.
        device_id: Optional ADB device ID.
        timeout: Command timeout in seconds.

    Returns:
        A tuple of (success, message).
    """
    if not shell_args:
        return False, "root shell command is required"

    adb_prefix = _get_adb_prefix(device_id)
    quoted_args = " ".join(shlex.quote(arg) for arg in shell_args)
    command = adb_prefix + ["shell", "su", "-c", quoted_args]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=timeout,
            check=False,
        )
        output = f"{result.stdout}\n{result.stderr}".strip()
        if result.returncode == 0:
            return True, output or "Success"
        return False, output or f"adb root shell failed with exit code {result.returncode}"
    except subprocess.TimeoutExpired:
        return False, f"adb root shell timeout after {timeout}s"
    except FileNotFoundError:
        return False, "adb command not found"
    except Exception as exc:
        return False, f"adb root shell error: {exc}"


def clear_accessibility_services(
    device_id: str | None = None,
    timeout: int = 30,
) -> Tuple[bool, list[str]]:
    """
    Clear Android accessibility services and related shortcut buttons.

    Args:
        device_id: Optional ADB device ID.
        timeout: Per-command timeout in seconds.

    Returns:
        A tuple of (all_success, command_outputs).
    """
    commands = [
        ["settings", "delete", "secure", "enabled_accessibility_services"],
        ["settings", "put", "secure", "accessibility_enabled", "0"],
        ["settings", "delete", "secure", "accessibility_button_targets"],
        ["settings", "put", "secure", "accessibility_shortcut_enabled", "0"],
        ["settings", "delete", "secure", "accessibility_shortcut_target_service"],
        ["am", "force-stop", "com.google.android.marvin.talkback"],
        ["am", "force-stop", "com.microsoft.appmanager"],
    ]
    outputs: list[str] = []
    all_success = True
    for shell_args in commands:
        success, message = run_root_shell_command(shell_args, device_id=device_id, timeout=timeout)
        outputs.append(f"{'OK' if success else 'FAIL'} {' '.join(shell_args)} -> {message}")
        if not success:
            all_success = False
    return all_success, outputs


def _get_adb_prefix(device_id: str | None) -> list:
    """Get ADB command prefix with optional device specifier."""
    if device_id:
        return ["adb", "-s", device_id]
    return ["adb"]
