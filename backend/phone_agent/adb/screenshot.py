"""Screenshot utilities for capturing Android device screen."""

import base64
import os
import re
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from io import BytesIO

from PIL import Image


@dataclass
class Screenshot:
    """Represents a captured screenshot."""
    base64_data: str
    width: int
    height: int
    is_sensitive: bool = False
    path: str = ""


def get_screenshot(device_id: str | None = None, screenshot_dir: str | None = None, timeout: int = 10) -> Screenshot:
    """
    Capture a screenshot from the connected Android device.

    Args:
        device_id: Optional ADB device ID for multi-device setups.
        screenshot_dir: Optional directory to store the screenshot.
        timeout: Timeout in seconds for screenshot operations.

    Returns:
        Screenshot object containing base64 data and dimensions.

    Note:
        If the screenshot fails (e.g., on sensitive screens like payment pages),
        a black fallback image is returned with is_sensitive=True.
    """
    save_dir = screenshot_dir if screenshot_dir else tempfile.gettempdir()
    temp_path = os.path.join(save_dir, f"screenshot_{uuid.uuid4()}.png")
    adb_prefix = _get_adb_prefix(device_id)

    try:
        display_id = _detect_primary_display_id(adb_prefix, timeout)
        result = _capture_remote_screenshot(adb_prefix, display_id, timeout)

        if _command_failed(result) and display_id:
            result = _capture_remote_screenshot(adb_prefix, None, timeout)

        if _command_failed(result):
            return _create_fallback_screenshot(is_sensitive=True)

        pull_result = _run_adb_command(
            adb_prefix + ["pull", "/sdcard/tmp.png", temp_path],
            timeout=5,
        )

        if pull_result.returncode != 0:
            return _create_fallback_screenshot(is_sensitive=False)

        if not os.path.exists(temp_path):
            return _create_fallback_screenshot(is_sensitive=False)

        # Read and encode image
        img = Image.open(temp_path)
        width, height = img.size

        buffered = BytesIO()
        img.save(buffered, format="PNG")
        base64_data = base64.b64encode(buffered.getvalue()).decode("utf-8")

        # Cleanup
        if not screenshot_dir:
            os.remove(temp_path)
        return Screenshot(
            path=temp_path, base64_data=base64_data, width=width, height=height, is_sensitive=False
        )

    except Exception as e:
        print(f"Screenshot error: {e}")
        return _create_fallback_screenshot(is_sensitive=False)


def _get_adb_prefix(device_id: str | None) -> list:
    """Get ADB command prefix with optional device specifier."""
    if device_id:
        return ["adb", "-s", device_id]
    return ["adb"]


def _run_adb_command(command: list[str], timeout: int) -> subprocess.CompletedProcess:
    """Execute an adb command with consistent subprocess settings."""
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _detect_primary_display_id(adb_prefix: list[str], timeout: int) -> str | None:
    """Detect the real primary display id from SurfaceFlinger."""
    try:
        result = _run_adb_command(
            adb_prefix + ["shell", "dumpsys", "SurfaceFlinger", "--display-id"],
            timeout=timeout,
        )
    except Exception:
        return None

    if result.returncode != 0:
        return None

    display_matches = re.findall(r"Display\s+(\d+)\s+\(HWC display\s+(\d+)\)", result.stdout)
    for display_id, hwc_display in display_matches:
        if hwc_display == "0":
            return display_id

    if display_matches:
        return display_matches[0][0]

    return None


def _capture_remote_screenshot(
    adb_prefix: list[str],
    display_id: str | None,
    timeout: int,
) -> subprocess.CompletedProcess:
    """Capture screenshot to a remote temp file, optionally targeting a display id."""
    command = adb_prefix + ["shell", "screencap", "-p"]
    if display_id:
        command.extend(["-d", display_id])
    command.append("/sdcard/tmp.png")
    return _run_adb_command(command, timeout=timeout)


def _command_failed(result: subprocess.CompletedProcess) -> bool:
    """Detect screencap failure messages reported by adb."""
    output = f"{result.stdout}{result.stderr}"
    return result.returncode != 0 or "Status: -1" in output or "Failed" in output


def _create_fallback_screenshot(is_sensitive: bool) -> Screenshot:
    """Create a black fallback image when screenshot fails."""
    default_width, default_height = 1080, 2400

    black_img = Image.new("RGB", (default_width, default_height), color="black")
    buffered = BytesIO()
    black_img.save(buffered, format="PNG")
    base64_data = base64.b64encode(buffered.getvalue()).decode("utf-8")

    return Screenshot(
        base64_data=base64_data,
        width=default_width,
        height=default_height,
        is_sensitive=is_sensitive,
    )
