from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from protection.dex_filter import analyze_and_filter_dex, copy_repaired_dex_files, pkg_to_prefixes


FRIDA_SERVER_REMOTE_PATH = "/data/local/tmp/frida-server"


@dataclass
class UnpackResult:
    archive_file: str | None = None
    clean_dir: str | None = None
    raw_dex_count: int = 0
    kept_dex_count: int = 0
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return bool(self.archive_file) and self.kept_dex_count > 0


def unpack_to_archive(
    task_id: str,
    package_name: str,
    device_serial: str,
    result_dir: Path,
    launch_wait_seconds: int = 20,
    timeout_seconds: int = 300,
) -> UnpackResult:
    """Dump packed app dex files, repair/filter them, and zip the local result directory."""
    unpack_root = result_dir / "unpack"
    raw_dir = unpack_root / "raw"
    clean_dir = unpack_root / "clean"
    raw_dir.mkdir(parents=True, exist_ok=True)
    clean_dir.mkdir(parents=True, exist_ok=True)

    notes: list[str] = []
    if not _frida_dexdump_command():
        raise RuntimeError("未找到 frida-dexdump，请安装 frida-dexdump")

    if not _is_frida_server_running(device_serial):
        _start_frida_server(device_serial)
    if not _is_frida_server_running(device_serial):
        raise RuntimeError("设备端 frida-server 未运行，无法执行脱壳")

    _launch_app(package_name, device_serial)
    time.sleep(max(0, launch_wait_seconds))
    pid = _get_app_pid(package_name, device_serial)
    if pid is None:
        raise RuntimeError(f"未获取到目标进程 PID: {package_name}")

    dump_result = _run_frida_dexdump(
        package_name=package_name,
        device_serial=device_serial,
        pid=pid,
        output_dir=raw_dir,
        timeout_seconds=timeout_seconds,
    )
    raw_dex_files = _collect_dex_files(raw_dir)
    if not raw_dex_files:
        raise RuntimeError(
            f"脱壳未产出 dex: returncode={dump_result.returncode} stderr={dump_result.stderr[:500]}"
        )

    filter_result = analyze_and_filter_dex(raw_dex_files, pkg_to_prefixes(package_name))
    valid_infos = [info for info in filter_result.infos if info.valid]
    kept_files = copy_repaired_dex_files(filter_result.kept or valid_infos or filter_result.infos, str(clean_dir))
    if not kept_files:
        raise RuntimeError("脱壳产物过滤后没有可归档 dex")

    metadata = {
        "task_id": task_id,
        "package_name": package_name,
        "device_serial": device_serial,
        "pid": pid,
        "raw_dex_count": len(raw_dex_files),
        "kept_dex_count": len(kept_files),
        "duplicates_removed_count": len(filter_result.duplicates_removed),
        "framework_removed_count": len(filter_result.framework_removed),
        "invalid_dex_count": len(filter_result.invalid),
        "returncode": dump_result.returncode,
        "stdout": dump_result.stdout[-4000:],
        "stderr": dump_result.stderr[-4000:],
        "notes": notes,
    }
    (unpack_root / "metadata.json").write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")

    archive_base = result_dir / f"{task_id}-unpack"
    archive_file = shutil.make_archive(str(archive_base), "zip", root_dir=str(unpack_root))

    return UnpackResult(
        archive_file=archive_file,
        clean_dir=str(clean_dir),
        raw_dex_count=len(raw_dex_files),
        kept_dex_count=len(kept_files),
        returncode=dump_result.returncode,
        stdout=dump_result.stdout,
        stderr=dump_result.stderr,
        notes=notes,
    )


@dataclass
class _DumpProcessResult:
    returncode: int
    stdout: str
    stderr: str


def _frida_dexdump_command() -> list[str]:
    binary = shutil.which("frida-dexdump")
    if binary:
        return [binary]
    try:
        import importlib.util

        if importlib.util.find_spec("frida_dexdump") is not None:
            return [sys.executable, "-m", "frida_dexdump"]
    except Exception:
        return []
    return []


def _adb_prefix(device_serial: str) -> list[str]:
    return ["adb", "-s", device_serial]


def _run_adb(device_serial: str, args: list[str], timeout: int = 30) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        _adb_prefix(device_serial) + args,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _is_frida_server_running(device_serial: str) -> bool:
    result = _run_adb(device_serial, ["shell", "su", "-c", "pidof frida-server"], timeout=10)
    return result.returncode == 0 and bool(result.stdout.strip())


def _start_frida_server(device_serial: str) -> None:
    _run_adb(device_serial, ["shell", "su", "-c", f"chmod 755 {FRIDA_SERVER_REMOTE_PATH}"], timeout=10)
    # Some su implementations keep adb open for background processes; a timeout still means the command was sent.
    try:
        _run_adb(
            device_serial,
            ["shell", "su", "-c", f"nohup {FRIDA_SERVER_REMOTE_PATH} >/dev/null 2>&1 &"],
            timeout=8,
        )
    except subprocess.TimeoutExpired:
        pass
    time.sleep(5)


def _launch_app(package_name: str, device_serial: str) -> None:
    _run_adb(device_serial, ["shell", "am", "force-stop", package_name], timeout=20)
    result = _run_adb(
        device_serial,
        ["shell", "monkey", "-p", package_name, "-c", "android.intent.category.LAUNCHER", "1"],
        timeout=30,
    )
    if "Events injected" not in (result.stdout or ""):
        raise RuntimeError(f"启动 APP 失败: {(result.stdout + result.stderr).strip()[:500]}")


def _get_app_pid(package_name: str, device_serial: str) -> int | None:
    result = _run_adb(device_serial, ["shell", "pidof", package_name], timeout=15)
    tokens = result.stdout.strip().split()
    if not tokens:
        return None
    try:
        return int(tokens[0])
    except ValueError:
        return None


def _run_frida_dexdump(
    package_name: str,
    device_serial: str,
    pid: int,
    output_dir: Path,
    timeout_seconds: int,
) -> _DumpProcessResult:
    cmd = [
        *_frida_dexdump_command(),
        "-D",
        device_serial,
        "-p",
        str(pid),
        "-d",
        "-o",
        str(output_dir),
    ]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        returncode = process.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()
        try:
            stdout, stderr = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            stdout, stderr = "", ""
        returncode = process.returncode if process.returncode is not None else 0

    if timed_out:
        stderr = (stderr or "") + f"\nfrida-dexdump timeout after {timeout_seconds}s for {package_name}"
    return _DumpProcessResult(returncode=returncode or 0, stdout=stdout or "", stderr=stderr or "")


def _collect_dex_files(root: Path) -> list[str]:
    dex_files: list[str] = []
    for current_root, _dirs, files in os.walk(root):
        for file_name in files:
            if file_name.endswith(".dex"):
                dex_files.append(str(Path(current_root) / file_name))
    return sorted(dex_files)
