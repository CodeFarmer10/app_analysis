from __future__ import annotations

import os
import re
import subprocess
import sys
import zipfile
from dataclasses import dataclass, field
from importlib import util
from pathlib import Path
from typing import Any


ARM64_APP = "lib/arm64-v8a/libapp.so"
ARM64_FLUTTER = "lib/arm64-v8a/libflutter.so"
BLUTTER_BACKEND_RE = re.compile(
    r"^blutter_dartvm(?P<version>\d+(?:\.\d+){1,3})_"
    r"(?P<os>[^_]+)_(?P<arch>[^_]+)(?P<suffix>.*)$"
)


@dataclass
class FlutterBlutterRunResult:
    status: str
    output_dir: str = ""
    asm_dir: str = ""
    input_dir: str = ""
    log_path: str = ""
    dart_version: str = ""
    snapshot_hash: str = ""
    target_arch: str = ""
    target_os: str = ""
    compressed_pointers: bool | None = None
    backend_version: str = ""
    backend_executable: str = ""
    backend_match: str = ""
    error: str = ""
    command: list[str] = field(default_factory=list)

    def to_static_fields(self) -> dict[str, Any]:
        return {
            "blutter_status": self.status,
            "blutter_output_dir": self.output_dir,
            "blutter_asm_dir": self.asm_dir,
            "blutter_input_dir": self.input_dir,
            "blutter_log_path": self.log_path,
            "dart_version": self.dart_version,
            "snapshot_hash": self.snapshot_hash,
            "target_arch": self.target_arch,
            "target_os": self.target_os,
            "compressed_pointers": self.compressed_pointers,
            "blutter_backend_version": self.backend_version,
            "blutter_backend_executable": self.backend_executable,
            "blutter_backend_match": self.backend_match,
            "blutter_error": self.error,
        }


def run_flutter_blutter(
    apk_path: str | Path,
    file_md5: str,
    *,
    tool_root: str | Path,
    output_root: str | Path,
    timeout_seconds: int,
) -> FlutterBlutterRunResult:
    md5 = str(file_md5 or "").strip().lower()
    if not md5:
        return FlutterBlutterRunResult(status="error", error="缺少 APP MD5，无法生成 Flutter asm")

    apk = Path(apk_path)
    if not apk.is_file():
        return FlutterBlutterRunResult(status="error", error=f"APK 文件不存在: {apk}")

    blutter_root = Path(tool_root).expanduser()
    blutter_script = blutter_root / "blutter.py"
    if not blutter_script.is_file():
        return FlutterBlutterRunResult(status="error", error=f"Blutter 脚本不存在: {blutter_script}")

    output_dir = Path(output_root).expanduser() / md5
    asm_dir = output_dir / "asm"
    input_dir = output_dir / "input"
    log_path = output_dir / "blutter.log"
    if asm_dir.is_dir() and (output_dir / "pp.txt").is_file():
        return FlutterBlutterRunResult(
            status="cached",
            output_dir=str(output_dir),
            asm_dir=str(asm_dir),
            input_dir=str(input_dir),
            log_path=str(log_path),
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    input_dir.mkdir(parents=True, exist_ok=True)

    try:
        _extract_flutter_libs(apk, input_dir)
        dart_info = _extract_dart_info(blutter_root, input_dir)
        backend = _select_backend(blutter_root, dart_info)
        command = _build_blutter_command(
            blutter_script,
            input_dir,
            output_dir,
            backend,
        )
        env = _build_blutter_env(blutter_root)
        with log_path.open("w", encoding="utf-8") as log_file:
            subprocess.run(
                command,
                cwd=str(_tool_workspace(blutter_root)),
                env=env,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                timeout=max(1, int(timeout_seconds or 1)),
                check=True,
            )
        if not asm_dir.is_dir():
            raise RuntimeError("Blutter 执行完成但未生成 asm 目录")
        return FlutterBlutterRunResult(
            status="complete",
            output_dir=str(output_dir),
            asm_dir=str(asm_dir),
            input_dir=str(input_dir),
            log_path=str(log_path),
            dart_version=dart_info["dart_version"],
            snapshot_hash=dart_info["snapshot_hash"],
            target_arch=dart_info["target_arch"],
            target_os=dart_info["target_os"],
            compressed_pointers=dart_info["compressed_pointers"],
            backend_version=backend["version"],
            backend_executable=str(backend["executable"]),
            backend_match=str(backend["match"]),
            command=command,
        )
    except subprocess.TimeoutExpired as exc:
        return _failed_result(output_dir, asm_dir, input_dir, log_path, f"Blutter 执行超时: {exc}")
    except (OSError, subprocess.CalledProcessError, RuntimeError, zipfile.BadZipFile, KeyError, AssertionError) as exc:
        return _failed_result(output_dir, asm_dir, input_dir, log_path, str(exc))


def _extract_flutter_libs(apk: Path, input_dir: Path) -> None:
    app_file = input_dir / "libapp.so"
    flutter_file = input_dir / "libflutter.so"
    if app_file.is_file() and flutter_file.is_file():
        return
    with zipfile.ZipFile(apk) as archive:
        for member, target in ((ARM64_APP, app_file), (ARM64_FLUTTER, flutter_file)):
            with archive.open(member) as source, target.open("wb") as destination:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    destination.write(chunk)


def _extract_dart_info(blutter_root: Path, input_dir: Path) -> dict[str, Any]:
    module_path = blutter_root / "extract_dart_info.py"
    spec = util.spec_from_file_location(f"_app_analysis_extract_dart_info_{id(module_path)}", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"无法加载 Dart 信息提取脚本: {module_path}")
    module = util.module_from_spec(spec)
    spec.loader.exec_module(module)
    dart_version, snapshot_hash, flags, arch, os_name = module.extract_dart_info(
        str(input_dir / "libapp.so"),
        str(input_dir / "libflutter.so"),
    )
    return {
        "dart_version": str(dart_version or ""),
        "snapshot_hash": str(snapshot_hash or ""),
        "target_arch": str(arch or ""),
        "target_os": str(os_name or ""),
        "compressed_pointers": "compressed-pointers" in set(flags or []),
    }


def _backend_executable(blutter_root: Path, dart_info: dict[str, Any]) -> Path:
    suffix = ""
    if dart_info["compressed_pointers"] is False:
        suffix += "_no-compressed-ptrs"
    version = str(dart_info["dart_version"])
    if version.startswith("2.10.") or version.startswith("2.11.") or version.startswith("2.12.") or version.startswith("2.13.") or version.startswith("2.14."):
        suffix += "_no-analysis"
    return blutter_root / "bin" / f"blutter_dartvm{version}_{dart_info['target_os']}_{dart_info['target_arch']}{suffix}"


def _select_backend(blutter_root: Path, dart_info: dict[str, Any]) -> dict[str, Any]:
    exact = _backend_executable(blutter_root, dart_info)
    actual_version = str(dart_info["dart_version"])
    if exact.is_file():
        return {
            "version": actual_version,
            "executable": exact,
            "match": "exact",
            "use_dart_version_arg": False,
        }

    compatible = _nearest_compatible_backend(blutter_root, dart_info)
    if compatible is not None:
        return {
            "version": compatible["version"],
            "executable": compatible["path"],
            "match": "compatible",
            "use_dart_version_arg": True,
        }

    return {
        "version": actual_version,
        "executable": exact,
        "match": "build_required",
        "use_dart_version_arg": False,
    }


def _nearest_compatible_backend(blutter_root: Path, dart_info: dict[str, Any]) -> dict[str, Any] | None:
    if dart_info["compressed_pointers"] is not True:
        return None
    actual = _version_tuple(str(dart_info["dart_version"]))
    if not actual:
        return None
    candidates = []
    for path in (blutter_root / "bin").glob("blutter_dartvm*"):
        match = BLUTTER_BACKEND_RE.match(path.name)
        if not match or match.group("suffix"):
            continue
        if match.group("os") != dart_info["target_os"] or match.group("arch") != dart_info["target_arch"]:
            continue
        version = _version_tuple(match.group("version"))
        if not version or version[0] != actual[0]:
            continue
        candidates.append(
            {
                "version": match.group("version"),
                "path": path,
                "distance": _version_distance(actual, version),
                "parsed_version": version,
            }
        )
    if not candidates:
        return None
    return min(candidates, key=lambda item: (item["distance"], _version_sort_key(item["parsed_version"])))


def _build_blutter_command(
    blutter_script: Path,
    input_dir: Path,
    output_dir: Path,
    backend: dict[str, Any],
) -> list[str]:
    command = [sys.executable, str(blutter_script)]
    if backend["use_dart_version_arg"]:
        command.extend(
            [
                str(input_dir / "libapp.so"),
                str(output_dir),
                "--dart-version",
                _dart_version_arg(str(backend["version"]), Path(str(backend["executable"]))),
            ]
        )
    else:
        command.extend([str(input_dir), str(output_dir)])
    return command


def _dart_version_arg(version: str, backend_executable: Path) -> str:
    match = BLUTTER_BACKEND_RE.match(backend_executable.name)
    if match:
        return f"{version}_{match.group('os')}_{match.group('arch')}"
    return version


def _version_tuple(version: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError:
        return ()


def _version_distance(left: tuple[int, ...], right: tuple[int, ...]) -> tuple[int, ...]:
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))
    return tuple(abs(a - b) for a, b in zip(padded_left, padded_right))


def _version_sort_key(version: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(-part for part in version)


def _build_blutter_env(blutter_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    python_bin = str(Path(sys.executable).resolve().parent)
    extra_python_bin = str(Path.home() / "Library/Python/3.13/bin")
    env["PATH"] = os.pathsep.join([python_bin, extra_python_bin, env.get("PATH", "")])
    env["PKG_CONFIG_PATH"] = os.pathsep.join(
        [str(blutter_root / "pkgconfig"), env.get("PKG_CONFIG_PATH", "")]
    ).rstrip(os.pathsep)
    env["DYLD_LIBRARY_PATH"] = os.pathsep.join(
        [str(blutter_root / "capstone" / "lib"), env.get("DYLD_LIBRARY_PATH", "")]
    ).rstrip(os.pathsep)
    return env


def _tool_workspace(blutter_root: Path) -> Path:
    return blutter_root.resolve().parent


def _failed_result(output_dir: Path, asm_dir: Path, input_dir: Path, log_path: Path, error: str) -> FlutterBlutterRunResult:
    return FlutterBlutterRunResult(
        status="failed",
        output_dir=str(output_dir),
        asm_dir=str(asm_dir),
        input_dir=str(input_dir),
        log_path=str(log_path),
        error=error[:1000],
    )
