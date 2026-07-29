from __future__ import annotations

import os
import re
import shutil
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
    r"snapshot_(?P<snapshot>[a-z0-9.-]+)_"
    r"(?P<os>[^_]+)_(?P<arch>[^_]+)_"
    r"(?P<pointers>compressed|uncompressed)"
    r"(?P<suffix>_no-analysis)?$"
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
    build_docker_image: str = "",
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

    dart_info: dict[str, Any] = {}
    backend: dict[str, Any] = {}
    command: list[str] = []
    try:
        _extract_flutter_libs(apk, input_dir)
        dart_info = _extract_dart_info(blutter_root, input_dir)
        backend = _select_backend(blutter_root, dart_info)
        command = _build_blutter_command(
            blutter_script,
            input_dir,
            output_dir,
            backend,
            build_docker_image=build_docker_image,
        )
        env = _build_blutter_env(blutter_root)
        with log_path.open("w", encoding="utf-8") as log_file:
            try:
                _run_blutter_command(
                    command,
                    asm_dir=asm_dir,
                    blutter_root=blutter_root,
                    env=env,
                    log_file=log_file,
                    timeout_seconds=timeout_seconds,
                )
            except (OSError, subprocess.CalledProcessError, RuntimeError, subprocess.TimeoutExpired) as compatible_exc:
                if backend.get("match") != "compatible":
                    raise
                log_file.write(
                    f"\n[app_analysis] compatible backend failed: {compatible_exc}\n"
                    "[app_analysis] retrying with build_required backend\n"
                )
                log_file.flush()
                _clear_blutter_output(output_dir, input_dir, log_path)
                backend = _build_required_backend(blutter_root, dart_info)
                command = _build_blutter_command(
                    blutter_script,
                    input_dir,
                    output_dir,
                    backend,
                    build_docker_image=build_docker_image,
                )
                try:
                    _run_blutter_command(
                        command,
                        asm_dir=asm_dir,
                        blutter_root=blutter_root,
                        env=env,
                        log_file=log_file,
                        timeout_seconds=timeout_seconds,
                    )
                except (OSError, subprocess.CalledProcessError, RuntimeError, subprocess.TimeoutExpired) as build_exc:
                    raise RuntimeError(
                        f"相近 Blutter 后端执行失败: {compatible_exc}; "
                        f"精确后端自动构建或执行失败: {build_exc}"
                    ) from build_exc
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
        return _failed_result(
            output_dir,
            asm_dir,
            input_dir,
            log_path,
            f"Blutter 执行超时: {exc}",
            dart_info=dart_info,
            backend=backend,
            command=command,
        )
    except (OSError, subprocess.CalledProcessError, RuntimeError, zipfile.BadZipFile, KeyError, AssertionError) as exc:
        return _failed_result(
            output_dir,
            asm_dir,
            input_dir,
            log_path,
            str(exc),
            dart_info=dart_info,
            backend=backend,
            command=command,
        )


def _run_blutter_command(
    command: list[str],
    *,
    asm_dir: Path,
    blutter_root: Path,
    env: dict[str, str],
    log_file: Any,
    timeout_seconds: int,
) -> None:
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


def _clear_blutter_output(output_dir: Path, input_dir: Path, log_path: Path) -> None:
    for path in output_dir.iterdir():
        if path == input_dir or path == log_path:
            continue
        if path.is_dir():
            shutil.rmtree(path, ignore_errors=True)
        else:
            path.unlink(missing_ok=True)


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
    version = str(dart_info["dart_version"])
    snapshot_hash = _snapshot_cache_token(dart_info.get("snapshot_hash"))
    pointer_mode = _pointer_mode(dart_info.get("compressed_pointers"))
    suffix = "_no-analysis" if _requires_no_analysis(version) else ""
    name = (
        f"blutter_dartvm{version}_snapshot_{snapshot_hash}_"
        f"{dart_info['target_os']}_{dart_info['target_arch']}_{pointer_mode}{suffix}"
    )
    return blutter_root / "bin" / name


def _select_backend(blutter_root: Path, dart_info: dict[str, Any]) -> dict[str, Any]:
    if not str(dart_info.get("snapshot_hash") or "").strip():
        raise RuntimeError("缺少 Snapshot Hash，无法选择 Blutter 后端")

    exact = _backend_executable(blutter_root, dart_info)
    actual_version = str(dart_info["dart_version"])
    if exact.is_file():
        return {
            "version": actual_version,
            "executable": exact,
            "match": "exact",
        }

    compatible = _nearest_compatible_backend(blutter_root, dart_info)
    if compatible is not None:
        return {
            "version": compatible["version"],
            "executable": compatible["path"],
            "match": "compatible",
        }

    return _build_required_backend(blutter_root, dart_info)


def _build_required_backend(blutter_root: Path, dart_info: dict[str, Any]) -> dict[str, Any]:
    actual_version = str(dart_info["dart_version"])
    return {
        "version": actual_version,
        "executable": _backend_executable(blutter_root, dart_info),
        "match": "build_required",
    }


def _nearest_compatible_backend(blutter_root: Path, dart_info: dict[str, Any]) -> dict[str, Any] | None:
    actual = _version_tuple(str(dart_info["dart_version"]))
    if not actual:
        return None
    snapshot_hash = _snapshot_cache_token(dart_info.get("snapshot_hash"))
    pointer_mode = _pointer_mode(dart_info.get("compressed_pointers"))
    expected_suffix = "_no-analysis" if _requires_no_analysis(str(dart_info["dart_version"])) else None
    candidates = []
    for path in (blutter_root / "bin").glob("blutter_dartvm*"):
        match = BLUTTER_BACKEND_RE.match(path.name)
        if not match:
            continue
        if match.group("os") != dart_info["target_os"] or match.group("arch") != dart_info["target_arch"]:
            continue
        if match.group("snapshot") != snapshot_hash or match.group("pointers") != pointer_mode:
            continue
        if match.group("suffix") != expected_suffix:
            continue
        version = _version_tuple(match.group("version"))
        if not version:
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
    *,
    build_docker_image: str = "",
) -> list[str]:
    image = str(build_docker_image or "").strip()
    if backend["match"] == "compatible":
        return [
            str(Path(str(backend["executable"])).resolve()),
            "-i",
            str((input_dir / "libapp.so").resolve()),
            "-o",
            str(output_dir.resolve()),
        ]

    if backend["match"] == "build_required" and image:
        blutter_root = blutter_script.parent.resolve()
        output_root = output_dir.resolve()
        return [
            "docker",
            "run",
            "--rm",
            "--volume",
            f"{blutter_root}:{blutter_root}",
            "--volume",
            f"{output_root}:{output_root}",
            "--workdir",
            str(_tool_workspace(blutter_root)),
            "--env",
            "BLUTTER_STATIC_LINK=1",
            image,
            "python3",
            str(blutter_script.resolve()),
            str(input_dir.resolve()),
            str(output_root),
        ]

    return [sys.executable, str(blutter_script), str(input_dir), str(output_dir)]


def _snapshot_cache_token(snapshot_hash: object) -> str:
    value = str(snapshot_hash or "").strip().lower()
    return re.sub(r"[^a-z0-9.-]+", "-", value).strip("-") or "unknown"


def _pointer_mode(compressed_pointers: object) -> str:
    return "compressed" if compressed_pointers is True else "uncompressed"


def _requires_no_analysis(version: str) -> bool:
    parsed = _version_tuple(version)
    return bool(parsed and parsed[0] == 2 and len(parsed) > 1 and parsed[1] < 15)


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


def _failed_result(
    output_dir: Path,
    asm_dir: Path,
    input_dir: Path,
    log_path: Path,
    error: str,
    *,
    dart_info: dict[str, Any] | None = None,
    backend: dict[str, Any] | None = None,
    command: list[str] | None = None,
) -> FlutterBlutterRunResult:
    dart_info = dart_info or {}
    backend = backend or {}
    return FlutterBlutterRunResult(
        status="failed",
        output_dir=str(output_dir),
        asm_dir=str(asm_dir),
        input_dir=str(input_dir),
        log_path=str(log_path),
        dart_version=str(dart_info.get("dart_version") or ""),
        snapshot_hash=str(dart_info.get("snapshot_hash") or ""),
        target_arch=str(dart_info.get("target_arch") or ""),
        target_os=str(dart_info.get("target_os") or ""),
        compressed_pointers=dart_info.get("compressed_pointers"),
        backend_version=str(backend.get("version") or ""),
        backend_executable=str(backend.get("executable") or ""),
        backend_match=str(backend.get("match") or ""),
        error=error[:1000],
        command=command or [],
    )
