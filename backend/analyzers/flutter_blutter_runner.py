from __future__ import annotations

import os
import re
import secrets
import shutil
import subprocess
import sys
import zipfile
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib import util
from pathlib import Path
from typing import Any, Optional, Union

from analyzers.flutter_blutter_recovery import (
    backend_signature,
    cleanup_recovery_attempt,
    create_recovery_attempt,
    fingerprint_lock,
    prepare_isolated_tool,
    promote_backend,
)


ARM64_APP = "lib/arm64-v8a/libapp.so"
ARM64_FLUTTER = "lib/arm64-v8a/libflutter.so"
BLUTTER_BACKEND_RE = re.compile(
    r"^blutter_dartvm(?P<version>\d+(?:\.\d+){1,3})_"
    r"snapshot_(?P<snapshot>[a-z0-9.-]+)_"
    r"(?P<os>[^_]+)_(?P<arch>[^_]+)_"
    r"(?P<pointers>compressed|uncompressed)"
    r"(?P<suffix>_no-analysis)?$"
)
BLUTTER_FAILURES = (
    OSError,
    subprocess.CalledProcessError,
    RuntimeError,
    subprocess.TimeoutExpired,
)
logger = logging.getLogger(__name__)


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
    compressed_pointers: Optional[bool] = None
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


@dataclass
class _RecoveryOutcome:
    success: bool
    log_path: Path
    backend: dict[str, Any]
    command: list[str]
    error: str = ""
    backend_promoted: bool = False


def run_flutter_blutter(
    apk_path: Union[str, Path],
    file_md5: str,
    *,
    tool_root: Union[str, Path],
    output_root: Union[str, Path],
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

    output_dir = Path(output_root).expanduser() / md5 / _new_run_attempt_id()
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
    result_log_path = log_path
    try:
        _extract_flutter_libs(apk, input_dir)
        dart_info = _extract_dart_info(blutter_root, input_dir)
        backend = _select_backend(blutter_root, dart_info)
        failed_backend_signature = (
            backend_signature(_backend_executable(blutter_root, dart_info))
            if backend.get("match") == "exact"
            else None
        )
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
                    timeout_seconds=_backend_timeout(backend, timeout_seconds),
                )
            except BLUTTER_FAILURES as first_exc:
                exact_exc = first_exc
                compatible_exc: Optional[BaseException] = None
                if backend.get("match") == "compatible":
                    compatible_exc = first_exc
                    log_file.write(
                        f"\n[app_analysis] compatible backend failed: {compatible_exc}\n"
                        "[app_analysis] retrying with build_required backend\n"
                    )
                    log_file.flush()
                    _clear_blutter_output(output_dir, input_dir, log_path)
                    backend = _build_required_backend(blutter_root, dart_info)
                    failed_backend_signature = None
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
                            timeout_seconds=_backend_timeout(backend, timeout_seconds),
                        )
                        exact_exc = None
                    except BLUTTER_FAILURES as build_exc:
                        exact_exc = build_exc

                if exact_exc is not None:
                    initial_error = str(exact_exc)
                    if compatible_exc is not None:
                        initial_error = (
                            f"相近 Blutter 后端执行失败: {compatible_exc}; "
                            f"精确后端自动构建或执行失败: {exact_exc}"
                        )
                    recovery = _recover_exact_backend(
                        md5=md5,
                        output_root=Path(output_root).expanduser(),
                        output_dir=output_dir,
                        asm_dir=asm_dir,
                        input_dir=input_dir,
                        normal_log_path=log_path,
                        normal_log_file=log_file,
                        blutter_root=blutter_root,
                        dart_info=dart_info,
                        backend=backend,
                        command=command,
                        failed_backend_signature=failed_backend_signature,
                        initial_error=initial_error,
                        timeout_seconds=timeout_seconds,
                        build_docker_image=build_docker_image,
                    )
                    result_log_path = recovery.log_path
                    backend = recovery.backend
                    command = recovery.command
                    if not recovery.success:
                        return _failed_result(
                            output_dir,
                            asm_dir,
                            input_dir,
                            recovery.log_path,
                            recovery.error,
                            dart_info=dart_info,
                            backend=backend,
                            command=command,
                        )
        return FlutterBlutterRunResult(
            status="complete",
            output_dir=str(output_dir),
            asm_dir=str(asm_dir),
            input_dir=str(input_dir),
            log_path=str(result_log_path),
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


def _backend_timeout(backend: dict[str, Any], timeout_seconds: int) -> int:
    configured = max(1, int(timeout_seconds or 1))
    if backend.get("match") == "compatible":
        return min(30, configured)
    return configured


def _recover_exact_backend(
    *,
    md5: str,
    output_root: Path,
    output_dir: Path,
    asm_dir: Path,
    input_dir: Path,
    normal_log_path: Path,
    normal_log_file: Any,
    blutter_root: Path,
    dart_info: dict[str, Any],
    backend: dict[str, Any],
    command: list[str],
    failed_backend_signature: Optional[tuple[int, int, int]],
    initial_error: str,
    timeout_seconds: int,
    build_docker_image: str,
) -> _RecoveryOutcome:
    attempt = None
    recovery_file = None
    recovery_log_file = normal_log_file
    recovery_log_path = normal_log_path
    backend_promoted = False
    recovery_backend = dict(backend)
    recovery_command = list(command)
    final_status = "failed"
    final_error = initial_error

    try:
        attempt = create_recovery_attempt(output_root, md5)
        normal_log_file.flush()
        try:
            descriptor = os.open(
                str(attempt.log_path),
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
            recovery_file = os.fdopen(descriptor, "w", encoding="utf-8")
            recovery_log_file = recovery_file
            recovery_log_path = attempt.log_path
        except OSError as log_exc:
            logger.exception(
                "create flutter blutter recovery log failed md5=%s path=%s err=%s",
                md5,
                attempt.log_path,
                log_exc,
            )

        started_at = datetime.now(timezone.utc).isoformat()
        fingerprint = _backend_executable(blutter_root, dart_info).name
        _write_recovery_text(
            recovery_log_file,
            "\n[recovery]\n"
            f"md5={md5}\n"
            f"attempt_id={attempt.attempt_id}\n"
            f"started_at={started_at}\n"
            f"backend_fingerprint={fingerprint}\n"
            f"initial_backend_match={backend.get('match', '')}\n"
            "initial_status=failed\n"
            f"initial_error={initial_error}\n",
        )
        if recovery_file is not None:
            _write_recovery_text(recovery_log_file, "\n[initial_log]\n")
            try:
                initial_log = normal_log_path.read_text(encoding="utf-8", errors="replace")
            except OSError as read_exc:
                initial_log = f"[unable to read initial log: {read_exc}]\n"
            _write_recovery_text(recovery_log_file, initial_log)
        _write_recovery_text(recovery_log_file, "\n[isolated_rebuild_log]\n")

        shutil.copy2(str(input_dir / "libapp.so"), str(attempt.input_dir / "libapp.so"))
        shutil.copy2(
            str(input_dir / "libflutter.so"),
            str(attempt.input_dir / "libflutter.so"),
        )

        shared_backend = _backend_executable(blutter_root, dart_info)
        with fingerprint_lock(blutter_root, fingerprint):
            current_signature = backend_signature(shared_backend)
            reuse_shared = (
                backend.get("match") == "exact"
                and failed_backend_signature is not None
                and current_signature is not None
                and current_signature != failed_backend_signature
            )
            if reuse_shared:
                _write_recovery_text(
                    recovery_log_file,
                    "[app_analysis] shared exact backend was repaired while waiting; reusing it\n",
                )
                recovery_command = [
                    str(shared_backend.resolve()),
                    "-i",
                    str((attempt.input_dir / "libapp.so").resolve()),
                    "-o",
                    str(attempt.output_dir.resolve()),
                ]
                recovery_run_root = blutter_root
                recovery_env = _build_blutter_env(blutter_root)
            else:
                prepare_isolated_tool(blutter_root, attempt)
                isolated_backend = _build_required_backend(attempt.tool_root, dart_info)
                recovery_command = _build_blutter_command(
                    attempt.tool_root / "blutter.py",
                    attempt.input_dir,
                    attempt.output_dir,
                    isolated_backend,
                    build_docker_image=build_docker_image,
                )
                recovery_run_root = attempt.tool_root
                recovery_env = _build_blutter_env(attempt.tool_root)

            _write_recovery_text(
                recovery_log_file,
                "[app_analysis] command=" + repr(recovery_command) + "\n",
            )
            _run_blutter_command(
                recovery_command,
                asm_dir=attempt.output_dir / "asm",
                blutter_root=recovery_run_root,
                env=recovery_env,
                log_file=recovery_log_file,
                timeout_seconds=timeout_seconds,
            )

            if not reuse_shared:
                isolated_executable = _backend_executable(attempt.tool_root, dart_info)
                if isolated_executable.is_file():
                    try:
                        promote_backend(isolated_executable, shared_backend)
                        backend_promoted = True
                    except OSError as promote_exc:
                        _write_recovery_text(
                            recovery_log_file,
                            f"[app_analysis] backend promotion failed: {promote_exc}\n",
                        )

        _replace_recovered_output(
            attempt.output_dir,
            output_dir,
            input_dir,
            normal_log_path,
        )
        if not asm_dir.is_dir():
            raise RuntimeError("隔离 Blutter 恢复完成但正常输出目录缺少 asm")

        recovery_backend = {
            "version": str(dart_info.get("dart_version") or ""),
            "executable": shared_backend,
            "match": "isolated_rebuild",
        }
        final_status = "recovered"
        final_error = ""
        return _RecoveryOutcome(
            success=True,
            log_path=recovery_log_path,
            backend=recovery_backend,
            command=recovery_command,
            backend_promoted=backend_promoted,
        )
    except Exception as recovery_exc:
        final_error = f"精确后端失败: {initial_error}; 隔离重编译或重试失败: {recovery_exc}"
        return _RecoveryOutcome(
            success=False,
            log_path=recovery_log_path,
            backend=recovery_backend,
            command=recovery_command,
            error=final_error,
            backend_promoted=backend_promoted,
        )
    finally:
        _write_recovery_text(
            recovery_log_file,
            "\n[final]\n"
            f"status={final_status}\n"
            f"backend_promoted={'true' if backend_promoted else 'false'}\n"
            f"finished_at={datetime.now(timezone.utc).isoformat()}\n"
            f"final_error={final_error}\n",
        )
        if recovery_file is not None:
            try:
                recovery_file.close()
            except OSError:
                pass
        if attempt is not None:
            try:
                cleanup_recovery_attempt(attempt)
            except (OSError, ValueError) as cleanup_exc:
                logger.warning(
                    "cleanup flutter blutter recovery attempt failed md5=%s path=%s err=%s",
                    md5,
                    attempt.root,
                    cleanup_exc,
                )


def _replace_recovered_output(
    recovered_output: Path,
    output_dir: Path,
    input_dir: Path,
    normal_log_path: Path,
) -> None:
    _clear_blutter_output(output_dir, input_dir, normal_log_path)
    for path in recovered_output.iterdir():
        target = output_dir / path.name
        if target.exists():
            if target.is_dir():
                shutil.rmtree(str(target))
            else:
                target.unlink()
        shutil.move(str(path), str(target))


def _write_recovery_text(log_file: Any, text: str) -> None:
    try:
        log_file.write(text)
        log_file.flush()
    except (AttributeError, OSError, ValueError) as log_exc:
        logger.warning("write flutter blutter recovery log failed err=%s", log_exc)


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


def _nearest_compatible_backend(
    blutter_root: Path, dart_info: dict[str, Any]
) -> Optional[dict[str, Any]]:
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
        input_root = input_dir.resolve()
        return [
            "docker",
            "run",
            "--rm",
            "--volume",
            f"{blutter_root}:{blutter_root}",
            "--volume",
            f"{output_root}:{output_root}",
            "--volume",
            f"{input_root}:{input_root}",
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


def _new_run_attempt_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    return f"{timestamp}-{os.getpid()}-{secrets.token_hex(3)}"


def _failed_result(
    output_dir: Path,
    asm_dir: Path,
    input_dir: Path,
    log_path: Path,
    error: str,
    *,
    dart_info: Optional[dict[str, Any]] = None,
    backend: Optional[dict[str, Any]] = None,
    command: Optional[list[str]] = None,
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
