from __future__ import annotations

import os
import re
import secrets
import shutil
import stat
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator, Optional, Tuple

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None


ISOLATED_FILES = ("blutter.py", "dartvm_fetch_build.py", "extract_dart_info.py")
ISOLATED_DIRS = ("blutter", "scripts", "pkgconfig", "capstone")
CLEAN_DIRS = ("bin", "build", "dartsdk", "packages")

_THREAD_LOCK_GUARD = threading.Lock()
_THREAD_LOCKS: dict[str, threading.Lock] = {}


@dataclass(frozen=True)
class RecoveryAttempt:
    md5: str
    attempt_id: str
    root: Path
    tool_root: Path
    input_dir: Path
    output_dir: Path
    log_path: Path


def create_recovery_attempt(output_root: Path, md5: str) -> RecoveryAttempt:
    root = Path(output_root).expanduser().resolve()
    safe_md5 = _safe_token(str(md5 or "").strip().lower())
    if not safe_md5:
        raise ValueError("缺少有效 APP MD5，无法创建 Blutter 恢复目录")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    attempt_id = f"{timestamp}-{os.getpid()}-{secrets.token_hex(3)}"
    attempt_root = root.with_name(root.name + "_rebuild") / safe_md5 / attempt_id
    log_path = root.with_name(root.name + "_failures") / safe_md5 / f"{attempt_id}.log"
    input_dir = attempt_root / "input"
    output_dir = attempt_root / "output"
    input_dir.mkdir(parents=True, exist_ok=False)
    output_dir.mkdir(parents=True, exist_ok=False)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    return RecoveryAttempt(
        md5=safe_md5,
        attempt_id=attempt_id,
        root=attempt_root,
        tool_root=attempt_root / "tool",
        input_dir=input_dir,
        output_dir=output_dir,
        log_path=log_path,
    )


def prepare_isolated_tool(source_root: Path, attempt: RecoveryAttempt) -> None:
    source = Path(source_root).resolve()
    attempt.tool_root.mkdir(parents=True, exist_ok=False)

    for name in ISOLATED_FILES:
        source_path = source / name
        if not source_path.is_file():
            raise FileNotFoundError(f"隔离重编译缺少 Blutter 文件: {source_path}")
        shutil.copy2(str(source_path), str(attempt.tool_root / name))

    for name in ISOLATED_DIRS:
        source_path = source / name
        if not source_path.is_dir():
            raise FileNotFoundError(f"隔离重编译缺少 Blutter 目录: {source_path}")
        shutil.copytree(
            str(source_path),
            str(attempt.tool_root / name),
            symlinks=True,
        )

    for name in CLEAN_DIRS:
        (attempt.tool_root / name).mkdir()


def backend_signature(path: Path) -> Optional[Tuple[int, int, int]]:
    candidate = Path(path)
    try:
        details = candidate.stat()
    except OSError:
        return None
    if not candidate.is_file():
        return None
    return details.st_ino, details.st_mtime_ns, details.st_size


@contextmanager
def fingerprint_lock(tool_root: Path, fingerprint: str) -> Iterator[None]:
    safe_fingerprint = _safe_token(fingerprint) or "unknown"
    with _THREAD_LOCK_GUARD:
        thread_lock = _THREAD_LOCKS.setdefault(safe_fingerprint, threading.Lock())

    with thread_lock:
        lock_dir = Path(tool_root).resolve() / "build" / ".recovery-locks"
        lock_dir.mkdir(parents=True, exist_ok=True)
        lock_path = lock_dir / f"{safe_fingerprint}.lock"
        with lock_path.open("a+b") as lock_file:
            if fcntl is not None:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def promote_backend(source: Path, target: Path) -> None:
    source_path = Path(source)
    target_path = Path(target)
    if not source_path.is_file():
        raise FileNotFoundError(f"隔离后端不存在: {source_path}")

    target_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=target_path.name + ".recovery-",
        dir=str(target_path.parent),
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        shutil.copy2(str(source_path), str(temporary))
        temporary.chmod(temporary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        os.replace(str(temporary), str(target_path))
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def cleanup_recovery_attempt(attempt: RecoveryAttempt) -> None:
    candidate = attempt.root.resolve()
    if candidate.name != attempt.attempt_id or candidate.parent.name != attempt.md5:
        raise ValueError(f"拒绝清理非 Blutter attempt 目录: {candidate}")
    if not candidate.parent.parent.name.endswith("_rebuild"):
        raise ValueError(f"拒绝清理恢复根之外的目录: {candidate}")
    shutil.rmtree(str(candidate), ignore_errors=True)


def _safe_token(value: object) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "")).strip("-.")
