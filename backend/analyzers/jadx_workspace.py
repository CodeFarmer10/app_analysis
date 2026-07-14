from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class JadxWorkspace:
    output_dir: str
    sources_dir: str
    return_code: int = 0
    warning: str | None = None


def jadx_inputs(path: str) -> list[str]:
    if not os.path.isdir(path):
        return [path]
    dex_files = sorted(
        os.path.join(root, name)
        for root, _dirs, files in os.walk(path)
        for name in files
        if name.endswith(".dex")
    )
    return dex_files or [path]


def _has_usable_output(output_dir: str) -> bool:
    root = Path(output_dir)
    for directory_name in ("sources", "resources"):
        directory = root / directory_name
        if not directory.is_dir():
            continue
        for item in directory.rglob("*"):
            try:
                if item.is_file() and item.stat().st_size > 0:
                    return True
            except OSError:
                continue
    return False


@contextmanager
def open_jadx_workspace(path: str, *, timeout: int = 300) -> Iterator[JadxWorkspace]:
    jadx = shutil.which("jadx")
    if not jadx:
        raise RuntimeError("未找到 jadx，请先安装 jadx 后再定位源码")

    with tempfile.TemporaryDirectory(prefix="apk-jadx-") as output_dir:
        completed = subprocess.run(
            [jadx, "-q", "-d", output_dir, *jadx_inputs(path)],
            capture_output=True,
            check=False,
            text=True,
            timeout=timeout,
        )
        warning = None
        if completed.returncode != 0:
            stderr = (completed.stderr or completed.stdout or "").strip()
            message = (stderr or f"jadx 执行失败，退出码 {completed.returncode}")[:4000]
            if not _has_usable_output(output_dir):
                raise RuntimeError(message)
            warning = f"jadx 部分反编译成功，退出码 {completed.returncode}: {message}"
            logger.warning("%s path=%s output_dir=%s", warning, path, output_dir)

        sources_dir = Path(output_dir) / "sources"
        yield JadxWorkspace(
            output_dir=output_dir,
            sources_dir=str(sources_dir if sources_dir.is_dir() else Path(output_dir)),
            return_code=completed.returncode,
            warning=warning,
        )
