from __future__ import annotations

from pathlib import Path


MAX_BLOB_BYTES = 64 * 1024 * 1024
MAX_TEXT_FILE_BYTES = 1 * 1024 * 1024

TEXT_EXTENSIONS = {
    ".java",
    ".kt",
    ".xml",
    ".json",
    ".properties",
    ".txt",
    ".js",
    ".html",
    ".gradle",
    ".smali",
}

MEDIA_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".bmp",
    ".ico",
    ".tif",
    ".tiff",
    ".heic",
    ".heif",
    ".mp3",
    ".mp4",
    ".m4a",
    ".aac",
    ".wav",
    ".ogg",
    ".flac",
    ".avi",
    ".mov",
    ".mkv",
    ".webm",
    ".ttf",
    ".otf",
    ".woff",
    ".woff2",
}


def artifact_extension(name: str) -> str:
    entry_name = str(name or "").rsplit("!", 1)[-1]
    return Path(entry_name).suffix.lower()


def is_text_artifact(name: str) -> bool:
    return artifact_extension(name) in TEXT_EXTENSIONS


def is_media_artifact(name: str) -> bool:
    return artifact_extension(name) in MEDIA_EXTENSIONS


def should_skip_artifact(name: str, uncompressed_size: int) -> bool:
    if is_media_artifact(name):
        return True
    return is_text_artifact(name) and uncompressed_size > MAX_TEXT_FILE_BYTES
