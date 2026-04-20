from __future__ import annotations

import io
import os
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import quote, unquote, urlparse
from urllib.request import Request, urlopen

from minio import Minio

from core.config import settings


class StorageService:
    def __init__(self):
        self.client = Minio(
            endpoint=settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=settings.MINIO_SECURE,
        )
        self.bucket_name = settings.BUCKET_TASK_FILES

    def ensure_buckets(self) -> None:
        if not self.client.bucket_exists(self.bucket_name):
            self.client.make_bucket(self.bucket_name)

    def build_task_object_name(self, task_id: str, file_type: str, file_name: str) -> str:
        safe_type = file_type.strip().strip("/").replace("\\", "/")
        safe_name = os.path.basename(file_name)
        return f"{task_id}/{safe_type}/{safe_name}"

    @staticmethod
    def _is_http_url(value: str) -> bool:
        text = (value or "").strip().lower()
        return text.startswith("http://") or text.startswith("https://")

    def _base_download_url(self) -> str:
        endpoint = str(settings.MINIO_ENDPOINT or "").strip().rstrip("/")
        if endpoint.startswith("http://") or endpoint.startswith("https://"):
            return endpoint
        scheme = "https" if settings.MINIO_SECURE else "http"
        return f"{scheme}://{endpoint}"

    def build_object_url(self, object_name: str, bucket: Optional[str] = None) -> str:
        target_bucket = bucket or self.bucket_name
        normalized_object = quote(str(object_name or "").strip().lstrip("/"), safe="/")
        return f"{self._base_download_url()}/{target_bucket}/{normalized_object}"

    def parse_object_name(self, object_ref: str, bucket: Optional[str] = None) -> str:
        normalized_ref = str(object_ref or "").strip()
        if not normalized_ref:
            return ""
        if not self._is_http_url(normalized_ref):
            return normalized_ref.lstrip("/")

        parsed = urlparse(normalized_ref)
        raw_path = unquote((parsed.path or "").strip()).lstrip("/")
        if not raw_path:
            return ""
        target_bucket = bucket or self.bucket_name
        bucket_prefix = f"{target_bucket}/"
        if raw_path.startswith(bucket_prefix):
            return raw_path[len(bucket_prefix):]
        if "/" in raw_path:
            return raw_path.split("/", 1)[1]
        return raw_path

    def _download_http_to_temp(self, url: str) -> str:
        parsed = urlparse(url)
        file_name = os.path.basename(unquote(parsed.path or "")) or "download.bin"
        temp_dir = tempfile.mkdtemp(prefix="fraud_app_")
        target_path = os.path.join(temp_dir, file_name)
        request = Request(url, method="GET")
        with urlopen(request, timeout=120) as response, open(target_path, "wb") as target_file:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                target_file.write(chunk)
        return target_path

    def get_download_url(self, object_ref: str | None, bucket: Optional[str] = None) -> str | None:
        raw = str(object_ref or "").strip()
        if not raw:
            return None
        if self._is_http_url(raw):
            return raw
        return self.build_object_url(raw, bucket=bucket)

    def upload_file(self, object_name: str, file_path: str, bucket: Optional[str] = None) -> None:
        target_bucket = bucket or self.bucket_name
        path = Path(file_path)
        self.client.fput_object(target_bucket, object_name, str(path))

    def upload_bytes(
        self,
        object_name: str,
        data: bytes,
        content_type: str = "application/octet-stream",
        bucket: Optional[str] = None,
    ) -> None:
        target_bucket = bucket or self.bucket_name
        stream = io.BytesIO(data)
        self.client.put_object(
            bucket_name=target_bucket,
            object_name=object_name,
            data=stream,
            length=len(data),
            content_type=content_type,
        )

    def get_presigned_url(
        self,
        object_name: str,
        expires_seconds: int = 3600,
        bucket: Optional[str] = None,
    ) -> str:
        if self._is_http_url(object_name):
            return object_name
        target_bucket = bucket or self.bucket_name
        normalized_object_name = self.parse_object_name(object_name, bucket=target_bucket)
        return self.client.presigned_get_object(
            bucket_name=target_bucket,
            object_name=normalized_object_name,
            expires=timedelta(seconds=expires_seconds),
        )

    def download_to_temp(self, object_name: str, bucket: Optional[str] = None) -> str:
        if self._is_http_url(object_name):
            return self._download_http_to_temp(object_name)
        target_bucket = bucket or self.bucket_name
        normalized_object_name = self.parse_object_name(object_name, bucket=target_bucket)
        temp_dir = tempfile.mkdtemp(prefix="fraud_app_")
        target_path = os.path.join(temp_dir, os.path.basename(normalized_object_name) or "download.bin")
        self.client.fget_object(target_bucket, normalized_object_name, target_path)
        return target_path

    def get_object_bytes(self, object_name: str, bucket: Optional[str] = None) -> bytes:
        if self._is_http_url(object_name):
            request = Request(object_name, method="GET")
            with urlopen(request, timeout=120) as response:
                return response.read()
        target_bucket = bucket or self.bucket_name
        normalized_object_name = self.parse_object_name(object_name, bucket=target_bucket)
        response = self.client.get_object(target_bucket, normalized_object_name)
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()

    def upload_task_file(self, task_id: str, file_type: str, file_path: str) -> str:
        object_name = self.build_task_object_name(task_id, file_type, os.path.basename(file_path))
        self.upload_file(object_name=object_name, file_path=file_path)
        return self.build_object_url(object_name)

    def upload_task_bytes(
        self,
        task_id: str,
        file_type: str,
        file_name: str,
        data: bytes,
        content_type: str = "application/octet-stream",
    ) -> str:
        object_name = self.build_task_object_name(task_id, file_type, file_name)
        self.upload_bytes(
            object_name=object_name,
            data=data,
            content_type=content_type,
        )
        return self.build_object_url(object_name)


storage_service = StorageService()
