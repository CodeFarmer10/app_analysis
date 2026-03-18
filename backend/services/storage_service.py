from __future__ import annotations

import io
import os
import tempfile
from datetime import timedelta
from pathlib import Path
from typing import Optional

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
        target_bucket = bucket or self.bucket_name
        return self.client.presigned_get_object(
            bucket_name=target_bucket,
            object_name=object_name,
            expires=timedelta(seconds=expires_seconds),
        )

    def download_to_temp(self, object_name: str, bucket: Optional[str] = None) -> str:
        target_bucket = bucket or self.bucket_name
        temp_dir = tempfile.mkdtemp(prefix="fraud_app_")
        target_path = os.path.join(temp_dir, os.path.basename(object_name) or "download.bin")
        self.client.fget_object(target_bucket, object_name, target_path)
        return target_path

    def upload_task_file(self, task_id: str, file_type: str, file_path: str) -> str:
        object_name = self.build_task_object_name(task_id, file_type, os.path.basename(file_path))
        self.upload_file(object_name=object_name, file_path=file_path)
        return object_name

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
        return object_name


storage_service = StorageService()
