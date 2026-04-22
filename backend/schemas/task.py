from datetime import datetime
import re
from urllib.parse import urlparse

from pydantic import BaseModel, Field, field_validator


class UrlSubmitRequest(BaseModel):
    urls: list[str] = Field(..., min_length=1, max_length=100)
    task_description: str = Field(default="", max_length=255)
    priority: int = Field(default=1, ge=1, le=1_000_000)


class BackendImportItem(BaseModel):
    minio_download_url: str = Field(..., min_length=1, max_length=512)
    priority: int = Field(default=1, ge=1, le=1_000_000)
    source_desc: str = Field(default="", max_length=255)
    md5: str = Field(..., min_length=32, max_length=32)
    file_size: int = Field(..., gt=0)

    @field_validator("minio_download_url")
    @classmethod
    def validate_minio_download_url(cls, value: str) -> str:
        text = value.strip()
        parsed = urlparse(text)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("minio_download_url must be a valid http/https URL")
        return text

    @field_validator("source_desc")
    @classmethod
    def normalize_source_desc(cls, value: str) -> str:
        return value.strip()

    @field_validator("md5")
    @classmethod
    def validate_md5(cls, value: str) -> str:
        text = value.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{32}", text):
            raise ValueError("md5 must be 32 lowercase/uppercase hex chars")
        return text


class BackendImportRequest(BaseModel):
    items: list[BackendImportItem] = Field(..., min_length=1, max_length=500)


class TaskStatusResponse(BaseModel):
    id: str
    status: str
    device_id: str | None = None
    device_serial: str | None = None
    error_message: str | None = None


class TaskListItem(BaseModel):
    id: str
    batch_id: str | None = None
    task_description: str | None = None
    priority: int = 1
    source_type: str
    source_name: str
    app_name: str | None = None
    package_name: str | None = None
    icon_url: str | None = None
    file_md5: str | None = None
    status: str
    can_download_apk: bool = False
    can_download_report: bool = False
    can_download_pcap: bool = False
    device_id: str | None = None
    device_serial: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class TaskListResponse(BaseModel):
    items: list[TaskListItem]
    total: int
    page: int
    size: int
