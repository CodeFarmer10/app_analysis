from datetime import datetime

from pydantic import BaseModel, Field


class UrlSubmitRequest(BaseModel):
    urls: list[str] = Field(..., min_length=1, max_length=100)


class TaskStatusResponse(BaseModel):
    id: str
    status: str
    device_id: str | None = None
    error_message: str | None = None


class TaskListItem(BaseModel):
    id: str
    source_type: str
    source_name: str
    app_name: str | None = None
    package_name: str | None = None
    icon_url: str | None = None
    file_md5: str | None = None
    status: str
    device_id: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class TaskListResponse(BaseModel):
    items: list[TaskListItem]
    total: int
    page: int
    size: int
