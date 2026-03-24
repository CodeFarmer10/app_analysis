from datetime import datetime

from pydantic import BaseModel, Field


class DeviceCreateRequest(BaseModel):
    serial: str = Field(..., min_length=1, max_length=128)
    name: str | None = Field(default=None, max_length=128)


class DeviceUpdateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)


class DeviceItem(BaseModel):
    id: str
    name: str | None = None
    serial: str
    android_version: str | None = None
    model: str | None = None
    resolution: str | None = None
    status: str
    current_task_id: str | None = None
    current_task_status: str | None = None
    last_heartbeat_at: datetime | None = None
    created_at: datetime | None = None
