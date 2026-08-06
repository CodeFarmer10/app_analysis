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
    quarantine_reason: str | None = None
    quarantined_at: datetime | None = None
    quarantine_task_id: str | None = None
    quarantine_package_name: str | None = None
    recovery_started_at: datetime | None = None
    recovery_attempt_id: str | None = None
    last_recovery_at: datetime | None = None
    recovery_error: str | None = None
    analyzed_app_count_1d: int = 0
    created_at: datetime | None = None
