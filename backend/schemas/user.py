from datetime import datetime

from pydantic import BaseModel, Field


class UserCreateRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=6, max_length=128)
    role: str = Field(default="user", pattern="^(admin|user)$")


class UserListItem(BaseModel):
    id: str
    username: str
    role: str
    created_at: datetime | None = None
