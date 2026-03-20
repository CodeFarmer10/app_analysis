from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status

from core.response import success_response
from core.security import get_current_admin, hash_password
from repositories.user_repo import (
    count_admin_users,
    create_user,
    delete_user,
    get_user_by_id,
    get_user_by_username,
    list_users,
)
from schemas.user import UserCreateRequest


router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("")
async def get_users(_: dict = Depends(get_current_admin)):
    users = list_users()
    return success_response({"items": users, "total": len(users)})


@router.post("")
async def add_user(payload: UserCreateRequest, _: dict = Depends(get_current_admin)):
    existed = get_user_by_username(payload.username)
    if existed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="用户名已存在",
        )

    create_user(
        user_id=str(uuid4()),
        username=payload.username,
        password_hash=hash_password(payload.password),
        role=payload.role,
    )
    return success_response({"success": True})


@router.delete("/{user_id}")
async def remove_user(user_id: str, current_admin: dict = Depends(get_current_admin)):
    target = get_user_by_id(user_id)
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在",
        )
    if current_admin["id"] == user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="不能删除当前登录用户",
        )
    if target["role"] == "admin" and count_admin_users() <= 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="至少保留一个管理员账户",
        )

    affected_rows = delete_user(user_id)
    if affected_rows == 0:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在",
        )
    return success_response({"success": True})
