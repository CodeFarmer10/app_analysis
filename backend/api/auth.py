from fastapi import APIRouter, Depends, HTTPException, status

from core.response import success_response
from core.security import create_access_token, get_current_user, hash_password, verify_password
from repositories.user_repo import get_user_by_username, update_password
from schemas.auth import ChangePasswordRequest, LoginRequest, LoginResponse


router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login")
async def login(payload: LoginRequest):
    user = get_user_by_username(payload.username)
    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误",
        )

    token = create_access_token(user["id"])
    data = LoginResponse(token=token, username=user["username"]).model_dump()
    return success_response(data)


@router.post("/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    _ = current_user
    return success_response({"success": True})


@router.post("/change-password")
async def change_password(
    payload: ChangePasswordRequest,
    current_user: dict = Depends(get_current_user),
):
    if not verify_password(payload.old_password, current_user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="旧密码错误",
        )
    if payload.old_password == payload.new_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="新密码不能与旧密码相同",
        )

    update_password(current_user["id"], hash_password(payload.new_password))
    return success_response({"success": True})
