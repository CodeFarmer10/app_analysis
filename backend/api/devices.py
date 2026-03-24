from fastapi import APIRouter, Depends

from core.response import success_response
from core.security import get_current_user
from schemas.device import DeviceCreateRequest, DeviceItem, DeviceUpdateRequest
from services.device_service import (
    create_new_device,
    get_device_detail,
    list_device_items,
    remove_device,
    update_device_name,
)


router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.get("/ping")
async def devices_ping(current_user: dict = Depends(get_current_user)):
    _ = current_user
    return success_response({"module": "devices", "status": "ready"})


@router.get("")
async def get_devices(current_user: dict = Depends(get_current_user)):
    _ = current_user
    items = [DeviceItem(**item).model_dump() for item in list_device_items()]
    return success_response({"items": items, "total": len(items)})


@router.get("/{device_id}")
async def get_device(device_id: str, current_user: dict = Depends(get_current_user)):
    _ = current_user
    data = DeviceItem(**get_device_detail(device_id)).model_dump()
    return success_response(data)


@router.post("")
async def add_device(
    payload: DeviceCreateRequest,
    current_user: dict = Depends(get_current_user),
):
    _ = current_user
    data = DeviceItem(**create_new_device(serial=payload.serial, name=payload.name)).model_dump()
    return success_response(data)


@router.put("/{device_id}")
async def edit_device(
    device_id: str,
    payload: DeviceUpdateRequest,
    current_user: dict = Depends(get_current_user),
):
    _ = current_user
    data = DeviceItem(**update_device_name(device_id=device_id, name=payload.name)).model_dump()
    return success_response(data)


@router.delete("/{device_id}")
async def delete_device(device_id: str, current_user: dict = Depends(get_current_user)):
    _ = current_user
    remove_device(device_id)
    return success_response({"success": True})
