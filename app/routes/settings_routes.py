from fastapi import APIRouter, HTTPException
from app.models.settings_models import SettingsUpdate
from app.config.database import user_collection

router = APIRouter(prefix="/settings", tags=["Settings"])

@router.post("/update")
async def update_settings(data: SettingsUpdate):
    update_fields = {}

    if data.receiver_lang is not None:
        update_fields["settings.receiver_lang"] = data.receiver_lang
    if data.sender_lang is not None:
        update_fields["settings.sender_lang"] = data.sender_lang
    if data.message_format is not None:
        update_fields["settings.message_format"] = data.message_format

    result = await user_collection.update_one({"uid": data.uid}, {"$set": update_fields})

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")

    return {"message": "Settings updated successfully"}

@router.get("/{uid}")
async def get_settings(uid: str):
    user = await user_collection.find_one({"uid": uid}, {"_id": 0, "settings": 1})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"settings": user.get("settings", {})}
