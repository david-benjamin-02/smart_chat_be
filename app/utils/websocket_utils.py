# import json
# from datetime import datetime
# from app.utils.helper import merge_sorted_uuid_segments
# from app.utils.translation_utils import translate_text
# from app.utils.audio_utils import text_to_audio
# from app.config.database import chat_collection, user_collection

# active_connections = {}

# async def send_json(websocket, data):
#     """Safely send JSON messages through websocket"""
#     try:
#         await websocket.send_text(json.dumps(data))
#     except Exception as e:
#         print("⚠️ WebSocket send error:", e)

# async def broadcast_user_status(status: str, user_id: str):
#     """Broadcast user online/offline status"""
#     for uid, conn in active_connections.items():
#         if uid != user_id:
#             await send_json(conn, {"type": "presence", "userId": user_id, "status": status})

# async def fetch_receiver_settings(uid):
#     user = await user_collection.find_one({"uid": uid})
#     if not user:
#         return None
#     return user.get("settings", {})


from typing import Dict
from fastapi import WebSocket
import json

active_connections: Dict[str, WebSocket] = {}

async def broadcast_user_status(status: str, user_id: str):
    for uid, conn in list(active_connections.items()):
        if uid != user_id:
            try:
                await conn.send_text(json.dumps({
                    "type": "presence",
                    "userId": user_id,
                    "status": status
                }))
            except Exception:
                active_connections.pop(uid, None)
