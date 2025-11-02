import json
from datetime import datetime
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.config.database import chat_collection, user_collection
from app.utils.translation_utils import translate_text
from app.utils.audio_utils import text_to_audio
from app.utils.chat_utils import merge_sorted_uuid_segments, fetch_receiver_data
from app.utils.websocket_utils import active_connections, broadcast_user_status

router = APIRouter(prefix="/ws", tags=["WebSocket Chat"])


@router.websocket("/chat/{sender_id}")
async def chat_websocket(websocket: WebSocket, sender_id: str):
    await websocket.accept()

    # Close previous connection if user is reconnecting
    if sender_id in active_connections:
        try:
            await active_connections[sender_id].close()
        except RuntimeError:
            pass

    # Register the new connection
    active_connections[sender_id] = websocket
    print(f"✅ {sender_id} connected")

    # Mark pending messages as delivered
    await chat_collection.update_many(
        {"receiver_id": sender_id, "status": "sent"},
        {"$set": {"status": "delivered"}},
    )

    # Notify senders about delivery
    undelivered_messages = await chat_collection.find(
        {"receiver_id": sender_id, "status": "delivered"}
    ).to_list(None)

    for msg in undelivered_messages:
        original_sender = msg.get("sender_id")
        if original_sender in active_connections:
            try:
                await active_connections[original_sender].send_text(
                    json.dumps({
                        "id": msg["message_id"],
                        "status": "delivered",
                        "receiverId": sender_id,
                    })
                )
            except RuntimeError:
                active_connections.pop(original_sender, None)

    # Broadcast presence updates
    await broadcast_user_status("online", sender_id)

    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)

            # Typing notification
            if message.get("type") == "typing":
                receiver_id = message.get("to")
                if receiver_id in active_connections:
                    await active_connections[receiver_id].send_text(
                        json.dumps({"type": "typing", "from": sender_id})
                    )
                continue

            # Extract fields
            message_id = message.get("id")
            receiver_id = message.get("receiverId")
            msg_type = message.get("msg_type")
            msg_text = message.get("msg_text")
            date = message.get("date")
            time = message.get("time")

            if not (receiver_id and msg_type and msg_text and date and time):
                print("❌ Missing fields in message:", message)
                continue

            # Chat ID and receiver settings
            chat_id = merge_sorted_uuid_segments(sender_id, receiver_id)
            receiver_settings = await fetch_receiver_data(receiver_id)
            message_format = receiver_settings.get("message_format")
            receiver_lang = receiver_settings.get("receiver_lang")

            trans_message = ""
            trans_media_url = ""

            # === Audio Message ===
            if msg_type == "Audio":
                if receiver_lang == "None" and (message_format in ["None", "Audio"]):
                    pass
                elif receiver_lang == "None" and message_format == "Text":
                    trans_message = message.get("transformed_text")
                elif receiver_lang and message_format == "Text":
                    transcribe_message = message.get("transformed_text")
                    trans_text = await translate_text(transcribe_message, receiver_lang)
                    trans_message = trans_text["translated_text"]
                elif receiver_lang and message_format in ["None", "Audio"]:
                    transcribe_message = message.get("transformed_text")
                    trans_text = await translate_text(transcribe_message, receiver_lang)
                    trans_message = trans_text["translated_text"]
                    audio_result = await text_to_audio(trans_message, receiver_lang)
                    trans_message = ""
                    if isinstance(audio_result, dict) and "audio_file" in audio_result:
                        trans_media_url = audio_result["audio_file"]
                    else:
                        trans_media_url = ""

            # === Text Message ===
            elif msg_type == "Text":
                if receiver_lang == "None" and message_format in ["None", "Text"]:
                    trans_message = msg_text
                else:
                    trans_text = await translate_text(msg_text, receiver_lang)
                    trans_message = trans_text["translated_text"]
                    if receiver_lang and message_format == "Audio":
                        audio_result = await text_to_audio(trans_message, receiver_lang)
                        if isinstance(audio_result, dict) and "audio_file" in audio_result:
                            trans_media_url = audio_result["audio_file"]
                        else:
                            trans_media_url = ""
                    else:
                        pass

            # Insert into MongoDB
            await chat_collection.insert_one({
                "message_id": message_id,
                "chat_id": chat_id,
                "sender_id": sender_id,
                "receiver_id": receiver_id,
                "message_type": msg_type,
                "message_text": msg_text,
                "media_url": "",
                "date": date,
                "time": time,
                "status": "sent",
                "transformation": {
                    "message_type": message_format,
                    "trans_message": trans_message,
                    "trans_media_url": trans_media_url,
                },
                "created_at": datetime.utcnow(),
            })

            # Acknowledge sender
            await websocket.send_text(json.dumps({
                "id": message_id,
                "msg_text": msg_text,
                "senderId": sender_id,
                "receiverId": receiver_id,
                "msg_type": msg_type,
                "time": time,
                "transformation": {
                    "message_type": message_format,
                    "trans_message": trans_message,
                    "trans_audio_url": trans_media_url,
                },
                "status": "sent",
            }))

            # Forward to receiver if connected
            if receiver_id in active_connections:
                sender_user = await user_collection.find_one({"uid": sender_id}, {"email": 1})
                await active_connections[receiver_id].send_text(json.dumps({
                    "id": message_id,
                    "msg_text": msg_text,
                    "senderId": sender_id,
                    "receiverId": receiver_id,
                    "msg_type": msg_type,
                    "time": time,
                    "name": sender_user["email"] if sender_user else sender_id,
                    "transformation": {
                        "message_type": message_format,
                        "trans_message": trans_message,
                        "trans_audio_url": trans_media_url,
                    },
                    "date": date,
                }))

                # Mark delivered
                await chat_collection.update_one(
                    {"message_id": message_id},
                    {"$set": {"status": "delivered"}},
                )

                # Acknowledge delivery to sender
                await websocket.send_text(json.dumps({
                    "id": message_id,
                    "status": "delivered",
                    "receiverId": receiver_id,
                }))

    except WebSocketDisconnect:
        print(f"🔌 {sender_id} disconnected")
        active_connections.pop(sender_id, None)
        await broadcast_user_status("offline", sender_id)


@router.websocket("/read/{reader_id}")
async def read_receipt(websocket: WebSocket, reader_id: str):
    await websocket.accept()
    print(f"📡 Read receipt WebSocket connected: {reader_id}")

    try:
        while True:
            data = await websocket.receive_text()
            payload = json.loads(data)

            message_id = payload.get("id")
            sender_id = payload.get("senderId")

            if not message_id or not sender_id:
                continue

            # ✅ Notify sender that message was read
            if sender_id in active_connections:
                await active_connections[sender_id].send_text(
                    json.dumps(
                        {
                            "id": message_id,
                            "status": "read",
                            "receiverId": reader_id,
                        }
                    )
                )

            # ✅ Update database
            await chat_collection.update_one(
                {"message_id": message_id},
                {"$set": {"status": "read"}},
            )

    except WebSocketDisconnect as e:
        print(f"🔌 Read WebSocket disconnected: {reader_id}, Code: {e.code}")
        # no cleanup needed, since main chat socket manages connections