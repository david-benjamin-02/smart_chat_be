from fastapi import (
    FastAPI,
    WebSocket,
    WebSocketDisconnect,
    HTTPException,
    File,
    UploadFile,
    Form,
)
import requests
import json
from datetime import datetime
import traceback
from starlette.websockets import WebSocketDisconnect

# from aksharamukha import transliterate
# from indic_transliteration.sanscript import transliterate, TAMIL, ITRANS
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field, model_validator
from typing import Dict
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from motor.motor_asyncio import AsyncIOMotorClient
from pydub import AudioSegment
import io, os, uuid, time, bcrypt, speech_recognition as sr
import language_tool_python
from googletrans import Translator
from gtts import gTTS
from bson import ObjectId
from indic_transliteration.sanscript import SchemeMap, SCHEMES, transliterate


# Setup FastAPI app
app = FastAPI()
# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace with specific origins in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
LANG_SCHEMES = {
    # "hi": sanscript.DEVANAGARI,
    # "ta": sanscript.TAMIL,
    # "kn": sanscript.KANNADA,
    # "ml": sanscript.MALAYALAM,
    # "te": sanscript.TELUGU,
    # "bn": sanscript.BENGALI,
    # "gu": sanscript.GUJARATI,
    # "pa": sanscript.GURMUKHI,
    # Add more if needed
}
# DB setup
MONGO_URI = "mongodb://localhost:27017"
client = AsyncIOMotorClient(MONGO_URI)
db = client["chat_app"]
user_collection = db["users"]
contact_collection = db["contacts"]
chat_collection = db["chats"]

# In-memory storage
active_connections: Dict[str, WebSocket] = {}
shared_keys: Dict[str, Dict[str, bytes]] = {}

# NLP tools
tool = language_tool_python.LanguageTool("en-US")
translator = Translator()


class TransReq(BaseModel):
    text: str
    language: str


# --- Models ---
class RegisterRequest(BaseModel):
    username: str
    phone: str
    email: EmailStr
    password: str
    confirmPassword: str

    @model_validator(mode="after")
    def check_passwords_match(self):
        if self.password != self.confirmPassword:
            raise ValueError("Passwords do not match")
        return self


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class SettingsUpdate(BaseModel):
    uid: str
    receiver_lang: str | None = None
    sender_lang: str | None = None  # optional field if needed
    message_format: str | None = None  # optional field if needed


class ContactAddRequest(BaseModel):
    current_user_uid: str  # the user who is adding the contact
    contact_email: EmailStr
    contact_name: str


class UpdateContactName(BaseModel):
    name: str


class UpdateProfile(BaseModel):
    name: str | None = None
    phone_number: str | None = None


class ForgotPasswordRequest(BaseModel):
    uid: str
    password: str


# --- Auth Routes ---
@app.post("/register")
async def register_user(request: RegisterRequest):
    if await user_collection.find_one(
        {"$or": [{"email": request.email}, {"phone_number": request.phone}]}
    ):
        raise HTTPException(status_code=400, detail="Email or phone already registered")

    user_id = str(uuid.uuid4())
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw().hex()
    hashed_password = bcrypt.hashpw(
        request.password.encode(), bcrypt.gensalt()
    ).decode()

    await user_collection.insert_one(
        {
            "uid": user_id,
            "name": request.username,
            "phone_number": request.phone,
            "email": request.email,
            "password": hashed_password,
            "private_key": private_key.private_bytes_raw().hex(),
            "public_key": public_key,
        }
    )
    await contact_collection.insert_one({"owner_uid": user_id, "contacts": []})

    return {"message": "User registered", "user_id": user_id, "public_key": public_key}


@app.post("/login")
async def login_user(request: LoginRequest):
    user = await user_collection.find_one({"email": request.email})
    if not user or not bcrypt.checkpw(
        request.password.encode(), user["password"].encode()
    ):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {
        "message": "Login successful",
        "user_id": user["uid"],
        "user_default_lang": user["settings"]["receiver_lang"],
        "username": user.get("username", user["name"]),
        "public_key": user["public_key"],
    }


# --- WebSocket Chat ---
@app.websocket("/ws/{uid}")
async def chat_socket(websocket: WebSocket, uid: str):
    user_doc = await user_collection.find_one({"uid": uid})
    if not user_doc:
        await websocket.close(code=1008)
        return

    private_key = x25519.X25519PrivateKey.from_private_bytes(
        bytes.fromhex(user_doc["private_key"])
    )
    public_key = user_doc["public_key"]

    await websocket.accept()
    active_connections[uid] = websocket
    shared_keys[uid] = {}
    await websocket.send_text("🔐 WebSocket connected!")

    try:
        while True:
            data = await websocket.receive_json()
            to_user = data.get("to")
            if not to_user:
                await websocket.send_text("❌ 'to' field required.")
                continue

            recipient_doc = await user_collection.find_one({"uid": to_user})
            if not recipient_doc or to_user not in active_connections:
                await websocket.send_text(f"❌ User '{to_user}' unavailable.")
                continue

            if to_user not in shared_keys[uid]:
                recipient_key = x25519.X25519PublicKey.from_public_bytes(
                    bytes.fromhex(recipient_doc["public_key"])
                )
                shared = private_key.exchange(recipient_key)
                derived_key = HKDF(
                    algorithm=hashes.SHA256(), length=32, salt=None, info=b"chat app"
                ).derive(shared)
                shared_keys[uid][to_user] = derived_key

            key = shared_keys[uid][to_user]

            if "message" in data:
                enc = encrypt_message(data["message"], key)
                await chat_collection.insert_one(
                    {
                        "from": uid,
                        "to": to_user,
                        "ciphertext": enc["ciphertext"],
                        "nonce": enc["nonce"],
                        "timestamp": time.time(),
                    }
                )

                # Share with recipient
                if uid not in shared_keys[to_user]:
                    recipient_private_key = x25519.X25519PrivateKey.from_private_bytes(
                        bytes.fromhex(recipient_doc["private_key"])
                    )
                    sender_public_key = x25519.X25519PublicKey.from_public_bytes(
                        bytes.fromhex(public_key)
                    )
                    reverse_shared = recipient_private_key.exchange(sender_public_key)
                    shared_keys[to_user][uid] = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b"chat app",
                    ).derive(reverse_shared)

                reverse_key = shared_keys[to_user][uid]
                decrypted_msg = decrypt_message(
                    enc["ciphertext"], enc["nonce"], reverse_key
                )
                await active_connections[to_user].send_json(
                    {"from": uid, "message": decrypted_msg}
                )

    except WebSocketDisconnect:
        active_connections.pop(uid, None)
        shared_keys.pop(uid, None)


# --- Speech to Text ---
@app.post("/speech_to_text")
async def speech_to_text(audio: UploadFile = File(...)):
    try:
        audio_data = await audio.read()
        segment = AudioSegment.from_file(io.BytesIO(audio_data))
        wav_io = io.BytesIO()
        segment.export(wav_io, format="wav")
        wav_io.seek(0)

        recognizer = sr.Recognizer()
        with sr.AudioFile(wav_io) as source:
            recorded = recognizer.record(source)
            original_text = recognizer.recognize_google(recorded)
            corrected_text = tool.correct(original_text)

        return {"original_text": original_text, "corrected_text": corrected_text}

    except sr.UnknownValueError:
        return JSONResponse(
            status_code=400, content={"error": "Could not understand audio"}
        )
    except sr.RequestError as e:
        return JSONResponse(
            status_code=500, content={"error": f"Speech recognition error: {e}"}
        )
    except Exception as e:
        return JSONResponse(
            status_code=500, content={"error": f"Unexpected error: {e}"}
        )


# --- Translate Text ---
# @app.post("/translate_text")
# async def translate_text(text: str = Form(...), language: str = Form("en")):
#     try:
#         translated = (
#             translator.translate(text, dest=language).text if language != "en" else text
#         )
#         audio_path = os.path.join("static", "translated_audio.mp3")
#         gTTS(text=translated, lang=language).save(audio_path)

#         return {"translated_text": translated, "audio_file": audio_path}
#     except Exception as e:
#         return JSONResponse(
#             status_code=500, content={"error": f"Translation error: {e}"}
#         )

# @app.post("/translate")
# async def translate_text(text: str = Form(...), language: str = Form("en")):
#     try:
#         translated = (
#             translator.translate(text, dest=language).text if language != "en" else text
#         )
#         return {"translated_text": translated}
#     except Exception as e:
#         return JSONResponse(
#             status_code=500, content={"error": f"Translation error: {e}"}
#         )


@app.post("/translate")
async def translate_text(text: str = Form(...), language: str = Form("en")):
    try:
        detected = translator.detect(text)
        source_lang = detected.lang

        if source_lang == language:
            translated = text  # No need to translate
        else:
            translated = translator.translate(text, src=source_lang, dest=language).text

        return {"translated_text": translated, "source_lang": source_lang}
    except Exception as e:
        return JSONResponse(
            status_code=500, content={"error": f"Translation error: {e}"}
        )


async def translate_texts(text, language):
    try:
        detected = translator.detect(text)
        source_lang = detected.lang

        if source_lang == language:
            translated = text  # No need to translate
        else:
            translated = translator.translate(text, src=source_lang, dest=language).text

        return {"translated_text": translated, "source_lang": source_lang}
    except Exception as e:
        return JSONResponse(
            status_code=500, content={"error": f"Translation error: {e}"}
        )


@app.post("/text-to-audio")
async def text_to_audio(text: str = Form(...), language: str = Form("en")):
    try:
        # Generate a MongoDB-style ObjectId for unique filename
        unique_filename = f"{str(ObjectId())}.mp3"
        audio_path = os.path.join("static", unique_filename)

        # Convert text to speech and save
        gTTS(text=text, lang=language).save(audio_path)

        return {"audio_file": audio_path}
    except Exception as e:
        return JSONResponse(
            status_code=500, content={"error": f"Audio conversion error: {e}"}
        )


async def text_to_audios(text, language):
    try:
        # Generate a MongoDB-style ObjectId for unique filename
        unique_filename = f"{str(ObjectId())}.mp3"
        audio_path = os.path.join("static", unique_filename)

        # Convert text to speech and save
        gTTS(text=text, lang=language).save(audio_path)

        return {"audio_file": audio_path}
    except Exception as e:
        return JSONResponse(
            status_code=500, content={"error": f"Audio conversion error: {e}"}
        )


@app.post("/update-settings")
async def update_settings(data: SettingsUpdate):
    update_fields = {}

    # Add theme if provided
    if data.receiver_lang is not None:
        update_fields["settings.receiver_lang"] = data.receiver_lang
    if data.sender_lang is not None:
        update_fields["settings.sender_lang"] = data.sender_lang
    if data.message_format is not None:
        update_fields["settings.message_format"] = data.message_format

    result = await user_collection.update_one(
        {"uid": data.uid}, {"$set": update_fields}
    )

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")

    return {"message": "Settings updated successfully"}


@app.post("/add-contact")
async def add_contact(data: ContactAddRequest):
    current_user = await user_collection.find_one({"uid": data.current_user_uid})
    if not current_user:
        raise HTTPException(status_code=404, detail="Current user not found")

    if data.contact_email == current_user["email"]:
        raise HTTPException(
            status_code=400, detail="You cannot add yourself as a contact"
        )

    contact_user = await user_collection.find_one({"email": data.contact_email})
    if not contact_user:
        raise HTTPException(status_code=404, detail="User Not in the System")

    # Check if contact already exists
    contact_doc = await contact_collection.find_one(
        {"owner_uid": data.current_user_uid}
    )
    if contact_doc:
        for contact in contact_doc.get("contacts", []):
            if contact["email"] == data.contact_email:
                raise HTTPException(status_code=400, detail="Contact already exists")

    # Add contact with unique ID
    contact_info = {
        "contact_id": str(ObjectId()),  # Unique identifier for this contact
        "uid": contact_user["uid"],
        "name": data.contact_name,
        "email": data.contact_email,
    }

    await contact_collection.update_one(
        {"owner_uid": data.current_user_uid}, {"$addToSet": {"contacts": contact_info}}
    )

    return {"message": "Contact added successfully"}


@app.get("/get-contacts/{uid}")
async def get_contacts(uid: str):

    contact_doc = await contact_collection.find_one({"owner_uid": uid})
    if not contact_doc:
        raise HTTPException(status_code=404, detail="No contacts found for this user")

    return {"contacts": contact_doc.get("contacts", [])}


@app.delete("/delete-contact/{uid}/{contact_id}")
async def delete_contact(uid: str, contact_id: str):
    result = await contact_collection.update_one(
        {"owner_uid": uid}, {"$pull": {"contacts": {"contact_id": contact_id}}}
    )

    if result.modified_count == 0:
        raise HTTPException(
            status_code=404, detail="Contact not found or already removed"
        )

    return {"message": "Contact deleted successfully"}


@app.get("/get-contact/{uid}/{contact_id}")
async def get_contact(uid: str, contact_id: str):
    contact_doc = await contact_collection.find_one({"owner_uid": uid})
    if not contact_doc:
        raise HTTPException(
            status_code=404, detail="No contact list found for this user"
        )

    for contact in contact_doc.get("contacts", []):
        if contact.get("contact_id") == contact_id:
            # Exclude 'uid' from the returned contact
            return {k: v for k, v in contact.items() if k != "uid"}

    raise HTTPException(status_code=404, detail="Contact not found")


@app.patch("/edit-contact/{uid}/{contact_id}")
async def edit_contact(uid: str, contact_id: str, data: UpdateContactName):
    contact_doc = await contact_collection.find_one({"owner_uid": uid})
    if not contact_doc:
        raise HTTPException(status_code=404, detail="Contact list not found")

    # Update the contact name in the array
    updated = False
    for contact in contact_doc.get("contacts", []):
        if contact.get("contact_id") == contact_id:
            contact["name"] = data.name
            updated = True
            break

    if not updated:
        raise HTTPException(status_code=404, detai1l="Contact not found")

    await contact_collection.update_one(
        {"owner_uid": uid}, {"$set": {"contacts": contact_doc["contacts"]}}
    )

    return {"message": "Contact name updated successfully"}


@app.patch("/update-profile/{uid}")
async def update_profile(uid: str, data: UpdateProfile):
    update_fields = {}
    if data.name:
        update_fields["name"] = data.name
    if data.phone_number:
        update_fields["phone_number"] = data.phone_number

    if not update_fields:
        raise HTTPException(
            status_code=400, detail="No valid fields provided for update"
        )

    result = await user_collection.update_one({"uid": uid}, {"$set": update_fields})

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")

    return {"message": "Profile updated successfully"}


@app.post("/forgot-password")
async def forgot_password(data: ForgotPasswordRequest):
    hashed_password = bcrypt.hashpw(data.password.encode(), bcrypt.gensalt()).decode()

    result = await user_collection.update_one(
        {"uid": data.uid}, {"$set": {"password": hashed_password}}
    )

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Email not found")

    return {"message": "Password updated successfully"}


from fastapi import HTTPException, APIRouter
from pymongo import DESCENDING


@app.get("/get-user-contacts/{uid}")
async def get_user_contacts(uid: str):
    contact_doc = await contact_collection.find_one(
        {"owner_uid": uid}, {"contacts.uid": 1, "contacts.name": 1, "_id": 0}
    )

    if not contact_doc:
        raise HTTPException(status_code=404, detail="No contacts found for this user")

    owner_segment = uid.split("-")[-1]
    enriched_contacts = []

    for contact in contact_doc.get("contacts", []):
        contact_uid = contact.get("uid")
        contact_name = contact.get("name")

        if not contact_uid:
            continue

        # Create chat key
        contact_segment = contact_uid.split("-")[-1]
        chat_key = "_".join(sorted([owner_segment, contact_segment]))

        # Get last 10 messages, sorted by created_at descending
        cursor = (
            chat_collection.find({"chat_id": chat_key})
            .sort("created_at", DESCENDING)
            .limit(10)
        )

        messages = []
        async for doc in cursor:
            messages.append(
                {
                    "id": str(doc.get("message_id")),
                    "message_text": doc.get("message_text"),
                    "sender_id": doc.get("sender_id"),
                    "receiver_id": doc.get("receiver_id"),
                    "message_type": doc.get("message_type"),
                    "date": doc.get("date"),
                    "time": doc.get("time"),
                    "created_at": doc.get("created_at"),
                }
            )

        enriched_contacts.append(
            {"uid": contact_uid, "name": contact_name, "recent_messages": messages}
        )

    return {"contacts": enriched_contacts}


# --- Helper ---
def encrypt_message(plaintext: str, key: bytes) -> Dict[str, str]:
    nonce = os.urandom(12)
    aead = ChaCha20Poly1305(key)
    ciphertext = aead.encrypt(nonce, plaintext.encode(), None)
    return {"ciphertext": ciphertext.hex(), "nonce": nonce.hex()}


def decrypt_message(ciphertext_hex: str, nonce_hex: str, key: bytes) -> str:
    ciphertext = bytes.fromhex(ciphertext_hex)
    nonce = bytes.fromhex(nonce_hex)
    aead = ChaCha20Poly1305(key)
    plaintext = aead.decrypt(nonce, ciphertext, None)
    return plaintext.decode()


@app.get("/")
def root():
    return {"message": "Welcome to the unified FastAPI App"}


def merge_sorted_uuid_segments(sender_id, receiver_id):
    # Extract the last segment after the last dash
    segment1 = sender_id.split("-")[-1]
    segment2 = receiver_id.split("-")[-1]

    # Sort the segments
    sorted_segments = sorted([segment1, segment2])

    # Join and return the result
    return "_".join(sorted_segments)


async def fetch_receiver_data(receiverId):
    receiver_data = await user_collection.find_one({"uid": receiverId})
    if not receiver_data:
        raise HTTPException(status_code=404, detail="No user found")
    message_format = receiver_data["settings"]["message_format"]
    receiver_lang = receiver_data["settings"]["receiver_lang"]
    return {"message_format": message_format, "receiver_lang": receiver_lang}

    # @app.websocket("/ws/chat/{sender_id}")
    # async def chat_websocket(websocket: WebSocket, sender_id: str):
    await websocket.accept()

    # If the user is already connected, close the previous connection
    if sender_id in active_connections:
        await active_connections[sender_id].close()

    # Store the new connection for the user
    active_connections[sender_id] = websocket

    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            receiverId = message["receiverId"]
            chatId = merge_sorted_uuid_segments(sender_id, receiverId)
            msg_type = message["msg_type"]
            msg_text = message["msg_text"]
            date = message["date"]
            time = message["time"]
            receiverSettings = fetch_receiver_data(receiverId)
            message_format = receiverSettings["message_format"]
            receiver_lang = receiverSettings["message_lang"]
            trans_message = ""
            trans_meadia_url = ""
            if receiver_lang == "None" and (
                message_format == "None" or message_format == "Text"
            ):
                trans_message = msg_text
            else:
                trans_text = translate_texts(msg_text, receiver_lang)
                if receiver_lang and (
                    receiver_lang == "None" or message_format == "Text"
                ):
                    trans_message = trans_text
                elif receiver_lang and (message_format == "Audio"):
                    trans_meadia_url = text_to_audios(msg_text, receiver_lang)
                else:
                    trans_message = msg_text

            await user_collection.insert_one(
                {
                    "chat_id": chatId,
                    "sender_id": sender_id,
                    "receiver_id": receiverId,
                    "message_type": msg_type,
                    "message_text": msg_text,
                    "media_url": "need to write function",
                    "date": date,
                    "time": time,
                    "transformation": {
                        "message_type": message_format,
                        "trans_message": trans_message,
                        "trans_meadia_url": trans_meadia_url,
                    },
                    "created_at": datetime.utcnow(),
                }
            )
            if receiverId in active_connections:
                # Send message to the receiver
                await active_connections[receiverId].send_text(json.dumps(message))

            # return {"message":"Message Sent Successfully"}
    except WebSocketDisconnect:
        # Remove the connection on disconnect
        del active_connections[sender_id]


@app.websocket("/ws/chat/{sender_id}")
async def chat_websocket(websocket: WebSocket, sender_id: str):
    await websocket.accept()

    # Close previous connection if user is reconnecting
    if sender_id in active_connections:
        try:
            await active_connections[sender_id].close()
        except RuntimeError:
            pass  # Ignore if already closed

    # Register the new connection
    active_connections[sender_id] = websocket
    print(f"✅ {sender_id} connected")

    # Notify others that this user is online
    for uid, conn in active_connections.items():
        if uid != sender_id:
            try:
                await conn.send_text(
                    json.dumps(
                        {"type": "presence", "userId": sender_id, "status": "online"}
                    )
                )
            except Exception:
                pass

    # Also send presence info to this user
    for uid in active_connections:
        if uid != sender_id:
            try:
                await websocket.send_text(
                    json.dumps({"type": "presence", "userId": uid, "status": "online"})
                )
            except Exception:
                pass

    try:
        while True:
            try:
                data = await websocket.receive_text()
                message = json.loads(data)

                # ✅ Typing event
                if message.get("type") == "typing":
                    receiver_id = message.get("to")
                    if receiver_id in active_connections:
                        await active_connections[receiver_id].send_text(
                            json.dumps({"type": "typing", "from": sender_id})
                        )
                    continue

                print("📥 Received:", message)

                # Validate message fields
                messageId = message.get("id")
                receiverId = message.get("receiverId")
                msg_type = message.get("msg_type")
                msg_text = message.get("msg_text")
                date = message.get("date")
                time = message.get("time")

                if not (receiverId and msg_type and msg_text and date and time):
                    print("❌ Missing fields in message:", message)
                    continue

                chatId = merge_sorted_uuid_segments(sender_id, receiverId)
                receiverSettings = await fetch_receiver_data(receiverId)
                message_format = receiverSettings.get("message_format")
                receiver_lang = receiverSettings.get("receiver_lang")

                trans_message = ""
                trans_media_url = ""

                if receiver_lang == "None" and (
                    message_format == "None" or message_format == "Text"
                ):
                    trans_message = msg_text
                else:
                    trans_text = await translate_texts(msg_text, receiver_lang)
                    if receiver_lang and (
                        message_format == "None" or message_format == "Text"
                    ):
                        trans_message = trans_text
                    elif receiver_lang and message_format == "Audio":
                        trans_media_url = await text_to_audios(msg_text, receiver_lang)
                    else:
                        trans_message = msg_text

                await chat_collection.insert_one(
                    {
                        "message_id": messageId,
                        "chat_id": chatId,
                        "sender_id": sender_id,
                        "receiver_id": receiverId,
                        "message_type": msg_type,
                        "message_text": msg_text,
                        "media_url": "",
                        "date": date,
                        "time": time,
                        "status": "sent",
                        "transformation": {
                            "message_type": message_format,
                            "trans_message": trans_message,
                            "trans_meadia_url": trans_media_url,
                        },
                        "created_at": datetime.utcnow(),
                    }
                )

                # Forward the message to the receiver if online
                if receiverId in active_connections:
                    await active_connections[receiverId].send_text(json.dumps(message))

                    # Acknowledge delivery to sender
                    await active_connections[sender_id].send_text(
                        json.dumps(
                            {
                                "id": messageId,
                                "status": "delivered",
                                "receiverId": receiverId,
                            }
                        )
                    )

            except WebSocketDisconnect:
                break  # Will be handled in outer try
            except Exception as e:
                print("❌ Error while handling message:", e)
                import traceback

                traceback.print_exc()

    except WebSocketDisconnect as e:
        print(f"🔌 WebSocket disconnected: {sender_id}, Code: {e.code}")
        active_connections.pop(sender_id, None)

        # Notify others that this user is offline
        for uid, conn in active_connections.items():
            try:
                await conn.send_text(
                    json.dumps(
                        {"type": "presence", "userId": sender_id, "status": "offline"}
                    )
                )
            except Exception:
                pass


@app.websocket("/ws/read/{reader_id}")
async def read_receipt(websocket: WebSocket, reader_id: str):
    await websocket.accept()
    print(f"📡 Read receipt WebSocket connected: {reader_id}")

    try:
        while True:
            data = await websocket.receive_text()
            payload = json.loads(data)

            message_id = payload.get("id")
            sender_id = payload.get("senderId")

            # ✅ Notify sender that message was read
            if sender_id in active_connections:
                await active_connections[sender_id].send_text(json.dumps({
                    "id": message_id,
                    "status": "read",
                    "receiverId": reader_id,
                }))
                await chat_collection.update_one(
                    {"message_id": message_id},
                    {"$set": {"status": "read"}}
                )

    except WebSocketDisconnect as e:
        print(f"🔌 Read WebSocket disconnected: {reader_id}, Code: {e.code}")
