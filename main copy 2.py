from fastapi import (
    FastAPI,
    Response,
    WebSocket,
    WebSocketDisconnect,
    HTTPException,
    File,
    UploadFile,
    Form,
)
import requests
from fastapi.responses import FileResponse, JSONResponse
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

    return {
        "message": "User registered",
        "user_id": user_id,
        "public_key": public_key,
    }


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
        "username": user.get("username", user["name"]),
        "public_key": user["public_key"],
    }

@app.post("/logout")
def logout(response: Response):
    response.delete_cookie("access_token")
    return {"message": "Logged out"}

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


# @app.post("/text-to-audio")
# async def text_to_audio(text: str = Form(...), language: str = Form("en")):
#     try:
#         # Generate a MongoDB-style ObjectId for unique filename
#         unique_filename = f"{str(ObjectId())}.mp3"
#         audio_path = os.path.join("static", unique_filename)

#         # Convert text to speech and save
#         gTTS(text=text, lang=language).save(audio_path)

#         return {"audio_file": audio_path}
#     except Exception as e:
#         return JSONResponse(
#             status_code=500, content={"error": f"Audio conversion error: {e}"}
#         )


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


ELEVENLABS_API_KEY = "your_api_key_here"  # replace with your actual key
VOICE_ID = "your_voice_id_here"  # after cloning/designing a voice

AUDIO_DIR = "static"
os.makedirs(AUDIO_DIR, exist_ok=True)

@app.post("/text-to-audio")
async def text_to_audio(text: str = Form(...), language: str = Form("hi")):
    try:
        url = f"https://api.elevenlabs.io/v1/text-to-speech/{VOICE_ID}"
        headers = {
            "xi-api-key": ELEVENLABS_API_KEY,
            "Content-Type": "application/json"
        }
        data = {
            "text": text,
            "model_id": "eleven_multilingual_v1",  # multilingual model
            "voice_settings": {
                "stability": 0.75,
                "similarity_boost": 0.75
            }
        }

        response = requests.post(url, headers=headers, json=data)
        if response.status_code != 200:
            return JSONResponse(status_code=500, content={"error": response.text})

        filename = f"{uuid.uuid4()}.mp3"
        path = os.path.join(AUDIO_DIR, filename)
        with open(path, "wb") as f:
            f.write(response.content)

        return FileResponse(path, media_type="audio/mpeg", filename=filename)

    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})