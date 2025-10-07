from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from typing import Dict
from pydantic import BaseModel, field_validator, model_validator
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from motor.motor_asyncio import AsyncIOMotorClient
import os, uuid, time
import bcrypt
from pydantic import BaseModel, EmailStr, Field
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

origins = [
    "http://localhost:3000",  # React dev server
    # Add other allowed origins here
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,              # or ["*"] to allow all
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB setup
MONGO_URI = "mongodb://localhost:27017"
client = AsyncIOMotorClient(MONGO_URI)
db = client["chat_app"]
user_collection = db["users"]
chat_collection = db["chats"]

# In-memory tracking
active_connections: Dict[str, WebSocket] = {}
shared_keys: Dict[str, Dict[str, bytes]] = {}

# Encryption helpers
def encrypt_message(plaintext: str, key: bytes) -> Dict[str, str]:
    nonce = os.urandom(12)
    aead = ChaCha20Poly1305(key)
    ciphertext = aead.encrypt(nonce, plaintext.encode(), None)
    return {
        "ciphertext": ciphertext.hex(),
        "nonce": nonce.hex()
    }

def decrypt_message(ciphertext_hex: str, nonce_hex: str, key: bytes) -> str:
    ciphertext = bytes.fromhex(ciphertext_hex)
    nonce = bytes.fromhex(nonce_hex)
    aead = ChaCha20Poly1305(key)
    plaintext = aead.decrypt(nonce, ciphertext, None)
    return plaintext.decode()

# Models
class RegisterRequest(BaseModel):
    name: str = Field(..., min_length=1)
    phone_number: str = Field(..., min_length=10, max_length=15)
    email: EmailStr
    password: str = Field(..., min_length=6)
    confirm_password: str
    
    @model_validator(mode="after")
    def check_passwords_match(self):
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match")
        return self
class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    
    # @field_validator("confirm_password")
    # def passwords_match(cls, v, values):
    #     if v != values.get("password"):
    #         raise ValueError("Passwords do not match")
    #     return v

# Register route
@app.post("/register")
async def register_user(request: RegisterRequest):
    # Check if email or phone number already exists
    existing = await user_collection.find_one({
        "$or": [
            {"phone_number": request.phone_number},
            {"email": request.email}
        ]
    })
    if existing:
        raise HTTPException(status_code=400, detail="Email or phone number already registered")

    user_id = str(uuid.uuid4())
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw().hex()

    # Hash password
    hashed_password = bcrypt.hashpw(request.password.encode(), bcrypt.gensalt()).decode()

    await user_collection.insert_one({
        "_id": user_id,
        "name": request.name,
        "phone_number": request.phone_number,
        "email": request.email,
        "password": hashed_password,
        "private_key": private_key.private_bytes_raw().hex(),
        "public_key": public_key
    })

    return {
        "message": "User registered successfully",
        "user_id": user_id,
        "public_key": public_key
    }

@app.post("/login")
async def login_user(request: LoginRequest):
    user = await user_collection.find_one({"email": request.email})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    stored_hash = user.get("password")
    if not stored_hash or not bcrypt.checkpw(request.password.encode(), stored_hash.encode()):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    return {
        "message": "Login successful",
        "user_id": user["_id"],
        "username": user["username"] if "username" in user else user["name"],
        "public_key": user["public_key"]
    }
# WebSocket chat
@app.websocket("/ws/{username}")
async def chat_socket(websocket: WebSocket, username: str):
    user_doc = await user_collection.find_one({"username": username})
    if not user_doc:
        await websocket.close(code=1008)
        return

    private_key = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(user_doc["private_key"]))
    public_key = user_doc["public_key"]

    await websocket.accept()
    active_connections[username] = websocket
    shared_keys[username] = {}

    await websocket.send_text("🔐 WebSocket connected!")

    try:
        while True:
            data = await websocket.receive_json()
            to_user = data.get("to")

            if not to_user:
                await websocket.send_text("❌ 'to' field required.")
                continue

            recipient_doc = await user_collection.find_one({"username": to_user})
            if not recipient_doc:
                await websocket.send_text(f"❌ User '{to_user}' not found.")
                continue

            if to_user not in active_connections:
                await websocket.send_text(f"❌ User '{to_user}' is not connected.")
                continue

            # Derive key
            if to_user not in shared_keys[username]:
                recipient_public_key_bytes = bytes.fromhex(recipient_doc["public_key"])
                recipient_public_key = x25519.X25519PublicKey.from_public_bytes(recipient_public_key_bytes)
                shared_secret = private_key.exchange(recipient_public_key)
                derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'chat app'
                ).derive(shared_secret)
                shared_keys[username][to_user] = derived_key

            key = shared_keys[username][to_user]

            if "message" in data:
                enc = encrypt_message(data["message"], key)

                # Insert message into DB
                try:
                    result = await chat_collection.insert_one({
                        "from": username,
                        "to": to_user,
                        "ciphertext": enc["ciphertext"],
                        "nonce": enc["nonce"],
                        "timestamp": time.time()
                    })
                    print(f"✅ Message inserted with ID: {result.inserted_id}")
                except Exception as e:
                    print(f"❌ Failed to insert message: {e}")
                    await websocket.send_text("❌ Failed to save message.")
                    continue

                # Decrypt for recipient
                if username not in shared_keys[to_user]:
                    recipient_private_key = x25519.X25519PrivateKey.from_private_bytes(
                        bytes.fromhex(recipient_doc["private_key"])
                    )
                    sender_public_key = x25519.X25519PublicKey.from_public_bytes(
                        bytes.fromhex(public_key)
                    )
                    reverse_shared = recipient_private_key.exchange(sender_public_key)
                    reverse_derived = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'chat app'
                    ).derive(reverse_shared)
                    shared_keys[to_user][username] = reverse_derived

                reverse_key = shared_keys[to_user][username]
                decrypted_msg = decrypt_message(enc["ciphertext"], enc["nonce"], reverse_key)

                await active_connections[to_user].send_json({
                    "from": username,
                    "message": decrypted_msg
                })

            elif "ciphertext" in data and "nonce" in data:
                try:
                    result = await chat_collection.insert_one({
                        "from": username,
                        "to": to_user,
                        "ciphertext": data["ciphertext"],
                        "nonce": data["nonce"],
                        "timestamp": time.time()
                    })
                    print(f"✅ Raw ciphertext inserted with ID: {result.inserted_id}")
                except Exception as e:
                    print(f"❌ Failed to insert raw message: {e}")
                    await websocket.send_text("❌ Failed to save encrypted message.")
                    continue

                await active_connections[to_user].send_json({
                    "from": username,
                    "ciphertext": data["ciphertext"],
                    "nonce": data["nonce"]
                })

            else:
                await websocket.send_text("❌ Invalid message format.")

    except WebSocketDisconnect:
        active_connections.pop(username, None)
        shared_keys.pop(username, None)
        print(f"{username} disconnected")

# Get all chat history
@app.get("/chat-history")
async def get_all_chats():
    chats = await chat_collection.find().sort("timestamp", -1).to_list(1000)
    for chat in chats:
        chat["_id"] = str(chat["_id"])
    return chats

# Get all registered users
@app.get("/users")
async def get_all_users():
    users_cursor = user_collection.find({}, {"_id": 1, "username": 1, "public_key": 1})
    users = await users_cursor.to_list(1000)
    for user in users:
        user["id"] = str(user["_id"])
        del user["_id"]
    return users

# Ping DB connection
@app.get("/ping-db")
async def ping_db():
    try:
        await db.command("ping")
        return {"status": "MongoDB connection OK"}
    except Exception as e:
        return {"status": "MongoDB connection failed", "error": str(e)}

