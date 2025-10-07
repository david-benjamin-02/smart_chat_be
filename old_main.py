'''
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from typing import Dict, List
from pydantic import BaseModel
import uuid
app = FastAPI()

# In-memory user store
users: List[Dict] = []
active_connections: Dict[str, WebSocket] = {}
# --------- Registration ---------
class RegisterRequest(BaseModel):
    username: str
    

@app.post("/register")
def register_user(request:RegisterRequest):
    if any(user['username'] == request.username for user in users):
        raise HTTPException(status_code=400, detail="Username already taken")
    
    user_id = str(uuid.uuid4())  # Generate UUID for the user

    new_user = {
        "id": user_id,
        "username": request.username,
    }
    print("new_user",new_user)
    users.append(new_user)
    print(users)

    return {
        "message": "User registered successfully",
        "user_id": user_id
    }

# --------- WebSocket Chat ---------
@app.websocket("/ws/{username}")
async def chat_socket(websocket: WebSocket, username: str):
    # Only allow registered users
    if not any(user['username'] == username for user in users):
        await websocket.close(code=1008)
        return

    await websocket.accept()
    active_connections[username] = websocket

    try:
        while True:
            data = await websocket.receive_json()
            to_user = data.get("to")
            message = data.get("message")

            if to_user not in active_connections:
                await websocket.send_text(f"User '{to_user}' is not connected.")
                continue

            # Send message to the recipient
            receiver_socket = active_connections[to_user]
            await receiver_socket.send_text(f"{username}: {message}")

    except WebSocketDisconnect:
        del active_connections[username]
        print(f"{username} disconnected")

# --------- Debug Endpoint ---------
@app.get("/users")
def get_all_users():
    return users
'''


'''
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from typing import Dict, List
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os, uuid, base64, json

app = FastAPI()

users: List[Dict] = []
active_connections: Dict[str, WebSocket] = {}
shared_keys: Dict[str, bytes] = {}  # username -> shared key

class RegisterRequest(BaseModel):
    username: str

@app.post("/register")
def register_user(request: RegisterRequest):
    if any(user['username'] == request.username for user in users):
        raise HTTPException(status_code=400, detail="Username already taken")

    user_id = str(uuid.uuid4())
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw().hex()

    new_user = {
        "id": user_id,
        "username": request.username,
        "private_key": private_key,
        "public_key": public_key
    }
    users.append(new_user)
    return {
        "message": "User registered",
        "user_id": user_id,
        "public_key": public_key  # Return to allow peer to use it
    }

@app.websocket("/ws/{username}")
async def chat_socket(websocket: WebSocket, username: str):
    user = next((u for u in users if u['username'] == username), None)
    if not user:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    active_connections[username] = websocket

    # Step 1: Receive peer's public key
    peer_data = await websocket.receive_json()
    peer_public_key_bytes = bytes.fromhex(peer_data['public_key'])
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)

    # Step 2: Compute shared key using ECDH
    private_key = user['private_key']
    shared_key = private_key.exchange(peer_public_key)

    # Derive a symmetric key from shared key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'chat app',
    ).derive(shared_key)

    shared_keys[username] = derived_key
    await websocket.send_text("🔐 Secure connection established!")

    try:
        while True:
            enc_data = await websocket.receive_json()
            to_user = enc_data["to"]
            ciphertext = bytes.fromhex(enc_data["ciphertext"])
            nonce = bytes.fromhex(enc_data["nonce"])


            if to_user not in active_connections:
                await websocket.send_text(f"User '{to_user}' is not connected.")
                continue

            # Forward encrypted message
            receiver_ws = active_connections[to_user]
            await receiver_ws.send_json({
                "from": username,
                "ciphertext": enc_data["ciphertext"],
                "nonce": enc_data["nonce"]
            })

    except WebSocketDisconnect:
        del active_connections[username]
        del shared_keys[username]
        print(f"{username} disconnected")

'''