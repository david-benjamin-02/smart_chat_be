from fastapi import APIRouter, HTTPException
from app.models.user_models import RegisterRequest, LoginRequest, ForgotPasswordRequest
from app.config.database import user_collection, contact_collection
import uuid, bcrypt
from cryptography.hazmat.primitives.asymmetric import x25519

router = APIRouter(prefix="/auth", tags=["Auth"])

# ✅ REGISTER USER
@router.post("/register")
async def register_user(request: RegisterRequest):
    if await user_collection.find_one(
        {"$or": [{"email": request.email}, {"phone_number": request.phone}]}
    ):
        raise HTTPException(status_code=400, detail="Email or phone already registered")

    user_id = str(uuid.uuid4())
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw().hex()
    hashed = bcrypt.hashpw(request.password.encode(), bcrypt.gensalt()).decode()

    await user_collection.insert_one({
        "uid": user_id,
        "name": request.username,
        "phone_number": request.phone,
        "email": request.email,
        "password": hashed,
        "private_key": private_key.private_bytes_raw().hex(),
        "public_key": public_key,
    })
    await contact_collection.insert_one({"owner_uid": user_id, "contacts": []})

    return {"message": "User registered", "user_id": user_id, "public_key": public_key}


# ✅ LOGIN USER
@router.post("/login")
async def login_user(request: LoginRequest):
    user = await user_collection.find_one({"email": request.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not bcrypt.checkpw(request.password.encode(), user["password"].encode()):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return {
            "message": "Login successful",
            "user_id": user["uid"],
            "user_default_lang": user["settings"]["receiver_lang"],
            "username": user.get("username", user["name"]),
            "public_key": user["public_key"],
            "sender_lang": user["settings"]["sender_lang"],
        }

# ✅ FORGOT PASSWORD (optional)
@router.post("/forgot-password")
async def forgot_password(request: ForgotPasswordRequest):
    user = await user_collection.find_one({"email": request.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # You can send an email or temporary code here later
    return {"message": f"Password reset link sent to {request.email}"}

@router.get("/user-email/{uid}")
async def get_user_email(uid: str):
    user = await user_collection.find_one({"uid": uid}, {"email": 1, "_id": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"email": user["email"]}
