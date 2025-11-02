from motor.motor_asyncio import AsyncIOMotorClient
from app.config.settings import settings

MONGO_URI = settings.MONGO_URI
client = AsyncIOMotorClient(MONGO_URI)
db = client[settings.DB_NAME]

user_collection = db["users"]
contact_collection = db["contacts"]
chat_collection = db["chats"]
