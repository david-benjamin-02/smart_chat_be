from app.config.database import user_collection

def merge_sorted_uuid_segments(uid1: str, uid2: str) -> str:
    """Create a stable chat_id from two UUIDs (order independent)."""
    seg1, seg2 = uid1.split("-")[-1], uid2.split("-")[-1]
    return "_".join(sorted([seg1, seg2]))

async def fetch_receiver_data(receiver_id: str):
    """Fetch receiver language and message format settings."""
    user = await user_collection.find_one(
        {"uid": receiver_id},
        {"settings.receiver_lang": 1, "settings.message_format": 1, "_id": 0},
    )
    return user.get("settings", {}) if user else {}
