# app/routes/chat_routes.py
from fastapi import APIRouter, HTTPException
from app.config.database import chat_collection, user_collection, contact_collection
from datetime import datetime
from pymongo import DESCENDING

router = APIRouter(prefix="/chat", tags=["Chat"])

# existing history & delete routes (keep them)
@router.get("/history/{chat_id}")
async def get_chat_history(chat_id: str):
    cursor = (
        chat_collection.find({"chat_id": chat_id})
        .sort("created_at", DESCENDING)
        .limit(20)
    )
    messages = []
    async for doc in cursor:
        messages.append({
            "id": str(doc.get("message_id")),
            "message_text": doc.get("message_text"),
            "sender_id": doc.get("sender_id"),
            "receiver_id": doc.get("receiver_id"),
            "message_type": doc.get("message_type"),
            "status": doc.get("status", "sent"),
            "date": doc.get("date"),
            "time": doc.get("time"),
            "created_at": doc.get("created_at"),
        })
    return {"messages": messages[::-1]}


@router.delete("/{chat_id}")
async def delete_chat(chat_id: str):
    result = await chat_collection.delete_many({"chat_id": chat_id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Chat not found")
    return {"message": "Chat deleted successfully"}


# === Restored original get_user_contacts logic ===
@router.get("/user-contacts/{uid}")
async def get_user_contacts(uid: str):
    print("in")
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
                    "status": doc.get("status", "sent"),
                    "created_at": doc.get("created_at"),
                }
            )

        enriched_contacts.append(
            {"uid": contact_uid, "name": contact_name, "recent_messages": messages}
        )

    # Get unread counts
    unread_cursor = await chat_collection.aggregate(
        [
            {"$match": {"receiver_id": uid, "status": {"$ne": "read"}}},
            {"$group": {"_id": "$sender_id", "count": {"$sum": 1}}},
        ]
    ).to_list(None)

    unread_map = {item["_id"]: item["count"] for item in unread_cursor}

    # Attach unread count to each contact
    for contact in enriched_contacts:
        contact["unread_count"] = unread_map.get(contact["uid"], 0)

    # --- Append unknown senders ---
    known_uids = {c["uid"] for c in enriched_contacts}

    # Find all unknown senders who messaged this user
    unknown_sender_ids = await chat_collection.distinct(
        "sender_id", {"receiver_id": uid}
    )
    unknown_sender_ids = [
        sid for sid in unknown_sender_ids if sid not in known_uids and sid != uid
    ]

    for sender_id in unknown_sender_ids:
        user = await user_collection.find_one({"uid": sender_id}, {"email": 1})
        if not user:
            continue

        sender_segment = sender_id.split("-")[-1]
        owner_segment = uid.split("-")[-1]
        chat_key = "_".join(sorted([sender_segment, owner_segment]))

        # Get last 10 messages for this unknown sender
        cursor = (
            chat_collection.find({"chat_id": chat_key})
            .sort("created_at", DESCENDING)
            .limit(10)
        )

        messages = []
        async for doc in cursor:
            print("doc", doc)
            messages.append(
                {
                    "id": str(doc.get("message_id")),
                    "message_text": doc.get("message_text"),
                    "sender_id": doc.get("sender_id"),
                    "receiver_id": doc.get("receiver_id"),
                    "message_type": doc.get("message_type"),
                    "date": doc.get("date"),
                    "time": doc.get("time"),
                    "status": doc.get("status", "sent"),
                    "created_at": doc.get("created_at"),
                }
            )

        enriched_contacts.append(
            {
                "uid": sender_id,
                "name": user["email"],
                "recent_messages": messages,
                "unread_count": unread_map.get(sender_id, 0),
                "is_unknown": True,
            }
        )

    # ✅ Sort by latest message
    enriched_contacts.sort(
        key=lambda contact: (
            contact["recent_messages"][0]["created_at"]
            if contact["recent_messages"]
            else datetime.min
        ),
        reverse=True,
    )

    return {"contacts": enriched_contacts}
