from fastapi import APIRouter, HTTPException
from app.models.contact_models import ContactAddRequest, UpdateContactName
from app.config.database import user_collection, contact_collection
from bson import ObjectId

router = APIRouter(prefix="/contacts", tags=["Contacts"])


# === Add Contact ===
@router.post("/add")
async def add_contact(data: ContactAddRequest):
    current_user = await user_collection.find_one({"uid": data.current_user_uid})
    if not current_user:
        raise HTTPException(status_code=404, detail="User not found")

    contact_user = await user_collection.find_one({"email": data.contact_email})
    if not contact_user:
        raise HTTPException(status_code=404, detail="Contact not registered")

    contact_info = {
        "contact_id": str(ObjectId()),
        "uid": contact_user["uid"],
        "name": data.contact_name,
        "email": data.contact_email,
    }

    await contact_collection.update_one(
        {"owner_uid": data.current_user_uid},
        {"$addToSet": {"contacts": contact_info}},
    )

    return {"message": "Contact added successfully"}


# === Get All Contacts ===
@router.get("/{uid}")
async def get_contacts(uid: str):
    contact_doc = await contact_collection.find_one(
        {"owner_uid": uid}, {"_id": 0, "contacts": 1}
    )
    if not contact_doc:
        raise HTTPException(status_code=404, detail="No contacts found for this user")

    return {"contacts": contact_doc.get("contacts", [])}


# === Update Contact Name ===
@router.patch("/edit/{uid}/{contact_id}")
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
        raise HTTPException(status_code=404, detail="Contact not found")

    await contact_collection.update_one(
        {"owner_uid": uid}, {"$set": {"contacts": contact_doc["contacts"]}}
    )

    return {"message": "Contact name updated successfully"}


# === Delete Contact ===
@router.delete("/delete/{uid}/{contact_id}")
async def delete_contact(uid: str, contact_id: str):
    result = await contact_collection.update_one(
        {"owner_uid": uid},
        {"$pull": {"contacts": {"contact_id": contact_id}}},
    )

    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Contact not found")

    return {"message": "Contact deleted successfully"}

# === Get Contact Detail ===
@router.get("/detail/{uid}/{contact_id}")
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

