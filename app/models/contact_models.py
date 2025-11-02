from pydantic import BaseModel, EmailStr

class ContactAddRequest(BaseModel):
    current_user_uid: str
    contact_email: EmailStr
    contact_name: str

class UpdateContactName(BaseModel):
    name: str
