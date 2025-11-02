from pydantic import BaseModel

class SettingsUpdate(BaseModel):
    uid: str
    receiver_lang: str | None = None
    sender_lang: str | None = None
    message_format: str | None = None
