from pydantic import BaseModel

class MessageModel(BaseModel):
    id: str
    msg_text: str
    msg_type: str
    senderId: str
    receiverId: str
    date: str
    time: str
