from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from app.utils.audio_utils import speech_to_text, text_to_audio
from app.utils.translation_utils import translate_text
import os, io
from fastapi.responses import JSONResponse
from datetime import datetime
from app.utils.chat_utils import fetch_receiver_data
from starlette.datastructures import UploadFile as StarletteUploadFile

router = APIRouter(prefix="/utils", tags=["Utilities"])
UPLOAD_FOLDER = "app/static/uploads"

@router.post("/speech-to-text")
async def speech_to_text_route(audio: UploadFile = File(...)):
    return await speech_to_text(audio)

@router.post("/text-to-audio")
async def text_to_audio_route(text: str = Form(...), language: str = Form("en")):
    return text_to_audio(text, language)

@router.post("/translate")
async def translate_text_route(text: str = Form(...), language: str = Form("en")):
    return await translate_text(text, language)


@router.post("/upload-voice")
async def upload_voice(receiverId: str = Form(...), file: UploadFile = File(...)):
    try:
        # --- Generate unique file name ---
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"voice_{timestamp}.webm"
        file_location = os.path.join(UPLOAD_FOLDER, filename)

        # --- Read & save the file ---
        content = await file.read()
        print("🔧 Saving to:", file_location)
        if not os.path.exists(UPLOAD_FOLDER):
            os.makedirs(UPLOAD_FOLDER)

        with open(file_location, "wb") as f:
            f.write(content)

        # --- Fetch receiver's settings ---
        receiverSettings = await fetch_receiver_data(receiverId)
        message_format = receiverSettings.get("message_format")
        receiver_lang = receiverSettings.get("receiver_lang")
        trans_message = ""

        # --- Transcribe only if receiver expects Text or has language preference ---
        if message_format == "Text" or receiver_lang:
            print("🧠 Transcribing voice for receiver expecting text...")
            fake_upload = StarletteUploadFile(filename=filename, file=io.BytesIO(content))
            result = await speech_to_text(fake_upload)

            if isinstance(result, dict) and "corrected_text" in result:
                trans_message = result["corrected_text"]
            else:
                trans_message = "[Could not transcribe audio]"

        return {
            "success": True,
            "file_url": f"/uploads/{filename}",
            "transcription": trans_message,
        }

    except Exception as e:
        print("❌ Error saving voice file:", e)
        return JSONResponse(status_code=500, content={"error": str(e)})