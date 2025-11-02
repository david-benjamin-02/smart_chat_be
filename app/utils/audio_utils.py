import io, os, uuid
from gtts import gTTS
from pydub import AudioSegment
import speech_recognition as sr
from fastapi.responses import JSONResponse
import language_tool_python

tool = language_tool_python.LanguageTool("en-US")

async def speech_to_text(audio):
    try:
        audio_data = await audio.read()
        segment = AudioSegment.from_file(io.BytesIO(audio_data))
        wav_io = io.BytesIO()
        segment.export(wav_io, format="wav")
        wav_io.seek(0)

        recognizer = sr.Recognizer()
        with sr.AudioFile(wav_io) as source:
            recorded = recognizer.record(source)
            original_text = recognizer.recognize_google(recorded)
            corrected_text = tool.correct(original_text)
        return {"original_text": original_text, "corrected_text": corrected_text}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

async def text_to_audio(text, language):
    filename = f"{uuid.uuid4()}.mp3"
    path = os.path.join("app/static/uploads", filename)
    gTTS(text=text, lang=language).save(path)
    return {"audio_file": f"/uploads/{filename}"}
