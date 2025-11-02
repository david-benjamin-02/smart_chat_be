from googletrans import Translator
from fastapi.responses import JSONResponse

translator = Translator()

async def translate_text(text, language):
    try:
        detected = translator.detect(text)
        src_lang = detected.lang
        if src_lang == language:
            return {"translated_text": text, "source_lang": src_lang}
        translated = translator.translate(text, src=src_lang, dest=language).text
        return {"translated_text": translated, "source_lang": src_lang}
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": f"Translation error: {e}"})
