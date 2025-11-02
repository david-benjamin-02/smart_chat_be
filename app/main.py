from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from app.middleware.cors import setup_cors
from app.routes import (
    auth_routes,
    contact_routes,
    settings_routes,
    chat_routes,
    utility_routes,
    websocket_routes,
)

app = FastAPI(title="Smart Chat", version="1.0")

# Setup CORS
setup_cors(app)

# Mount static uploads
app.mount("/uploads", StaticFiles(directory="app/static/uploads"), name="uploads")

# Include all route modules
app.include_router(auth_routes.router)
app.include_router(contact_routes.router)
app.include_router(settings_routes.router)   # ✅ Add this
app.include_router(chat_routes.router)       # ✅ Add this
app.include_router(utility_routes.router)
app.include_router(websocket_routes.router)  # ✅ For WebSocket features

@app.get("/")
def root():
    return {"message": "Smart Chat Backend is running 🚀"}
