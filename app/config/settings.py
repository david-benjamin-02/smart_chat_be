# class Settings:
#     PROJECT_NAME = "Smart Chat API"
#     VERSION = "1.0.0"
#     DESCRIPTION = "AI-powered multilingual chat system"

# settings = Settings()

from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    MONGO_URI: str
    DB_NAME: str
    PRIVATE_KEY_PATH: str
    PUBLIC_KEY_PATH: str
    PORT: int
    HOST: str

    class Config:
        env_file = ".env"

settings = Settings()
