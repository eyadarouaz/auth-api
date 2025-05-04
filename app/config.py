import os

from dotenv import load_dotenv

load_dotenv()


class Settings:
    DATABASE_URI: str = os.getenv("DATABASE_URI")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your_secret_key")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    CONNECTION_STRING: str = os.getenv("AZURE_SERVICE_BUS_CONNECTION_STRING")
    QUEUE_NAME: str = os.getenv("AZURE_SERVICE_BUS_QUEUE_NAME")


settings = Settings()
