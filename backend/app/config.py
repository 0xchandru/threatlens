from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY:  str = ""
    ALIENVAULT_API_KEY: str = ""

    DATABASE_URL: str = "sqlite:///./threatlens.db"
    REDIS_URL:    str = "redis://localhost:6379/0"

    SECRET_KEY:   str = "change-this-in-production"
    ALGORITHM:    str = "HS256"
    TOKEN_EXPIRE: int = 480

    RATE_LIMIT:   int = 200

    CORS_ORIGINS: str = "*"

    class Config:
        env_file = ".env"

settings = Settings()
