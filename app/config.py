import os


class Config:
    DATABASE_URL = os.getenv(
        "DATABASE_URL", "postgresql+asyncpg://svitsov:svitsov123@postgres:5432/auth_db"
    )
    REDIS_HOST = os.getenv("REDIS_HOST", "redis")
    REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
    JWT_SECRET = os.getenv("JWT_SECRET", "default-secret-change-me")
    JWT_ACCESS_TTL_MINUTES = int(os.getenv("JWT_ACCESS_TTL_MINUTES", "15"))
    JWT_REFRESH_TTL_DAYS = int(os.getenv("JWT_REFRESH_TTL_DAYS", "7"))


config = Config()
