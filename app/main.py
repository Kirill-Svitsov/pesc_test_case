from fastapi import FastAPI, Depends
from fastapi.security import HTTPBearer
from contextlib import asynccontextmanager
import os
from app.database import init_db
from app.redis_client import init_redis, close_redis
from app.routers import auth, content

security = HTTPBearer()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await init_redis()
    print("Database and Redis initialized")
    yield
    await close_redis()
    print("Connections closed")


app = FastAPI(
    title="JWT Auth System with Redis + PostgreSQL",
    description="Асинхронная система авторизации с черным/белым списками токенов",
    version="1.0.0",
    lifespan=lifespan,
    swagger_ui_parameters={"persistAuthorization": True},
)
app.include_router(auth.router)
app.include_router(content.router, dependencies=[Depends(security)])


@app.get("/")
async def root():
    return {
        "message": "JWT Auth System",
        "docs": "/docs",
        "ports": {
            "app": int(os.getenv("APP_PORT", 8055)),
            "redis_host": int(os.getenv("HOST_REDIS_PORT", 6366)),
            "postgres_host": int(os.getenv("HOST_POSTGRES_PORT", 5433)),
        },
    }


@app.get("/health")
async def health():
    return {"status": "ok", "services": ["postgres", "redis"]}
