from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.constatns import ONE_DAY, REFRESH_LIMIT, ONE_MINUTE, REGISTER_LIMIT
from app.database import get_db
from app.models import User
from app.auth import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_token_type,
)
from app.redis_client import (
    add_to_whitelist,
    remove_from_whitelist,
    add_to_blacklist,
    is_in_whitelist,
    check_rate_limit,
    check_login_rate_limit,
)
from app.config import config
import uuid
import time

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post("/register")
async def register(
    username: str,
    email: str,
    password: str,
    request: Request,
    role: str = "user",
    db: AsyncSession = Depends(get_db),
):
    client_ip = request.client.host if request.client else "unknown"
    if await check_rate_limit(
        client_ip, "register", limit=REGISTER_LIMIT, window=ONE_MINUTE
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many registration attempts. Try again later.",
        )
    if len(password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password too short (min 6 chars)",
        )
    result = await db.execute(select(User).where(User.username == username))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Username already exists"
        )
    result = await db.execute(select(User).where(User.email == email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Email already exists"
        )
    hashed = hash_password(password)
    new_user = User(username=username, email=email, hashed_password=hashed, role=role)
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    return {"message": "User created", "user_id": new_user.id, "role": new_user.role}


@router.post("/login")
async def login(
    username: str, password: str, request: Request, db: AsyncSession = Depends(get_db)
):
    client_ip = request.client.host if request.client else "unknown"
    if await check_login_rate_limit(client_ip, username):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Please try again later.",
        )
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    session_id = str(uuid.uuid4())
    access_token, _ = create_access_token(user.id, user.role)
    refresh_token, _ = create_refresh_token(user.id, session_id)
    refresh_ttl = config.JWT_REFRESH_TTL_DAYS * ONE_DAY
    await add_to_whitelist(user.id, session_id, refresh_ttl)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": config.JWT_ACCESS_TTL_MINUTES * ONE_MINUTE,
    }


@router.post("/refresh")
async def refresh(
    refresh_token: str, request: Request, db: AsyncSession = Depends(get_db)
):
    client_ip = request.client.host if request.client else "unknown"
    if await check_rate_limit(
        client_ip, "refresh", limit=REFRESH_LIMIT, window=ONE_MINUTE
    ):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many refresh requests",
        )
    token_type = get_token_type(refresh_token)
    if token_type != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type"
        )
    payload = decode_token(refresh_token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    user_id = int(payload.get("sub"))
    session_id = payload.get("sid")
    if not await is_in_whitelist(user_id, session_id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token revoked"
        )
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
        )
    new_access_token, _ = create_access_token(user.id, user.role)
    return {"access_token": new_access_token, "token_type": "bearer"}


@router.post("/logout")
async def logout(access_token: str, refresh_token: str, request: Request):
    access_payload = decode_token(access_token)
    if access_payload and access_payload.get("type") == "access":
        jti = access_payload.get("jti")
        exp = access_payload.get("exp")
        now = int(time.time())
        ttl = max(0, exp - now)
        if ttl > 0:
            await add_to_blacklist(jti, ttl)
    refresh_payload = decode_token(refresh_token)
    if refresh_payload and refresh_payload.get("type") == "refresh":
        user_id = int(refresh_payload.get("sub"))
        session_id = refresh_payload.get("sid")
        await remove_from_whitelist(user_id, session_id)
    return {"message": "Logged out successfully"}
