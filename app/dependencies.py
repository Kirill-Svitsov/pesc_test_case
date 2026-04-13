from fastapi import Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db
from app.redis_client import (
    is_blacklisted,
    check_suspicious_ip,
    check_suspicious_user_agent,
)
from app.auth import decode_token, get_token_type, TOKEN_TYPE_ACCESS
from app.models import User


async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
        )
    token = auth_header.split(" ")[1]
    token_type = get_token_type(token)
    if token_type != TOKEN_TYPE_ACCESS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type"
        )
    payload = decode_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
        )
    if await is_blacklisted(payload.get("jti")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked"
        )
    result = await db.execute(select(User).where(User.id == int(payload.get("sub"))))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found"
        )
    client_ip = request.client.host if request.client else "unknown"
    client_ua = request.headers.get("User-Agent", "unknown")
    await check_suspicious_ip(user.id, client_ip)
    await check_suspicious_user_agent(user.id, client_ua)
    return user


def require_role(required_role: str):
    """Возвращает функцию-зависимость для проверки роли.
    Admin имеет доступ ко всем ресурсам независимо от required_role.
    """

    async def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role == "admin":
            return current_user
        if current_user.role != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{required_role}' required",
            )
        return current_user

    return role_checker
