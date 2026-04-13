import uuid
import time
from jose import jwt, JWTError
import bcrypt
from app.config import config
from app.constatns import ONE_DAY, ONE_MINUTE

TOKEN_TYPE_ACCESS = "access"
TOKEN_TYPE_REFRESH = "refresh"


def hash_password(password: str) -> str:
    """Хеширует пароль с помощью bcrypt."""
    password = password[:72]
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Проверяет пароль."""
    plain = plain[:72]
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def create_access_token(user_id: int, role: str):
    jti = str(uuid.uuid4())
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "role": role,
        "jti": jti,
        "type": TOKEN_TYPE_ACCESS,
        "iat": now,
        "exp": now + (config.JWT_ACCESS_TTL_MINUTES * ONE_MINUTE),
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm="HS256"), jti


def create_refresh_token(user_id: int, session_id: str):
    jti = str(uuid.uuid4())
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "sid": session_id,
        "jti": jti,
        "type": TOKEN_TYPE_REFRESH,
        "iat": now,
        "exp": now + (config.JWT_REFRESH_TTL_DAYS * ONE_DAY),
    }
    return jwt.encode(payload, config.JWT_SECRET, algorithm="HS256"), jti


def decode_token(token: str):
    try:
        return jwt.decode(token, config.JWT_SECRET, algorithms=["HS256"])
    except JWTError:
        return None


def get_token_type(token: str):
    payload = decode_token(token)
    return payload.get("type") if payload else None
