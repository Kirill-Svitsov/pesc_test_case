import redis.asyncio as redis
from app.config import config
from app.constatns import (
    ONE_HOUR,
    ONE_MINUTE,
    REDIS_LIMIT,
    TEN_MINUTES,
    LOGIN_IP_LIMIT,
    LOGIN_USER_LIMIT,
)

# Константы для ключей
KEY_BLACKLIST_PREFIX = "blacklist:access:"
KEY_WHITELIST_PREFIX = "whitelist:refresh:"
KEY_USER_LAST_IP_PREFIX = "user:"
KEY_USER_SUSPICIOUS_PREFIX = "user:"
KEY_USER_LAST_UA_PREFIX = "user:"
KEY_RATE_LIMIT_PREFIX = "rate:"

redis_client = None


async def init_redis():
    """Инициализирует подключение к Redis."""
    global redis_client
    redis_client = await redis.from_url(
        f"redis://{config.REDIS_HOST}:{config.REDIS_PORT}", decode_responses=True
    )
    return redis_client


async def close_redis():
    """Закрывает соединение с Redis."""
    if redis_client:
        await redis_client.close()


async def add_to_blacklist(jti: str, ttl_seconds: int):
    """Добавляет access токен в чёрный список."""
    await redis_client.setex(f"{KEY_BLACKLIST_PREFIX}{jti}", ttl_seconds, "revoked")


async def is_blacklisted(jti: str) -> bool:
    """Проверяет, находится ли access токен в чёрном списке."""
    return await redis_client.exists(f"{KEY_BLACKLIST_PREFIX}{jti}") > 0


async def add_to_whitelist(user_id: int, session_id: str, ttl_seconds: int):
    """Добавляет refresh сессию в белый список."""
    await redis_client.setex(
        f"{KEY_WHITELIST_PREFIX}{user_id}:{session_id}", ttl_seconds, "active"
    )


async def is_in_whitelist(user_id: int, session_id: str) -> bool:
    """Проверяет, активна ли refresh сессия."""
    return (
        await redis_client.exists(f"{KEY_WHITELIST_PREFIX}{user_id}:{session_id}") > 0
    )


async def remove_from_whitelist(user_id: int, session_id: str):
    """Удаляет refresh сессию из белого списка (logout)."""
    await redis_client.delete(f"{KEY_WHITELIST_PREFIX}{user_id}:{session_id}")


async def revoke_all_user_sessions(user_id: int):
    """Отзывает все активные сессии пользователя (при подозрении на кражу)."""
    pattern = f"{KEY_WHITELIST_PREFIX}{user_id}:*"
    async for key in redis_client.scan_iter(match=pattern):
        await redis_client.delete(key)


async def check_suspicious_ip(user_id: int, current_ip: str) -> bool:
    """
    Проверяет смену IP на подозрительную активность.
    Блокирует сессии при 5+ сменах IP за 10 минут (устойчиво к VPN).
    Возвращает True, если запрос признан подозрительным.
    """
    last_ip_key = f"{KEY_USER_LAST_IP_PREFIX}{user_id}:last_ip"
    suspicious_key = f"{KEY_USER_SUSPICIOUS_PREFIX}{user_id}:suspicious_count"

    last_ip = await redis_client.get(last_ip_key)

    if last_ip and last_ip != current_ip:
        count = await redis_client.incr(suspicious_key)
        await redis_client.expire(suspicious_key, TEN_MINUTES)

        if count >= 5:
            await revoke_all_user_sessions(user_id)
            return True
    else:
        await redis_client.delete(suspicious_key)

    await redis_client.setex(last_ip_key, ONE_HOUR, current_ip)
    return False


async def check_suspicious_user_agent(user_id: int, current_ua: str) -> bool:
    """
    Проверяет смену User-Agent на подозрительную активность.
    Возвращает True, если User-Agent резко изменился (возможна кража).
    """
    last_ua_key = f"{KEY_USER_LAST_UA_PREFIX}{user_id}:last_ua"
    last_ua = await redis_client.get(last_ua_key)
    if last_ua and last_ua != current_ua:
        suspicious_key = f"{KEY_USER_SUSPICIOUS_PREFIX}{user_id}:ua_changes"
        count = await redis_client.incr(suspicious_key)
        await redis_client.expire(suspicious_key, ONE_HOUR)
        if count >= 3:
            await revoke_all_user_sessions(user_id)
            return True
        return False
    else:
        await redis_client.setex(last_ua_key, ONE_HOUR, current_ua)
    return False


async def check_rate_limit(
    identifier: str, endpoint: str, limit: int = REDIS_LIMIT, window: int = ONE_MINUTE
) -> bool:
    """
    Проверяет лимит запросов (защита от брутфорса и DDoS).
    Args:
        identifier: IP или username
        endpoint: название эндпоинта (например, "login", "register")
        limit: максимальное количество запросов за окно
        window: окно в секундах
    Returns:
        True если лимит превышен, False если можно выполнить запрос
    """
    key = f"{KEY_RATE_LIMIT_PREFIX}{endpoint}:{identifier}"
    count = await redis_client.incr(key)
    if count == 1:
        await redis_client.expire(key, window)
    return count > limit


async def check_login_rate_limit(ip: str, username: str) -> bool:
    """
    Специальная проверка для логина (по IP + username).
    Защита от брутфорса паролей.
    """
    if await check_rate_limit(ip, "login_ip", limit=LOGIN_IP_LIMIT, window=ONE_MINUTE):
        return True
    if await check_rate_limit(
        username, "login_user", limit=LOGIN_USER_LIMIT, window=ONE_MINUTE
    ):
        return True

    return False
