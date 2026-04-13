import pytest
from unittest.mock import AsyncMock, MagicMock, call

from app.redis_client import (
    is_blacklisted,
    revoke_all_user_sessions,
    check_suspicious_ip,
    check_suspicious_user_agent,
    check_rate_limit,
    KEY_BLACKLIST_PREFIX,
    KEY_WHITELIST_PREFIX,
    KEY_USER_SUSPICIOUS_PREFIX,
    TEN_MINUTES,
)


@pytest.fixture(autouse=True)
def mock_redis(mocker):
    """Предоставляет мок-объект Redis для всех тестов в модуле."""
    mock = MagicMock()
    for method in ["setex", "exists", "get", "incr", "delete", "expire", "close"]:
        setattr(mock, method, AsyncMock())

    async def empty_scan(*args, **kwargs):
        return
        yield

    mock.scan_iter = empty_scan
    mocker.patch("app.redis_client.redis_client", mock)
    return mock


@pytest.mark.asyncio
async def test_is_blacklisted_token(mock_redis):
    """Проверяет, что токен в блэклисте корректно определяется."""
    mock_redis.exists.return_value = 1
    result = await is_blacklisted("jti_123")
    assert result is True
    mock_redis.exists.assert_called_once_with(f"{KEY_BLACKLIST_PREFIX}jti_123")


@pytest.mark.asyncio
async def test_suspicious_ip_triggers_revoke(mock_redis, mocker):
    """Проверяет, что 5+ смен IP в окне времени инициируют отзыв сессий."""
    user_id = 42
    new_ip = "10.0.0.99"
    mock_redis.get.return_value = "192.168.1.1"
    mock_redis.incr.return_value = 5
    mocker.patch("app.redis_client.revoke_all_user_sessions", new=AsyncMock())
    result = await check_suspicious_ip(user_id, new_ip)
    assert result is True
    mock_redis.incr.assert_called_with(
        f"{KEY_USER_SUSPICIOUS_PREFIX}{user_id}:suspicious_count"
    )
    mock_redis.expire.assert_any_call(
        f"{KEY_USER_SUSPICIOUS_PREFIX}{user_id}:suspicious_count", TEN_MINUTES
    )


@pytest.mark.asyncio
async def test_suspicious_ua_triggers_revoke(mock_redis, mocker):
    """Проверяет, что 3+ смены User-Agent в окне времени инициируют отзыв сессий."""
    user_id = 42
    new_ua = "Mozilla/5.0 EvilBot"
    mock_redis.get.return_value = "Mozilla/5.0 LegitBrowser"
    mock_redis.incr.return_value = 3
    mocker.patch("app.redis_client.revoke_all_user_sessions", new=AsyncMock())
    result = await check_suspicious_user_agent(user_id, new_ua)
    assert result is True
    suspicious_key = f"{KEY_USER_SUSPICIOUS_PREFIX}{user_id}:ua_changes"
    mock_redis.incr.assert_called_with(suspicious_key)


@pytest.mark.asyncio
async def test_rate_limit_exceeded(mock_redis):
    """Проверяет логику rate limit: первый запрос и превышение лимита."""
    mock_redis.incr.return_value = 1
    result = await check_rate_limit("192.168.1.1", "login", limit=10, window=60)
    assert result is False
    mock_redis.expire.assert_called_with("rate:login:192.168.1.1", 60)
    mock_redis.incr.return_value = 11
    mock_redis.expire.reset_mock()
    result = await check_rate_limit("192.168.1.1", "login", limit=10, window=60)
    assert result is True
    mock_redis.expire.assert_not_called()


@pytest.mark.asyncio
async def test_revoke_all_user_sessions_deletes_keys(mock_redis):
    """Проверяет, что все сессии пользователя удаляются по паттерну."""
    user_id = 42
    keys = [
        f"{KEY_WHITELIST_PREFIX}{user_id}:sess1",
        f"{KEY_WHITELIST_PREFIX}{user_id}:sess2",
    ]

    async def mock_scan_iter(match):
        for key in keys:
            yield key

    mock_redis.scan_iter = mock_scan_iter
    await revoke_all_user_sessions(user_id)
    assert mock_redis.delete.call_count == 2
    calls = [call(k) for k in keys]
    mock_redis.delete.assert_has_calls(calls, any_order=True)
