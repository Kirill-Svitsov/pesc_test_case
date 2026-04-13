import pytest
from unittest.mock import AsyncMock

from app.models import User


@pytest.mark.asyncio
async def test_register_success(client, mocker):
    """Проверяет успешную регистрацию пользователя с валидными данными."""
    c, mock_db = client
    mocker.patch("app.routers.auth.hash_password", return_value="hashed")
    mock_db.execute.return_value.scalar_one_or_none.return_value = None
    resp = await c.post(
        "/auth/register",
        params={"username": "new", "email": "n@t.com", "password": "pass123"},
    )
    assert resp.status_code == 200
    assert resp.json()["message"] == "User created"


@pytest.mark.asyncio
async def test_login_success(client, mocker):
    """Проверяет успешный вход с корректными учётными данными."""
    c, mock_db = client
    mocker.patch("app.routers.auth.verify_password", return_value=True)
    mocker.patch("app.routers.auth.create_access_token", return_value=("acc", 900))
    mocker.patch("app.routers.auth.create_refresh_token", return_value=("ref", 86400))
    user = User(id=1, username="u", email="e@e.com", hashed_password="x", role="user")
    mock_db.execute.return_value.scalar_one_or_none.return_value = user
    resp = await c.post("/auth/login", params={"username": "u", "password": "correct"})
    assert resp.status_code == 200
    assert resp.json()["access_token"] == "acc"


@pytest.mark.asyncio
async def test_login_wrong_password(client, mocker):
    """Проверяет отказ во входе при неверном пароле."""
    c, mock_db = client
    mocker.patch("app.routers.auth.verify_password", return_value=False)
    user = User(id=1, username="u", email="e@e.com", hashed_password="x", role="user")
    mock_db.execute.return_value.scalar_one_or_none.return_value = user
    resp = await c.post("/auth/login", params={"username": "u", "password": "wrong"})
    assert resp.status_code == 401
    assert "Invalid credentials" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_get_content_with_token(client, mocker):
    """Проверяет доступ к защищённому эндпоинту с валидным токеном."""
    c, mock_db = client
    mocker.patch(
        "app.dependencies.decode_token",
        return_value={"sub": "1", "jti": "j", "type": "access", "exp": 9999},
    )
    mocker.patch("app.dependencies.get_token_type", return_value="access")
    mocker.patch("app.dependencies.is_blacklisted", return_value=False)
    mocker.patch("app.dependencies.check_suspicious_ip", new=AsyncMock())
    mocker.patch("app.dependencies.check_suspicious_user_agent", new=AsyncMock())
    user = User(id=1, username="u", email="e@e.com", hashed_password="x", role="user")
    mock_db.execute.return_value.scalar_one_or_none.return_value = user
    resp = await c.get("/content/common", headers={"Authorization": "Bearer any"})
    assert resp.status_code == 200
    assert resp.json()["user"] == "u"


@pytest.mark.asyncio
async def test_refresh_token_success(client, mocker):
    """Проверяет успешное обновление access-токена через валидный refresh-токен."""
    c, mock_db = client
    mocker.patch("app.routers.auth.get_token_type", return_value="refresh")
    mocker.patch(
        "app.routers.auth.decode_token",
        return_value={"sub": "1", "type": "refresh", "sid": "s"},
    )
    mocker.patch("app.routers.auth.create_access_token", return_value=("new_acc", 900))
    mocker.patch("app.routers.auth.is_in_whitelist", return_value=True)
    user = User(id=1, username="u", email="e@e.com", hashed_password="x", role="user")
    mock_db.execute.return_value.scalar_one_or_none.return_value = user
    resp = await c.post("/auth/refresh", params={"refresh_token": "valid"})
    assert resp.status_code == 200
    assert resp.json()["access_token"] == "new_acc"
