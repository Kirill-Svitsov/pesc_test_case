import pytest_asyncio
from unittest.mock import AsyncMock, MagicMock
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.database import get_db


@pytest_asyncio.fixture(scope="function")
async def client(mocker):
    """Предоставляет тестовый клиент с моками БД и Redis-зависимостей."""
    mocker.patch("app.routers.auth.check_rate_limit", new=AsyncMock(return_value=False))
    mocker.patch(
        "app.routers.auth.check_login_rate_limit", new=AsyncMock(return_value=False)
    )
    mocker.patch("app.routers.auth.add_to_whitelist", new=AsyncMock())
    mocker.patch("app.routers.auth.add_to_blacklist", new=AsyncMock())
    mocker.patch("app.routers.auth.remove_from_whitelist", new=AsyncMock())
    mocker.patch("app.routers.auth.is_in_whitelist", new=AsyncMock(return_value=True))
    mock_session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalar_one_or_none = MagicMock(return_value=None)
    mock_session.execute = AsyncMock(return_value=mock_result)
    mock_session.commit = AsyncMock()
    mock_session.add = MagicMock()
    mock_session.refresh = AsyncMock()

    async def override_get_db():
        yield mock_session

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c, mock_session
    app.dependency_overrides.clear()
