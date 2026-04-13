# JWT Auth System with Redis + PostgreSQL

Асинхронная система авторизации и аутентификации на FastAPI с поддержкой черного и белого списков токенов, rate limiting и защитой от подозрительной активности.

## Описание

Реализована полнофункциональная система аутентификации с использованием JWT-токенов, где:

- Access-токены хранятся в черном списке (blacklist) при отзыве
- Refresh-токены привязаны к сессиям в белом списке (whitelist)
- Реализована защита от брутфорса через rate limiting
- Детектируется подозрительная активность: частая смена IP и User-Agent
- Поддерживается разграничение доступа по ролям (user, admin)

## Технологический стек

- Язык: Python 3.12
- Фреймворк: FastAPI 0.100+
- База данных: PostgreSQL 15 (asyncpg)
- Кэш и сессии: Redis 7 (redis.asyncio)
- ORM: SQLAlchemy 2.0 (асинхронная)
- Токены: PyJWT 2.8+
- Тестирование: pytest 7.4+, pytest-asyncio, pytest-mock, httpx
- Контейнеризация: Docker, Docker Compose

## Структура проекта
├── app/
│   ├── auth.py                 # Генерация и верификация JWT, хэширование паролей
│   ├── config.py               # Конфигурация приложения через переменные окружения
│   ├── constatns.py            # Константы приложения (таймауты, лимиты)
│   ├── database.py             # Инициализация SQLAlchemy, модель User
│   ├── dependencies.py         # Зависимости FastAPI: get_current_user, require_role
│   ├── main.py                 # Точка входа, регистрация роутеров, lifespan
│   ├── models.py               # SQLAlchemy-модели
│   ├── password_service.py     # Сервис для работы с паролями (bcrypt)
│   ├── redis_client.py         # Клиент Redis и функции для black/white-lists, rate limit
│   └── routers/
│       ├── auth.py             # Эндпоинты: register, login, refresh, logout
│       └── content.py          # Эндпоинты с контентом по ролям
├── tests/
│   ├── conftest.py             # Фикстуры для тестов: клиент, моки БД и Redis
│   ├── test_auth_flow.py       # Интеграционные тесты основных сценариев аутентификации
│   └── test_redis_security.py  # Юнит-тесты функций безопасности из redis_client.py
├── docker-compose.yml          # Оркестрация сервисов: app, postgres, redis
├── Dockerfile                  # Образ приложения
├── requirements.txt            # Зависимости Python
└── README.md                   # Этот файл


## Установка и запуск

### Через Docker (рекомендуется)

1. Создайте файл `.env` на основе `.env.example`:
```
POSTGRES_USER=app_user
POSTGRES_PASSWORD=secure_password
POSTGRES_DB=auth_db
JWT_SECRET=your_super_secret_jwt_key_change_in_production
JWT_ACCESS_TTL_MINUTES=15
JWT_REFRESH_TTL_DAYS=7
HOST_APP_PORT=8055
HOST_POSTGRES_PORT=5433
HOST_REDIS_PORT=6379
```
2. Запустите сервисы:

```
docker-compose up --build
```
Приложение доступно по адресу: http://localhost:8055
Документация API: http://localhost:8055/docs

### Локальная разработка

### Установите зависимости:
```
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
### Запустите инфраструктуру:
```
docker-compose up -d
```

### Запуск всех тестов
```
pytest tests/ -v
```