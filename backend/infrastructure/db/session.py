"""
NovaGuard — Engine e SessionMaker SQLAlchemy (Async).

Configura:
  - Engine assíncrono (asyncpg) para operações normais.
  - Engine síncrono (psycopg2) para tarefas Celery.
  - SessionMaker para injeção de dependência via FastAPI.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session, sessionmaker

from backend.core.config import get_settings

logger = logging.getLogger(__name__)

# ── Engines ──────────────────────────────────────────────────────

_settings = get_settings()

# Engine assíncrono (FastAPI)
async_engine = create_async_engine(
    _settings.database_url,
    echo=_settings.app_env == "development",
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,
    pool_recycle=3600,
)

# Engine síncrono (Celery workers)
sync_engine = create_engine(
    _settings.database_url_sync,
    echo=False,
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,
    pool_recycle=3600,
)

# ── Session Factories ────────────────────────────────────────────

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

SyncSessionLocal = sessionmaker(
    bind=sync_engine,
    class_=Session,
    expire_on_commit=False,
)


# ── Dependency Injection (FastAPI) ───────────────────────────────


async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Gera uma sessão assíncrona para uso como dependência do FastAPI.
    A sessão é fechada automaticamente ao final do request.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


def get_sync_session() -> Session:
    """
    Retorna uma sessão síncrona para uso nos workers Celery.
    O caller é responsável por fechar a sessão.
    """
    return SyncSessionLocal()
