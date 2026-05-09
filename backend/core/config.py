"""
NovaGuard — Configuração Central via Pydantic Settings.

Todas as variáveis de ambiente são carregadas e validadas automaticamente
a partir de um arquivo `.env` ou do ambiente do sistema.
"""

from __future__ import annotations

import json
from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuração centralizada da plataforma NovaGuard."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ──────────────────────────────────────────────
    app_name: str = "NovaGuard"
    app_env: str = "development"
    log_level: str = "INFO"

    # ── Database (PostgreSQL / TimescaleDB) ──────────────────────
    database_url: str = (
        "postgresql+asyncpg://novaguard:novaguard_secret@localhost:5432/novaguard_db"
    )
    database_url_sync: str = (
        "postgresql+psycopg2://novaguard:novaguard_secret@localhost:5432/novaguard_db"
    )

    # ── Redis (Cache + Celery Broker) ────────────────────────────
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # ── Security ─────────────────────────────────────────────────
    api_keys: list[str] = []

    @field_validator("api_keys", mode="before")
    @classmethod
    def parse_api_keys(cls, v: str | list) -> list:
        """Aceita tanto uma lista Python quanto uma string JSON."""
        if isinstance(v, str):
            return json.loads(v)
        return v

    # ── Rate Limiting ────────────────────────────────────────────
    rate_limit: str = "60/minute"

    # ── Cache ────────────────────────────────────────────────────
    cache_ttl_seconds: int = 86400  # 24 horas

    # ── Bulk Insert ──────────────────────────────────────────────
    bulk_insert_size: int = 1000

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Singleton — garante uma única instância de Settings por processo."""
    return Settings()
