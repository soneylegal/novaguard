"""
NovaGuard — Testes E2E: API Endpoints.

Testa as rotas da API de ponta a ponta usando httpx TestClient.
Requer mocking do Celery e Redis para evitar dependência de infra.

Usa FastAPI dependency_overrides para substituir get_settings e
get_async_session, evitando qualquer acesso a infra real.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from backend.core.config import Settings, get_settings


def _make_test_settings() -> MagicMock:
    """Cria um objeto Settings mockado com valores de teste."""
    s = MagicMock(spec=Settings)
    s.api_keys = ["test-key-001", "test-key-002"]
    s.rate_limit = "1000/minute"
    s.redis_url = "redis://localhost:6379/0"
    s.celery_broker_url = "redis://localhost:6379/1"
    s.celery_result_backend = "redis://localhost:6379/2"
    s.app_env = "testing"
    s.cache_ttl_seconds = 86400
    s.bulk_insert_size = 1000
    s.database_url = "postgresql+asyncpg://novaguard:novaguard_secret@localhost:5432/novaguard_db"
    s.database_url_sync = (
        "postgresql+psycopg2://novaguard:novaguard_secret@localhost:5432/novaguard_db"
    )
    s.is_production = False
    s.app_name = "NovaGuard"
    s.log_level = "INFO"
    return s


@pytest.fixture
def client():
    """
    TestClient com todas as dependências de infra mockadas.

    Usa dependency_overrides do FastAPI para que get_settings retorne
    os settings de teste, evitando que a validação de API keys use
    as chaves do .env.
    """
    test_settings = _make_test_settings()

    with (
        patch("backend.api.v1.ingest_router.celery_app") as mock_celery,
        patch("backend.core.cache._redis_client", new=None),
        patch("backend.core.cache.get_redis") as mock_get_redis,
        patch("backend.main.get_settings", return_value=test_settings),
    ):
        mock_celery.send_task = MagicMock()

        mock_redis_instance = AsyncMock()
        mock_redis_instance.ping = AsyncMock(return_value=True)
        mock_get_redis.return_value = mock_redis_instance

        from backend.main import app

        # Override FastAPI DI — this is the correct way to inject test deps
        app.dependency_overrides[get_settings] = lambda: test_settings

        with TestClient(app, raise_server_exceptions=False) as c:
            yield c

        # Cleanup
        app.dependency_overrides.clear()


class TestRootEndpoint:
    """Testes para o endpoint raiz."""

    def test_root_returns_platform_info(self, client):
        """GET / deve retornar informações da plataforma."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["platform"] == "NovaGuard"
        assert data["version"] == "1.0.0"


class TestIngestEndpoint:
    """Testes para o endpoint de ingestão."""

    def test_ingest_without_api_key(self, client):
        """POST sem API Key deve retornar 401."""
        response = client.post(
            "/api/v1/ingest/",
            json={
                "logs": [
                    {
                        "source_ip": "10.0.0.1",
                        "destination_ip": "8.8.8.8",
                        "domain": "test.com",
                    }
                ],
                "agent_id": "test-agent",
            },
        )
        assert response.status_code == 401

    def test_ingest_with_invalid_api_key(self, client):
        """POST com API Key inválida deve retornar 403."""
        response = client.post(
            "/api/v1/ingest/",
            json={
                "logs": [
                    {
                        "source_ip": "10.0.0.1",
                        "destination_ip": "8.8.8.8",
                        "domain": "test.com",
                    }
                ],
                "agent_id": "test-agent",
            },
            headers={"X-API-KEY": "invalid-key"},
        )
        assert response.status_code == 403

    def test_ingest_with_invalid_payload(self, client):
        """POST com payload inválido deve retornar 422."""
        response = client.post(
            "/api/v1/ingest/",
            json={"logs": [], "agent_id": "test"},
            headers={"X-API-KEY": "test-key-001"},
        )
        assert response.status_code == 422

    def test_ingest_valid_batch(self, client):
        """POST com batch válido deve retornar 202."""
        response = client.post(
            "/api/v1/ingest/",
            json={
                "logs": [
                    {
                        "source_ip": "192.168.1.10",
                        "destination_ip": "8.8.8.8",
                        "domain": "google.com",
                        "query_type": "A",
                    },
                    {
                        "source_ip": "192.168.1.11",
                        "destination_ip": "8.8.4.4",
                        "domain": "github.com",
                        "query_type": "AAAA",
                    },
                ],
                "agent_id": "test-agent-001",
                "batch_sequence": 1,
            },
            headers={"X-API-KEY": "test-key-001"},
        )
        assert response.status_code == 202
        data = response.json()
        assert data["status"] == "accepted"
        assert data["log_count"] == 2
        assert "batch_id" in data


class TestSecurityMiddleware:
    """Testes para a camada de segurança."""

    def test_request_id_header(self, client):
        """Toda resposta deve conter X-Request-ID."""
        response = client.get("/")
        assert "X-Request-ID" in response.headers
        assert len(response.headers["X-Request-ID"]) == 36  # UUID format
