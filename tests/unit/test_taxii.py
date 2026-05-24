"""
NovaGuard — Testes Unitários: Servidor TAXII 2.1 e Métricas.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from backend.core.config import Settings, get_settings
from backend.infrastructure.db.models import DNSLog
from backend.infrastructure.db.session import get_async_session
from backend.infrastructure.repositories.log_repo import LogRepository


def _make_test_settings() -> MagicMock:
    s = MagicMock(spec=Settings)
    s.api_keys = ["test-key-001"]
    s.rate_limit = "1000/minute"
    s.redis_url = "redis://localhost:6379/0"
    s.celery_broker_url = "redis://localhost:6379/1"
    s.celery_result_backend = "redis://localhost:6379/2"
    s.app_env = "testing"
    s.is_production = False
    return s


@pytest.fixture
def client():
    test_settings = _make_test_settings()
    mock_session = AsyncMock()

    with (
        patch("backend.core.cache._redis_client", new=None),
        patch("backend.core.cache.get_redis") as mock_get_redis,
        patch("backend.main.get_settings", return_value=test_settings),
    ):
        mock_redis_instance = AsyncMock()
        mock_redis_instance.ping = AsyncMock(return_value=True)
        mock_get_redis.return_value = mock_redis_instance

        from backend.main import app

        app.dependency_overrides[get_settings] = lambda: test_settings
        app.dependency_overrides[get_async_session] = lambda: mock_session

        with TestClient(app, raise_server_exceptions=False) as c:
            yield c

        app.dependency_overrides.clear()


class TestTaxiiDiscovery:
    """Testes para o endpoint de Discovery do TAXII 2.1."""

    def test_discovery_unauthorized(self, client):
        """Acesso sem API Key válida deve retornar 401."""
        response = client.get("/api/v1/taxii2/")
        assert response.status_code == 401

    def test_discovery_success(self, client):
        """Acesso com API Key válida deve retornar os dados de descoberta e cabeçalho correto."""
        response = client.get("/api/v1/taxii2/", headers={"X-API-KEY": "test-key-001"})
        assert response.status_code == 200
        assert response.headers["Content-Type"] == "application/taxii+json;version=2.1"
        data = response.json()
        assert data["title"] == "NovaGuard TAXII 2.1 Server"
        assert "/api/v1/taxii2/root/" in data["api_roots"]


class TestTaxiiApiRoot:
    """Testes para o endpoint do API Root do TAXII 2.1."""

    def test_api_root_success(self, client):
        response = client.get("/api/v1/taxii2/root/", headers={"X-API-KEY": "test-key-001"})
        assert response.status_code == 200
        assert response.headers["Content-Type"] == "application/taxii+json;version=2.1"
        data = response.json()
        assert data["title"] == "NovaGuard API Root"
        assert "2.1" in data["versions"]


class TestTaxiiCollections:
    """Testes para listagem e detalhes das coleções do TAXII 2.1."""

    def test_list_collections(self, client):
        response = client.get(
            "/api/v1/taxii2/root/collections/", headers={"X-API-KEY": "test-key-001"}
        )
        assert response.status_code == 200
        assert response.headers["Content-Type"] == "application/taxii+json;version=2.1"
        data = response.json()
        assert "collections" in data
        assert len(data["collections"]) == 1
        assert data["collections"][0]["id"] == "threat-logs"

    def test_get_collection_details_success(self, client):
        response = client.get(
            "/api/v1/taxii2/root/collections/threat-logs/",
            headers={"X-API-KEY": "test-key-001"},
        )
        assert response.status_code == 200
        assert response.headers["Content-Type"] == "application/taxii+json;version=2.1"
        data = response.json()
        assert data["id"] == "threat-logs"

    def test_get_collection_details_not_found(self, client):
        response = client.get(
            "/api/v1/taxii2/root/collections/unknown/",
            headers={"X-API-KEY": "test-key-001"},
        )
        assert response.status_code == 404


class TestTaxiiCollectionObjects:
    """Testes para recuperação de objetos em formato STIX 2.1."""

    @patch.object(LogRepository, "get_threat_logs_for_stix")
    def test_get_objects_empty(self, mock_get_stix, client):
        mock_get_stix.return_value = []
        response = client.get(
            "/api/v1/taxii2/root/collections/threat-logs/objects/",
            headers={"X-API-KEY": "test-key-001"},
        )
        assert response.status_code == 200
        assert response.headers["Content-Type"] == "application/stix+json;version=2.1"
        data = response.json()
        assert data["type"] == "bundle"
        assert len(data["objects"]) == 0

    @patch.object(LogRepository, "get_threat_logs_for_stix")
    def test_get_objects_with_threats(self, mock_get_stix, client):
        # Criar log fictício
        log1 = DNSLog(
            id=str(uuid.uuid4()),
            timestamp=datetime(2026, 5, 21, 10, 0, 0, tzinfo=UTC),
            source_ip="10.0.0.2",
            destination_ip="8.8.8.8",
            domain="c2-strike.net",
            query_type="A",
            protocol="DNS",
            threat_level="malicious",
            threat_source="threat_intel",
        )
        mock_get_stix.return_value = [log1]

        response = client.get(
            "/api/v1/taxii2/root/collections/threat-logs/objects/",
            headers={"X-API-KEY": "test-key-001"},
        )
        assert response.status_code == 200
        assert response.headers["Content-Type"] == "application/stix+json;version=2.1"
        data = response.json()
        assert data["type"] == "bundle"

        objects = data["objects"]
        # Deve ter: 1 indicator, 1 observed-data, 1 relationship
        assert len(objects) == 3

        types = [obj["type"] for obj in objects]
        assert "indicator" in types
        assert "observed-data" in types
        assert "relationship" in types

        # Validar indicator
        indicator = [obj for obj in objects if obj["type"] == "indicator"][0]
        assert indicator["pattern"] == "[domain-name:value = 'c2-strike.net']"
        assert indicator["name"] == "NovaGuard Threat: c2-strike.net"

        # Validar observed-data
        observed = [obj for obj in objects if obj["type"] == "observed-data"][0]
        assert observed["objects"]["0"]["value"] == "10.0.0.2"


class TestMetricsThreatSummary:
    """Testes para o endpoint público de resumo de métricas."""

    @patch.object(LogRepository, "get_threat_summary_stats")
    def test_metrics_success(self, mock_summary, client):
        mock_summary.return_value = {
            "total_logs": 100,
            "threats": {
                "malicious": 10,
                "suspicious": 5,
                "total_threats": 15,
            },
            "top_affected_ips": [{"ip": "10.0.0.2", "count": 15}],
            "top_threat_domains": [
                {"domain": "c2-strike.net", "threat_level": "malicious", "count": 10}
            ],
        }

        response = client.get(
            "/api/v1/metrics/threat-summary",
            headers={"X-API-KEY": "test-key-001"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["total_logs"] == 100
        assert data["threats"]["total_threats"] == 15
        assert len(data["top_affected_ips"]) == 1
