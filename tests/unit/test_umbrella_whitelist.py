"""
NovaGuard — Testes Unitários: Cisco Umbrella Whitelist & Registered Domain Extraction.
"""

from __future__ import annotations

import io
import zipfile
from unittest.mock import MagicMock, patch

from backend.core.entropy import extract_registered_domain
from backend.workers.feed_tasks import sync_top_domains
from backend.workers.intel_tasks import process_and_enrich_batch


def test_extract_registered_domain():
    """Valida a extração correta de domínios base/registrados com subdomínios."""
    # Casos simples e sem subdomínio
    assert extract_registered_domain("google.com") == "google.com"
    assert extract_registered_domain("github.io") == "github.io"

    # Subdomínios de nível único
    assert extract_registered_domain("www.google.com") == "google.com"
    assert extract_registered_domain("platform-cdn.sharethis.com") == "sharethis.com"
    assert extract_registered_domain("encrypted-tbn0.gstatic.com") == "gstatic.com"

    # Subdomínios de múltiplos níveis
    assert extract_registered_domain("sub.domain.github.io") == "github.io"
    assert extract_registered_domain("a.b.c.d.google.com.br") == "google.com.br"

    # TLDs compostos
    assert extract_registered_domain("xjz897fka31s.co.uk") == "xjz897fka31s.co.uk"
    assert extract_registered_domain("test.coop") == "test.coop"

    # Sensibilidade a maiúsculas e espaços
    assert extract_registered_domain("  WWW.Google.Com  ") == "google.com"

    # Tratamento de pontos extras
    assert extract_registered_domain(".google.com.") == "google.com"


@patch("backend.workers.feed_tasks.httpx.get")
@patch("backend.workers.intel_tasks._get_sync_redis")
def test_sync_top_domains(mock_get_redis, mock_httpx_get):
    """Testa o download do feed Umbrella, extração e inserção no Redis."""
    # Mock Redis client
    mock_redis = MagicMock()
    mock_get_redis.return_value = mock_redis

    # Mock Zip file content
    csv_content = "1,google.com\n2,youtube.com\n3,sharethis.com\n"
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as z:
        z.writestr("top-1m.csv", csv_content)
    zip_buffer.seek(0)

    mock_response = MagicMock()
    mock_response.content = zip_buffer.getvalue()
    mock_httpx_get.return_value = mock_response

    # Executa a task
    result = sync_top_domains()

    assert result["status"] == "success"
    assert result["total_fetched"] == 3

    # Verifica chamadas ao Redis
    mock_redis.delete.assert_called_once_with("whitelist:top_domains")
    # sadd deve ter sido chamado para adicionar os 3 domínios
    mock_redis.pipeline.return_value.sadd.assert_any_call(
        "whitelist:top_domains", "google.com", "youtube.com", "sharethis.com"
    )


@patch("backend.workers.intel_tasks.celery_app")
@patch("backend.workers.intel_tasks._get_sync_redis")
@patch("backend.workers.intel_tasks.get_sync_session")
def test_enrichment_bypasses_whitelisted_domains(mock_get_session, mock_get_redis, mock_celery):
    """Valida se o pipeline de enriquecimento identifica domínios populares.

    Marca-os como safe de imediato.
    """
    mock_redis = MagicMock()
    mock_get_redis.return_value = mock_redis
    mock_session = MagicMock()
    mock_get_session.return_value = mock_session

    # Mock do Cache Redis:
    # 1. Primeiro pipe.get retorna None para simular cache miss geral
    mock_redis.pipeline.return_value.execute.side_effect = [
        [None, None],  # Resultados do pipe.get do cache
        [True, False],  # Resultados do pipe.sismember da whitelist
        [True, True],  # Resultados do pipe.set final
    ]

    # Logs para teste:
    # - platform-cdn.sharethis.com (está na whitelist -> is_whitelisted = True)
    # - unknown-suspicious-domain.xyz (não está na whitelist -> is_whitelisted = False)
    logs = [
        {
            "timestamp": "2026-05-22T14:00:00Z",
            "source_ip": "1.1.1.1",
            "destination_ip": "8.8.8.8",
            "domain": "platform-cdn.sharethis.com",
        },
        {
            "timestamp": "2026-05-22T14:00:00Z",
            "source_ip": "1.1.1.1",
            "destination_ip": "8.8.8.8",
            "domain": "unknown-suspicious-domain.xyz",
        },
    ]

    # Mock de repositório de ameaças vazios
    mock_session.query.return_value.filter.return_value.first.return_value = None

    with patch("backend.workers.intel_tasks.SyncLogRepository") as mock_repo_class:
        mock_repo_inst = MagicMock()
        mock_repo_class.return_value = mock_repo_inst
        mock_repo_inst.get_threat_types_for_domains.return_value = {}  # Nenhuma ameaça no banco

        # Executa enriquecimento
        result = process_and_enrich_batch(
            batch_id="test_batch_123", agent_id="agent_123", logs=logs
        )

        # O repositório do DB só deve ter sido consultado para o domínio que NÃO está na whitelist
        mock_repo_inst.get_threat_types_for_domains.assert_called_once_with(
            ["unknown-suspicious-domain.xyz"]
        )

        assert result["total_logs"] == 2
        # Ambos os logs devem ter sido processados, mas apenas o não-whitelist
        # pode ter sido avaliado por DGA
