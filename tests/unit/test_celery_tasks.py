"""
NovaGuard — Testes Unitários: Celery Tasks.

Testes de smoke para validar que as tasks Celery podem ser
importadas e invocadas sem erros de sintaxe ou imports quebrados.
Mock completo de infra (Redis, PostgreSQL, SQLAlchemy sessions).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch


class TestProcessAndEnrichBatch:
    """Smoke tests para a task de enriquecimento."""

    @patch("backend.workers.intel_tasks.celery_app")
    @patch("backend.workers.intel_tasks.SyncLogRepository")
    @patch("backend.workers.intel_tasks.get_sync_session")
    @patch("backend.workers.intel_tasks.sync_redis")
    def test_empty_batch_returns_zero(self, mock_redis_mod, mock_session, mock_repo, mock_celery):
        """Lote vazio deve retornar total_logs=0."""
        # Mock Redis client
        mock_redis_client = MagicMock()
        mock_redis_client.pipeline.return_value.execute.return_value = []
        mock_redis_mod.from_url.return_value = mock_redis_client

        from backend.workers.intel_tasks import process_and_enrich_batch

        result = process_and_enrich_batch(
            batch_id="test-batch-001",
            agent_id="test-agent",
            logs=[],
        )

        assert result["batch_id"] == "test-batch-001"
        assert result["total_logs"] == 0

    @patch("backend.workers.intel_tasks.celery_app")
    @patch("backend.workers.intel_tasks.SyncLogRepository")
    @patch("backend.workers.intel_tasks.get_sync_session")
    @patch("backend.workers.intel_tasks.sync_redis")
    def test_single_log_enrichment_dispatches_to_sink(
        self, mock_redis_mod, mock_session, mock_repo, mock_celery
    ):
        """Um log deve ser enriquecido e encaminhado ao sink."""
        # Mock Redis — cache miss
        mock_pipeline = MagicMock()
        mock_pipeline.execute.return_value = [None]
        mock_redis_client = MagicMock()
        mock_redis_client.pipeline.return_value = mock_pipeline
        mock_redis_mod.from_url.return_value = mock_redis_client

        # Mock Repository — no known threats
        mock_repo_instance = MagicMock()
        mock_repo_instance.get_threat_domains.return_value = set()
        mock_repo.return_value = mock_repo_instance

        from backend.workers.intel_tasks import process_and_enrich_batch

        result = process_and_enrich_batch(
            batch_id="test-batch-002",
            agent_id="test-agent",
            logs=[
                {
                    "timestamp": "2026-05-09T12:00:00+00:00",
                    "source_ip": "10.0.0.1",
                    "destination_ip": "8.8.8.8",
                    "domain": "example.com",
                    "query_type": "A",
                    "protocol": "DNS",
                }
            ],
        )

        assert result["total_logs"] == 1
        assert result["cache_misses"] == 1
        mock_celery.send_task.assert_called_once()


class TestBulkPersistLogs:
    """Smoke tests para a task de persistência."""

    @patch("backend.workers.sink_tasks.SyncLogRepository")
    @patch("backend.workers.sink_tasks.get_sync_session")
    def test_empty_batch_persists_zero(self, mock_session, mock_repo):
        """Lote vazio deve persistir 0 registros."""
        mock_repo_instance = MagicMock()
        mock_repo.return_value = mock_repo_instance

        from backend.workers.sink_tasks import bulk_persist_logs

        result = bulk_persist_logs(batch_id="test-sink-001", enriched_logs=[])

        assert result["total_persisted"] == 0
        mock_repo_instance.bulk_insert.assert_not_called()

    @patch("backend.workers.sink_tasks.SyncLogRepository")
    @patch("backend.workers.sink_tasks.get_sync_session")
    def test_batch_calls_bulk_insert(self, mock_session, mock_repo):
        """Lote com dados deve invocar bulk_insert no repositório."""
        mock_repo_instance = MagicMock()
        mock_repo_instance.bulk_insert.return_value = 1
        mock_repo.return_value = mock_repo_instance

        from backend.workers.sink_tasks import bulk_persist_logs

        result = bulk_persist_logs(
            batch_id="test-sink-002",
            enriched_logs=[
                {
                    "timestamp": "2026-05-09T12:00:00+00:00",
                    "source_ip": "10.0.0.1",
                    "destination_ip": "8.8.8.8",
                    "domain": "example.com",
                    "query_type": "A",
                    "protocol": "DNS",
                    "threat_level": "safe",
                    "threat_source": None,
                    "enriched_at": "2026-05-09T12:00:01+00:00",
                }
            ],
        )

        assert result["total_persisted"] == 1
        mock_repo_instance.bulk_insert.assert_called_once()
