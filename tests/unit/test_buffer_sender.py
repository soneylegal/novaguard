"""
NovaGuard — Testes Unitários: Buffer Sender.

Testa a lógica de buffer, flush e fallback SQLite
sem dependência de rede ou API real.
"""

from __future__ import annotations

import sqlite3
from unittest.mock import MagicMock

import pytest

from agent.buffer_sender import INITIAL_BACKOFF_SECONDS, MAX_BACKOFF_SECONDS, BufferSender


@pytest.fixture
def sender(tmp_path):
    """Cria um BufferSender com SQLite em diretório temporário."""
    sqlite_path = str(tmp_path / "test_fallback.db")
    s = BufferSender(
        api_url="http://localhost:8000/api/v1/ingest",
        api_key="test-key",
        flush_interval=60,  # Alto para evitar flush automático
        flush_size=100,
        agent_id="test-agent",
        sqlite_path=sqlite_path,
    )
    yield s
    s._http_client.close()


class TestBufferSender:
    """Testes para o buffer em memória."""

    def test_enqueue_adds_to_buffer(self, sender):
        """Enqueue deve adicionar ao buffer em memória."""
        log = {
            "timestamp": "2024-01-01T00:00:00Z",
            "source_ip": "10.0.0.1",
            "destination_ip": "8.8.8.8",
            "domain": "test.com",
        }
        sender.enqueue(log)
        assert len(sender._buffer) == 1
        assert sender.stats["total_enqueued"] == 1

    def test_enqueue_multiple(self, sender):
        """Múltiplos enqueues devem acumular."""
        for i in range(50):
            sender.enqueue(
                {"domain": f"test{i}.com", "source_ip": "10.0.0.1", "destination_ip": "8.8.8.8"}
            )
        assert len(sender._buffer) == 50
        assert sender.stats["total_enqueued"] == 50

    def test_flush_clears_buffer(self, sender):
        """Flush deve esvaziar o buffer."""
        sender.enqueue({"domain": "test.com", "source_ip": "10.0.0.1", "destination_ip": "8.8.8.8"})

        # Mock o envio para falhar (vai para SQLite)
        sender._send_batch = MagicMock(return_value=False)
        sender._flush()

        assert len(sender._buffer) == 0

    def test_exponential_backoff(self, sender):
        """Backoff deve dobrar a cada falha até o máximo."""
        assert sender._current_backoff == INITIAL_BACKOFF_SECONDS

        sender._escalate_backoff()
        assert sender._current_backoff == INITIAL_BACKOFF_SECONDS * 2

        sender._escalate_backoff()
        assert sender._current_backoff == INITIAL_BACKOFF_SECONDS * 4

        # Simula muitas falhas
        for _ in range(20):
            sender._escalate_backoff()
        assert sender._current_backoff == MAX_BACKOFF_SECONDS

    def test_backoff_resets_on_success(self, sender):
        """Backoff deve resetar após envio bem-sucedido."""
        sender._escalate_backoff()
        sender._escalate_backoff()
        assert sender._current_backoff > INITIAL_BACKOFF_SECONDS

        # Simula envio bem-sucedido
        sender._current_backoff = INITIAL_BACKOFF_SECONDS
        assert sender._current_backoff == INITIAL_BACKOFF_SECONDS


class TestSQLiteFallback:
    """Testes para o fallback SQLite."""

    def test_persist_to_sqlite(self, sender):
        """Logs devem ser persistidos no SQLite ao falhar."""
        logs = [{"domain": "test.com", "source_ip": "10.0.0.1"}]
        sender._persist_to_sqlite(logs)

        conn = sqlite3.connect(sender._sqlite_path)
        cursor = conn.execute("SELECT COUNT(*) FROM pending_logs")
        count = cursor.fetchone()[0]
        conn.close()

        assert count == 1
        assert sender.stats["total_failed"] == 1

    def test_drain_sqlite_on_recovery(self, sender):
        """Logs do SQLite devem ser re-enviados ao reconectar."""
        # Persiste um batch
        logs = [{"domain": "test.com", "source_ip": "10.0.0.1"}]
        sender._persist_to_sqlite(logs)

        # Simula envio bem-sucedido
        sender._send_batch = MagicMock(return_value=True)
        sender._drain_sqlite()

        assert sender.stats["total_recovered"] == 1

        # Verifica que o SQLite está vazio
        assert sender._count_sqlite_pending() == 0

    def test_count_sqlite_pending(self, sender):
        """Contagem de pendentes deve ser precisa."""
        assert sender._count_sqlite_pending() == 0

        sender._persist_to_sqlite([{"domain": "a.com"}])
        sender._persist_to_sqlite([{"domain": "b.com"}])

        assert sender._count_sqlite_pending() == 2

    def test_stats_tracking(self, sender):
        """Estatísticas devem ser rastreadas corretamente."""
        assert sender.stats["total_enqueued"] == 0
        assert sender.stats["total_sent"] == 0
        assert sender.stats["total_failed"] == 0
        assert sender.stats["total_recovered"] == 0
        assert sender.stats["batches_sent"] == 0
