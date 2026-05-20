"""
NovaGuard — Testes Unitários: Repository (Mock).

Testa a lógica de repositório sem banco de dados real,
usando mocks do SQLAlchemy Session.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import MagicMock


class TestSyncLogRepository:
    """Testes para o repositório síncrono (Celery workers)."""

    def test_bulk_insert_empty_list(self):
        """Bulk insert com lista vazia deve retornar 0."""
        from backend.infrastructure.repositories.log_repo import SyncLogRepository

        mock_session = MagicMock()
        repo = SyncLogRepository(mock_session)

        result = repo.bulk_insert([])
        assert result == 0
        mock_session.execute.assert_not_called()

    def test_bulk_insert_with_data(self):
        """Bulk insert com dados deve executar e commitar."""
        from backend.infrastructure.repositories.log_repo import SyncLogRepository

        mock_session = MagicMock()
        repo = SyncLogRepository(mock_session)

        logs = [
            {
                "timestamp": datetime.now(UTC).isoformat(),
                "source_ip": "10.0.0.1",
                "destination_ip": "8.8.8.8",
                "domain": "test.com",
                "query_type": "A",
                "protocol": "DNS",
                "agent_id": "test-agent",
                "threat_level": "safe",
            }
        ]

        result = repo.bulk_insert(logs)
        assert result == 1
        mock_session.execute.assert_called_once()
        mock_session.commit.assert_called_once()

    def test_get_threat_domains(self):
        """Deve retornar um set de domínios maliciosos."""
        from backend.infrastructure.repositories.log_repo import SyncLogRepository

        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.all.return_value = [
            ("malware.com",),
            ("phishing.net",),
            ("evil.org",),
        ]
        mock_session.execute.return_value = mock_result

        repo = SyncLogRepository(mock_session)
        domains = repo.get_threat_domains()

        assert domains == {"malware.com", "phishing.net", "evil.org"}
        assert len(domains) == 3

    def test_get_threat_domains_with_types(self):
        """Deve retornar um dicionário de domínios e tipos de ameaça."""
        from backend.infrastructure.repositories.log_repo import SyncLogRepository

        mock_session = MagicMock()
        mock_result = MagicMock()
        mock_result.all.return_value = [
            ("malware.com", "malware"),
            ("phishing.net", "phishing"),
            ("evil.org", "c2_server"),
        ]
        mock_session.execute.return_value = mock_result

        repo = SyncLogRepository(mock_session)
        domains_with_types = repo.get_threat_domains_with_types()

        assert domains_with_types == {
            "malware.com": "malware",
            "phishing.net": "phishing",
            "evil.org": "c2_server",
        }
        assert len(domains_with_types) == 3

    def test_close(self):
        """Close deve chamar session.close()."""
        from backend.infrastructure.repositories.log_repo import SyncLogRepository

        mock_session = MagicMock()
        repo = SyncLogRepository(mock_session)
        repo.close()
        mock_session.close.assert_called_once()
