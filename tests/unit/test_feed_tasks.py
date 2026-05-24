"""
NovaGuard — Testes Unitários: Feed Tasks & Whitelist.

Testa a lógica de whitelist e exclusão de domínios confiáveis durante a sincronização
dos feeds de Threat Intelligence (URLhaus e PhishTank).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from backend.workers.feed_tasks import _bulk_upsert_domains, is_whitelisted


class TestFeedTasksWhitelist:
    """Valida a funcionalidade de whitelist para evitar a ingestão de falsos positivos."""

    def test_is_whitelisted_exact_match(self):
        """Domínios confiáveis exatos devem ser identificados como whitelisted."""
        assert is_whitelisted("google.com") is True
        assert is_whitelisted("github.com") is True
        assert is_whitelisted("microsoft.com") is True
        assert is_whitelisted("doubleclick.net") is True
        assert is_whitelisted("adnxs.com") is True

    def test_is_whitelisted_subdomains(self):
        """Subdomínios de domínios confiáveis também devem ser identificados como whitelisted."""
        assert is_whitelisted("www.google.com") is True
        assert is_whitelisted("accounts.google.com") is True
        assert is_whitelisted("sub.domain.github.io") is True
        assert is_whitelisted("pages.github.io") is True
        assert is_whitelisted("googleads.g.doubleclick.net") is True
        assert is_whitelisted("ib.adnxs.com") is True

    def test_is_whitelisted_case_insensitive_and_whitespace(self):
        """Deve ser insensível a maiúsculas e espaços em branco."""
        assert is_whitelisted("   GOOGLE.COM  ") is True
        assert is_whitelisted("WWW.MICROSOFT.COM") is True

    def test_is_whitelisted_non_matching(self):
        """Domínios que não estão na whitelist não devem ser identificados como tal."""
        assert is_whitelisted("malicious-site.com") is False
        assert is_whitelisted("google.com.attacker.net") is False
        assert is_whitelisted("github-phish.co") is False

    @patch("backend.workers.feed_tasks.get_sync_session")
    def test_bulk_upsert_skips_whitelisted_domains(self, mock_get_session):
        """O método de bulk upsert deve pular a inserção de domínios na whitelist."""
        mock_session = MagicMock()
        mock_get_session.return_value = mock_session

        # Fornece um conjunto de domínios contendo tanto legítimos quanto maliciosos
        domains_set = {
            "google.com",
            "www.google.com",
            "malicious-site-xyz.net",
            "phishing-domain.org",
        }

        # Mock query return para não existente no banco
        mock_session.query.return_value.filter.return_value.first.return_value = None

        result = _bulk_upsert_domains(
            domains=domains_set,
            threat_type="phishing",
            source="test_source",
        )

        # Deve ter inserido apenas os 2 domínios que não estão na whitelist
        assert result["inserted"] == 2
        # O total pulado deve ser 2 (google.com e www.google.com)
        assert result["skipped"] == 2

        # Verifica se o session.add foi chamado apenas para os domínios não confiáveis
        added_calls = [call[0][0].domain for call in mock_session.add.call_args_list]
        assert "google.com" not in added_calls
        assert "www.google.com" not in added_calls
        assert "malicious-site-xyz.net" in added_calls
        assert "phishing-domain.org" in added_calls
