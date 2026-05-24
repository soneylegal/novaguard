"""
NovaGuard — Testes Unitários: Task de Alertas (Mock).
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from backend.workers.alert_tasks import send_alert_task


class TestSendAlertTask:
    """Testes unitários para a task de envio de alertas."""

    @patch("backend.workers.alert_tasks.settings")
    def test_skipped_when_no_webhook_url(self, mock_settings):
        """Se o webhook_url não estiver configurado, a task deve ser ignorada."""
        mock_settings.webhook_url = None

        result = send_alert_task(
            source_ip="192.168.1.100",
            domain="c2-malicious.com",
            threat_type="c2_server",
            timestamp="2026-05-20T10:00:00Z",
        )

        assert result["status"] == "skipped"
        assert result["reason"] == "no_webhook_url"
        assert result["alert"]["details"]["severity"] == "CRITICAL"
        assert "c2-malicious.com" in result["alert"]["message"]

    @patch("backend.workers.alert_tasks.httpx.post")
    @patch("backend.workers.alert_tasks.settings")
    def test_sent_generic_webhook(self, mock_settings, mock_post):
        """Se for um webhook genérico, envia o payload padrão."""
        mock_settings.webhook_url = "https://my-webhook.site/alerts"

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        result = send_alert_task(
            source_ip="192.168.1.100",
            domain="malware-drop.org",
            threat_type="malware",
            timestamp="2026-05-20T10:00:00Z",
        )

        assert result["status"] == "sent"
        assert result["status_code"] == 200
        mock_post.assert_called_once()

        # Verificar argumentos chamados no mock
        called_args, called_kwargs = mock_post.call_args
        assert called_args[0] == "https://my-webhook.site/alerts"
        assert called_kwargs["json"]["details"]["threat_type"] == "MALWARE"
        assert called_kwargs["json"]["details"]["severity"] == "HIGH"

    @patch("backend.workers.alert_tasks.httpx.post")
    @patch("backend.workers.alert_tasks.settings")
    def test_sent_discord_webhook(self, mock_settings, mock_post):
        """Se for um webhook do Discord, envia formatado como Embed."""
        mock_settings.webhook_url = "https://discord.com/api/webhooks/1234/5678"

        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_post.return_value = mock_response

        result = send_alert_task(
            source_ip="192.168.1.100",
            domain="phishing-banco.com",
            threat_type="phishing",
            timestamp="2026-05-20T10:00:00Z",
        )

        assert result["status"] == "sent"
        mock_post.assert_called_once()

        # Verificar formatação Discord Embed
        called_args, called_kwargs = mock_post.call_args
        payload = called_kwargs["json"]
        assert "embeds" in payload
        assert len(payload["embeds"]) == 1
        embed = payload["embeds"][0]
        assert "Ameaça Detectada" in embed["title"]
        assert embed["color"] == 15844367  # Yellow

        # Verificar fields do embed
        fields = {f["name"]: f["value"] for f in embed["fields"]}
        assert fields["IP de Origem"] == "`192.168.1.100`"
        assert fields["Domínio Acessado"] == "`phishing-banco.com`"
        assert fields["Tipo de Ameaça"] == "`PHISHING`"
        assert "MÉDIO" in fields["Severidade"]

    @patch("backend.workers.alert_tasks.settings")
    def test_dga_suspicious_alert_formatting(self, mock_settings):
        """Domínios suspensos DGA devem ter severidade MEDIUM e mensagem adequada."""
        mock_settings.webhook_url = None

        result = send_alert_task(
            source_ip="192.168.1.100",
            domain="xjz897fka31s.co.uk",
            threat_type="dga_suspicious",
            timestamp="2026-05-21T10:00:00Z",
        )

        assert result["status"] == "skipped"
        assert result["alert"]["details"]["severity"] == "MEDIUM"
        assert "alta entropia" in result["alert"]["message"]

    @patch("backend.workers.alert_tasks.send_alert_task.retry")
    @patch("backend.workers.alert_tasks.httpx.post")
    @patch("backend.workers.alert_tasks.settings")
    def test_retry_on_http_error(self, mock_settings, mock_post, mock_retry):
        """Erros de HTTP devem acionar o retry da task Celery."""
        mock_settings.webhook_url = "https://my-webhook.site/alerts"

        # Simular erro HTTP
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_post.side_effect = httpx.HTTPStatusError(
            message="Internal Error", request=MagicMock(), response=mock_response
        )

        # Fazer com que o mock_retry lance uma exceção para interromper o fluxo e validar a chamada
        mock_retry.side_effect = Exception("CeleryRetryCalled")

        with pytest.raises(Exception, match="CeleryRetryCalled"):
            send_alert_task(
                source_ip="192.168.1.100",
                domain="c2-malicious.com",
                threat_type="c2_server",
                timestamp="2026-05-20T10:00:00Z",
            )

        mock_retry.assert_called_once()
