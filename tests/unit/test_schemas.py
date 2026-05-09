"""
NovaGuard — Testes Unitários: Schemas Pydantic.

Valida a integridade dos modelos de domínio sem dependência
de banco de dados ou serviços externos.
"""

from __future__ import annotations

from datetime import datetime

import pytest
from pydantic import ValidationError

from backend.domain.schemas import (
    DNSLogItem,
    IngestResponse,
    LogBatchCreate,
    Protocol,
    ThreatLevel,
)


class TestDNSLogItem:
    """Testes para o schema DNSLogItem."""

    def test_valid_log_item(self):
        """Valida criação de um log item válido."""
        item = DNSLogItem(
            source_ip="192.168.1.10",
            destination_ip="8.8.8.8",
            domain="google.com",
            query_type="A",
        )
        assert item.domain == "google.com"
        assert item.protocol == Protocol.DNS
        assert item.query_type == "A"

    def test_domain_normalization(self):
        """Domínio deve ser normalizado (lowercase, sem trailing dot)."""
        item = DNSLogItem(
            source_ip="10.0.0.1",
            destination_ip="8.8.8.8",
            domain="  Google.COM.  ",
        )
        assert item.domain == "google.com"

    def test_invalid_ip_too_short(self):
        """IP com menos de 7 caracteres deve falhar na validação."""
        with pytest.raises(ValidationError):
            DNSLogItem(
                source_ip="1.1",  # muito curto
                destination_ip="8.8.8.8",
                domain="example.com",
            )

    def test_domain_max_length(self):
        """Domínio com mais de 253 caracteres deve falhar."""
        with pytest.raises(ValidationError):
            DNSLogItem(
                source_ip="10.0.0.1",
                destination_ip="8.8.8.8",
                domain="a" * 254,
            )

    def test_empty_domain(self):
        """Domínio vazio deve falhar."""
        with pytest.raises(ValidationError):
            DNSLogItem(
                source_ip="10.0.0.1",
                destination_ip="8.8.8.8",
                domain="",
            )

    def test_timestamp_defaults_to_now(self):
        """Timestamp deve ter default de utcnow()."""
        item = DNSLogItem(
            source_ip="10.0.0.1",
            destination_ip="8.8.8.8",
            domain="test.com",
        )
        assert isinstance(item.timestamp, datetime)

    def test_protocol_enum(self):
        """Protocolo deve aceitar valores do enum."""
        item = DNSLogItem(
            source_ip="10.0.0.1",
            destination_ip="8.8.8.8",
            domain="test.com",
            protocol=Protocol.HTTPS,
        )
        assert item.protocol == Protocol.HTTPS


class TestLogBatchCreate:
    """Testes para o schema de lote de logs."""

    def test_valid_batch(self):
        """Batch com logs válidos deve ser aceito."""
        logs = [
            DNSLogItem(
                source_ip=f"10.0.0.{i}",
                destination_ip="8.8.8.8",
                domain=f"domain{i}.com",
            )
            for i in range(10)
        ]
        batch = LogBatchCreate(
            logs=logs,
            agent_id="test-agent-001",
            batch_sequence=1,
        )
        assert len(batch.logs) == 10
        assert batch.agent_id == "test-agent-001"

    def test_empty_batch_rejected(self):
        """Batch vazio deve ser rejeitado (min_length=1)."""
        with pytest.raises(ValidationError):
            LogBatchCreate(
                logs=[],
                agent_id="test-agent",
            )

    def test_batch_max_size(self):
        """Batch com mais de 5000 logs deve ser rejeitado."""
        logs = [
            DNSLogItem(
                source_ip="10.0.0.1",
                destination_ip="8.8.8.8",
                domain="test.com",
            )
        ] * 5001
        with pytest.raises(ValidationError):
            LogBatchCreate(
                logs=logs,
                agent_id="test-agent",
            )


class TestThreatLevel:
    """Testes para o enum ThreatLevel."""

    def test_valid_levels(self):
        """Todos os níveis de ameaça devem ser válidos."""
        assert ThreatLevel.SAFE == "safe"
        assert ThreatLevel.MALICIOUS == "malicious"
        assert ThreatLevel.SUSPICIOUS == "suspicious"
        assert ThreatLevel.UNKNOWN == "unknown"


class TestIngestResponse:
    """Testes para o schema de resposta de ingestão."""

    def test_response_format(self):
        """Resposta deve ter todos os campos obrigatórios."""
        response = IngestResponse(
            batch_id="abc-123",
            log_count=500,
        )
        assert response.status == "accepted"
        assert response.batch_id == "abc-123"
        assert response.log_count == 500
