"""
NovaGuard — Modelos Pydantic (Domain Schemas).

Entidades de negócio puras, sem dependência de frameworks de infra.
Divididas em:
  - Schemas de entrada (ingestão de dados dos agentes)
  - Schemas de saída (respostas da API para dashboards)
  - Schemas internos (representação enriquecida para o worker)
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator

# ── Enums ────────────────────────────────────────────────────────


class ThreatLevel(StrEnum):
    """Classificação de ameaça de um domínio DNS."""

    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    UNKNOWN = "unknown"


class Protocol(StrEnum):
    """Protocolo de rede capturado."""

    DNS = "DNS"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    TCP = "TCP"
    UDP = "UDP"
    OTHER = "OTHER"


# ── Schemas de Entrada (Ingestão) ────────────────────────────────


class DNSLogItem(BaseModel):
    """
    Representação de um único registro DNS capturado pelo agente de borda.
    Modelo ultra-otimizado para validação de lotes de 1000+ itens.
    """

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Momento exato da captura do pacote (UTC).",
    )
    source_ip: str = Field(
        ...,
        min_length=7,
        max_length=45,
        description="IP de origem da requisição DNS.",
    )
    destination_ip: str = Field(
        ...,
        min_length=7,
        max_length=45,
        description="IP de destino (geralmente o servidor DNS).",
    )
    domain: str = Field(
        ...,
        min_length=1,
        max_length=253,
        description="Domínio consultado (ex: google.com).",
    )
    query_type: str = Field(
        default="A",
        max_length=10,
        description="Tipo de query DNS (A, AAAA, CNAME, MX, etc.).",
    )
    protocol: Protocol = Field(
        default=Protocol.DNS,
        description="Protocolo de rede capturado.",
    )
    agent_id: str | None = Field(
        default=None,
        max_length=64,
        description="Identificador único do agente de borda.",
    )

    @field_validator("domain", mode="before")
    @classmethod
    def normalize_domain(cls, v: str) -> str:
        """Remove trailing dots e normaliza para lowercase."""
        return v.strip().lower().rstrip(".")


class LogBatchCreate(BaseModel):
    """
    Lote de logs DNS enviado pelo agente de borda.
    O agente acumula em buffer e envia a cada 5s ou 1000 logs.
    """

    logs: list[DNSLogItem] = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="Lista de registros DNS capturados.",
    )
    agent_id: str = Field(
        ...,
        max_length=64,
        description="Identificador do agente que enviou o lote.",
    )
    batch_sequence: int = Field(
        default=0,
        ge=0,
        description="Número sequencial do lote (para detecção de gaps).",
    )


# ── Schemas Internos (Enriquecimento) ───────────────────────────


class EnrichedLog(BaseModel):
    """Registro DNS após enriquecimento pelo worker Celery."""

    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime
    source_ip: str
    destination_ip: str
    domain: str
    query_type: str
    protocol: Protocol
    agent_id: str | None = None
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    threat_source: str | None = None
    enriched_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ── Schemas de Saída (API Response) ──────────────────────────────


class LogResponse(BaseModel):
    """Resposta individual de log para dashboards."""

    id: UUID
    timestamp: datetime
    source_ip: str
    destination_ip: str
    domain: str
    query_type: str
    protocol: str
    agent_id: str | None = None
    threat_level: ThreatLevel
    threat_source: str | None = None
    enriched_at: datetime | None = None

    model_config = {"from_attributes": True}


class LogListResponse(BaseModel):
    """Resposta paginada para listagem de logs."""

    total: int
    page: int
    page_size: int
    items: list[LogResponse]


class IngestResponse(BaseModel):
    """Resposta da rota de ingestão (202 Accepted)."""

    status: str = "accepted"
    message: str = "Lote recebido e enfileirado para processamento."
    batch_id: str
    log_count: int


class ThreatSummary(BaseModel):
    """Resumo de ameaças para o dashboard."""

    domain: str
    threat_level: ThreatLevel
    hit_count: int
    first_seen: datetime
    last_seen: datetime
    source_ips: list[str]


class DashboardStats(BaseModel):
    """Estatísticas gerais do dashboard."""

    total_logs: int
    total_domains: int
    malicious_domains: int
    safe_domains: int
    unknown_domains: int
    logs_last_24h: int
    top_threats: list[ThreatSummary]
    top_queried_domains: list[dict]


class HealthResponse(BaseModel):
    """Resposta do health check."""

    status: str = "healthy"
    version: str = "1.0.0"
    database: str = "connected"
    redis: str = "connected"
    celery: str = "connected"
