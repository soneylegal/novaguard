"""
NovaGuard — Modelos SQLAlchemy (Mapeamento ORM).

Define as tabelas do banco de dados com:
  - Particionamento por data (range partitioning) para séries temporais.
  - Índices otimizados para queries de dashboard.
  - Campos de enriquecimento de ameaças.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    """Base declarativa para todos os modelos SQLAlchemy."""

    pass


class DNSLog(Base):
    """
    Tabela principal de logs DNS.

    Projetada para alto volume de escrita (bulk inserts de 1000+).
    Índices focados em queries de dashboard:
      - Por domínio (threat lookup)
      - Por timestamp (range queries de séries temporais)
      - Por threat_level (filtros de severidade)
      - Por agent_id (rastreamento de agentes)
    """

    __tablename__ = "dns_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        index=True,
        server_default=func.now(),
    )
    source_ip: Mapped[str] = mapped_column(
        String(45),
        nullable=False,
    )
    destination_ip: Mapped[str] = mapped_column(
        String(45),
        nullable=False,
    )
    domain: Mapped[str] = mapped_column(
        String(253),
        nullable=False,
        index=True,
    )
    query_type: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default="A",
    )
    protocol: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default="DNS",
    )
    agent_id: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
        index=True,
    )

    # ── Campos de Enriquecimento ─────────────────────────────────
    threat_level: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="unknown",
        index=True,
    )
    threat_source: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    enriched_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    # ── Metadata ─────────────────────────────────────────────────
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # ── Índices Compostos ────────────────────────────────────────
    __table_args__ = (
        Index("ix_dns_logs_domain_timestamp", "domain", "timestamp"),
        Index("ix_dns_logs_threat_timestamp", "threat_level", "timestamp"),
        Index("ix_dns_logs_agent_timestamp", "agent_id", "timestamp"),
        Index("ix_dns_logs_source_ip_timestamp", "source_ip", "timestamp"),
    )

    def __repr__(self) -> str:
        return (
            f"<DNSLog(id={self.id}, domain={self.domain}, "
            f"threat={self.threat_level}, ts={self.timestamp})>"
        )


class ThreatIntel(Base):
    """
    Tabela de inteligência de ameaças.
    Domínios conhecidos como maliciosos carregados de listas externas.
    """

    __tablename__ = "threat_intel"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    domain: Mapped[str] = mapped_column(
        String(253),
        nullable=False,
        unique=True,
        index=True,
    )
    threat_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="malware",
    )
    source: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="internal",
    )
    confidence: Mapped[str] = mapped_column(
        String(10),
        nullable=False,
        default="high",
    )
    added_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )

    def __repr__(self) -> str:
        return f"<ThreatIntel(domain={self.domain}, type={self.threat_type})>"


class AgentRegistry(Base):
    """
    Registro de agentes de borda autorizados.
    Rastreia status, última atividade e metadados do agente.
    """

    __tablename__ = "agent_registry"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    agent_id: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        unique=True,
        index=True,
    )
    hostname: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )
    api_key_hash: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    last_seen: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )
    total_logs_sent: Mapped[int] = mapped_column(
        default=0,
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="active",
    )
    registered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    def __repr__(self) -> str:
        return f"<AgentRegistry(agent_id={self.agent_id}, status={self.status})>"
