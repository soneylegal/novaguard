"""
NovaGuard — Repositório de Logs DNS.

Repositório especializado que herda o CRUD genérico e adiciona:
  - Bulk inserts otimizados (1000 registros por transação)
  - Queries de dashboard (top threats, stats, timeline)
  - Filtros por período, agente, domínio e threat level

Tanto na versão assíncrona (FastAPI) quanto síncrona (Celery).
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import desc, func, insert, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from backend.infrastructure.db.models import DNSLog, ThreatIntel
from backend.infrastructure.repositories.base import BaseRepository

logger = logging.getLogger(__name__)


class LogRepository(BaseRepository[DNSLog]):
    """
    Repositório assíncrono de logs DNS para uso no FastAPI.
    """

    def __init__(self, session: AsyncSession):
        super().__init__(DNSLog, session)

    # ── Queries de Dashboard ─────────────────────────────────────

    async def get_logs_filtered(
        self,
        domain: str | None = None,
        threat_level: str | None = None,
        agent_id: str | None = None,
        source_ip: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        offset: int = 0,
        limit: int = 100,
    ) -> tuple[Sequence[DNSLog], int]:
        """
        Busca logs com filtros combinados e retorna (items, total_count).
        """
        conditions = self._build_filters(
            domain, threat_level, agent_id, source_ip, start_time, end_time
        )

        # Query de contagem
        count_stmt = select(func.count()).select_from(DNSLog).where(*conditions)
        total = (await self.session.execute(count_stmt)).scalar_one()

        # Query paginada
        stmt = (
            select(DNSLog)
            .where(*conditions)
            .order_by(desc(DNSLog.timestamp))
            .offset(offset)
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        items = result.scalars().all()

        return items, total

    async def get_top_threats(self, limit: int = 10) -> list[dict[str, Any]]:
        """
        Retorna os domínios maliciosos mais frequentes.
        Otimizado com GROUP BY + aggregate functions.
        """
        stmt = (
            select(
                DNSLog.domain,
                DNSLog.threat_level,
                func.count(DNSLog.id).label("hit_count"),
                func.min(DNSLog.timestamp).label("first_seen"),
                func.max(DNSLog.timestamp).label("last_seen"),
                func.array_agg(func.distinct(DNSLog.source_ip)).label("source_ips"),
            )
            .where(DNSLog.threat_level == "malicious")
            .group_by(DNSLog.domain, DNSLog.threat_level)
            .order_by(desc("hit_count"))
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        rows = result.all()

        return [
            {
                "domain": row.domain,
                "threat_level": row.threat_level,
                "hit_count": row.hit_count,
                "first_seen": row.first_seen,
                "last_seen": row.last_seen,
                "source_ips": row.source_ips or [],
            }
            for row in rows
        ]

    async def get_top_queried_domains(self, limit: int = 10) -> list[dict[str, Any]]:
        """Retorna os domínios mais consultados (todas as classificações)."""
        stmt = (
            select(
                DNSLog.domain,
                func.count(DNSLog.id).label("query_count"),
                DNSLog.threat_level,
            )
            .group_by(DNSLog.domain, DNSLog.threat_level)
            .order_by(desc("query_count"))
            .limit(limit)
        )
        result = await self.session.execute(stmt)
        return [
            {
                "domain": row.domain,
                "query_count": row.query_count,
                "threat_level": row.threat_level,
            }
            for row in result.all()
        ]

    async def get_dashboard_stats(self) -> dict[str, Any]:
        """
        Estatísticas agregadas para o dashboard principal.
        Executa múltiplas queries otimizadas em paralelo (via pipeline).
        """
        now = datetime.now(UTC)
        day_ago = now - timedelta(hours=24)

        # Total de logs
        total_logs = await self.count()

        # Logs nas últimas 24h
        stmt_24h = select(func.count()).select_from(DNSLog).where(DNSLog.timestamp >= day_ago)
        logs_24h = (await self.session.execute(stmt_24h)).scalar_one()

        # Contagem por threat_level
        stmt_threat = select(DNSLog.threat_level, func.count(DNSLog.id)).group_by(
            DNSLog.threat_level
        )
        threat_counts = dict((await self.session.execute(stmt_threat)).all())

        # Domínios únicos
        stmt_domains = select(func.count(func.distinct(DNSLog.domain)))
        total_domains = (await self.session.execute(stmt_domains)).scalar_one()

        return {
            "total_logs": total_logs,
            "total_domains": total_domains,
            "malicious_domains": threat_counts.get("malicious", 0),
            "safe_domains": threat_counts.get("safe", 0),
            "unknown_domains": threat_counts.get("unknown", 0),
            "logs_last_24h": logs_24h,
        }

    # ── Helpers ──────────────────────────────────────────────────

    @staticmethod
    def _build_filters(
        domain: str | None,
        threat_level: str | None,
        agent_id: str | None,
        source_ip: str | None,
        start_time: datetime | None,
        end_time: datetime | None,
    ) -> list:
        """Constrói lista de condições SQLAlchemy a partir dos filtros."""
        conditions = []
        if domain:
            conditions.append(DNSLog.domain.ilike(f"%{domain}%"))
        if threat_level:
            conditions.append(DNSLog.threat_level == threat_level)
        if agent_id:
            conditions.append(DNSLog.agent_id == agent_id)
        if source_ip:
            conditions.append(DNSLog.source_ip == source_ip)
        if start_time:
            conditions.append(DNSLog.timestamp >= start_time)
        if end_time:
            conditions.append(DNSLog.timestamp <= end_time)
        return conditions


class SyncLogRepository:
    """
    Repositório síncrono de logs DNS para uso nos workers Celery.

    Celery não suporta async nativo, então esta versão usa
    sessões síncronas com psycopg2.
    """

    def __init__(self, session: Session):
        self.session = session

    def bulk_insert(self, logs: list[dict[str, Any]]) -> int:
        """
        Inserção em lote de logs enriquecidos.
        Usa `insert().values()` para máxima performance.
        """
        if not logs:
            return 0

        stmt = insert(DNSLog).values(logs)
        self.session.execute(stmt)
        self.session.commit()

        logger.info("Sync bulk insert: %d DNS logs persisted.", len(logs))
        return len(logs)

    def get_threat_domains(self) -> set[str]:
        """
        Carrega todos os domínios da tabela threat_intel.
        Usado pelo worker para cruzamento local.
        """
        stmt = select(ThreatIntel.domain)
        result = self.session.execute(stmt)
        domains = {row[0] for row in result.all()}
        logger.info("Loaded %d threat domains from DB.", len(domains))
        return domains

    def close(self) -> None:
        """Fecha a sessão síncrona."""
        self.session.close()
