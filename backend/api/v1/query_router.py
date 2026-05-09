"""
NovaGuard — Rotas de Consulta (Dashboard API).

Endpoints GET para alimentar dashboards e ferramentas de análise:
  - Listagem paginada de logs com filtros
  - Estatísticas agregadas do dashboard
  - Top ameaças e domínios mais consultados
  - Health check
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.cache import get_redis
from backend.core.security import validate_api_key
from backend.domain.schemas import (
    DashboardStats,
    HealthResponse,
    LogListResponse,
    LogResponse,
    ThreatSummary,
)
from backend.infrastructure.db.session import get_async_session
from backend.infrastructure.repositories.log_repo import LogRepository

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Consultas & Dashboard"])


@router.get(
    "/logs",
    response_model=LogListResponse,
    summary="Lista logs DNS com filtros e paginação",
    responses={
        200: {"description": "Lista paginada de logs DNS."},
        401: {"description": "API Key não fornecida."},
        403: {"description": "API Key inválida."},
    },
)
async def list_logs(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _api_key: Annotated[str, Depends(validate_api_key)],
    domain: str | None = Query(None, description="Filtro por domínio (parcial)"),
    threat_level: str | None = Query(None, description="Filtro por nível de ameaça"),
    agent_id: str | None = Query(None, description="Filtro por ID do agente"),
    source_ip: str | None = Query(None, description="Filtro por IP de origem"),
    start_time: datetime | None = Query(None, description="Início do período (ISO 8601)"),
    end_time: datetime | None = Query(None, description="Fim do período (ISO 8601)"),
    page: int = Query(1, ge=1, description="Número da página"),
    page_size: int = Query(50, ge=1, le=500, description="Itens por página"),
) -> LogListResponse:
    """Retorna logs DNS filtrados com paginação offset-based."""
    repo = LogRepository(session)
    offset = (page - 1) * page_size

    items, total = await repo.get_logs_filtered(
        domain=domain,
        threat_level=threat_level,
        agent_id=agent_id,
        source_ip=source_ip,
        start_time=start_time,
        end_time=end_time,
        offset=offset,
        limit=page_size,
    )

    return LogListResponse(
        total=total,
        page=page,
        page_size=page_size,
        items=[LogResponse.model_validate(item) for item in items],
    )


@router.get(
    "/stats",
    response_model=DashboardStats,
    summary="Estatísticas gerais do dashboard",
    responses={
        200: {"description": "Estatísticas agregadas."},
    },
)
async def get_dashboard_stats(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _api_key: Annotated[str, Depends(validate_api_key)],
) -> DashboardStats:
    """Retorna estatísticas agregadas para o dashboard principal."""
    repo = LogRepository(session)

    stats = await repo.get_dashboard_stats()
    top_threats_raw = await repo.get_top_threats(limit=10)
    top_queried = await repo.get_top_queried_domains(limit=10)

    top_threats = [
        ThreatSummary(
            domain=t["domain"],
            threat_level=t["threat_level"],
            hit_count=t["hit_count"],
            first_seen=t["first_seen"],
            last_seen=t["last_seen"],
            source_ips=t["source_ips"],
        )
        for t in top_threats_raw
    ]

    return DashboardStats(
        **stats,
        top_threats=top_threats,
        top_queried_domains=top_queried,
    )


@router.get(
    "/threats",
    response_model=list[ThreatSummary],
    summary="Top domínios maliciosos",
)
async def get_top_threats(
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _api_key: Annotated[str, Depends(validate_api_key)],
    limit: int = Query(20, ge=1, le=100, description="Número de resultados"),
) -> list[ThreatSummary]:
    """Retorna os domínios maliciosos mais frequentes."""
    repo = LogRepository(session)
    threats = await repo.get_top_threats(limit=limit)

    return [
        ThreatSummary(
            domain=t["domain"],
            threat_level=t["threat_level"],
            hit_count=t["hit_count"],
            first_seen=t["first_seen"],
            last_seen=t["last_seen"],
            source_ips=t["source_ips"],
        )
        for t in threats
    ]


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check da plataforma",
    status_code=status.HTTP_200_OK,
)
async def health_check() -> HealthResponse:
    """
    Verifica a saúde dos componentes críticos:
    database, redis e celery.
    """
    db_status = "connected"
    redis_status = "connected"
    celery_status = "connected"

    # Testar Redis
    try:
        redis_client = await get_redis()
        await redis_client.ping()
    except Exception:
        redis_status = "disconnected"

    # Testar Celery
    try:
        from backend.workers.celery_app import celery_app

        inspect = celery_app.control.inspect()
        if not inspect.ping():
            celery_status = "no_workers"
    except Exception:
        celery_status = "disconnected"

    overall = "healthy"
    if any(s != "connected" for s in [db_status, redis_status]):
        overall = "degraded"

    return HealthResponse(
        status=overall,
        database=db_status,
        redis=redis_status,
        celery=celery_status,
    )
