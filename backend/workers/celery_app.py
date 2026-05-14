"""
NovaGuard — Celery Application.

Configuração central do Celery com:
  - Redis como broker e result backend
  - Serialização via JSON (segurança)
  - Filas separadas para enrichment e sink
  - Task routing automático
  - Retry policies para resiliência
"""

from __future__ import annotations

import logging

from celery import Celery
from celery.signals import worker_process_init

from backend.core.config import get_settings

logger = logging.getLogger("novaguard")

settings = get_settings()


@worker_process_init.connect
def on_worker_init(**kwargs):
    """Log das tabelas visíveis no banco ao iniciar cada processo worker."""
    from sqlalchemy import inspect as sa_inspect

    from backend.infrastructure.db.session import sync_engine

    try:
        inspector = sa_inspect(sync_engine)
        tables = inspector.get_table_names()
        logger.info("Worker init — Tables in DB: %s", tables)
        if "threat_intel" not in tables:
            logger.error(
                "CRITICAL: tabela 'threat_intel' NÃO encontrada! " "Execute: alembic upgrade head"
            )
    except Exception as e:
        logger.error("Failed to inspect DB on worker init: %s", e)


# ── Celery App ───────────────────────────────────────────────────

celery_app = Celery(
    "novaguard",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
)

celery_app.conf.update(
    # ── Serialização ─────────────────────────────────────────────
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    # ── Timezone ─────────────────────────────────────────────────
    timezone="UTC",
    enable_utc=True,
    # ── Filas ────────────────────────────────────────────────────
    task_default_queue="default",
    task_routes={
        "workers.intel_tasks.*": {"queue": "enrichment"},
        "workers.sink_tasks.*": {"queue": "sink"},
    },
    # ── Performance ──────────────────────────────────────────────
    worker_prefetch_multiplier=4,
    worker_max_tasks_per_child=1000,
    worker_concurrency=4,
    # ── Retry Defaults ───────────────────────────────────────────
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_default_retry_delay=5,
    task_max_retries=3,
    # ── Result ───────────────────────────────────────────────────
    result_expires=3600,
    # ── Imports ──────────────────────────────────────────────────
    include=[
        "backend.workers.intel_tasks",
        "backend.workers.sink_tasks",
    ],
)
