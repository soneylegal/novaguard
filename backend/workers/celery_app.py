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

from celery import Celery

from backend.core.config import get_settings

settings = get_settings()

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
    worker_max_tasks_per_child=1000,  # Recicla worker a cada 1000 tasks
    worker_concurrency=4,

    # ── Retry Defaults ───────────────────────────────────────────
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_default_retry_delay=5,
    task_max_retries=3,

    # ── Result ───────────────────────────────────────────────────
    result_expires=3600,  # Results expiram em 1h

    # ── Imports ──────────────────────────────────────────────────
    include=[
        "backend.workers.intel_tasks",
        "backend.workers.sink_tasks",
    ],
)
