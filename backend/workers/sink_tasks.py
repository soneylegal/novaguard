"""
NovaGuard — Task de Persistência (Sink).

Responsável por gravar lotes enriquecidos no PostgreSQL.
Estratégia:
  - Usa `insert().values()` para bulk insert (1000+ registros por transação)
  - Retry automático com backoff em caso de falha no BD
  - Chunking para lotes maiores que BULK_INSERT_SIZE
"""

from __future__ import annotations

import logging
from typing import Any

from backend.core.config import get_settings
from backend.infrastructure.db.session import get_sync_session
from backend.infrastructure.repositories.log_repo import SyncLogRepository
from backend.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

settings = get_settings()


@celery_app.task(
    name="workers.sink_tasks.bulk_persist_logs",
    bind=True,
    max_retries=5,
    default_retry_delay=10,
    acks_late=True,
    queue="sink",
)
def bulk_persist_logs(
    self,
    batch_id: str,
    enriched_logs: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Persiste um lote de logs enriquecidos no PostgreSQL.

    Para lotes maiores que BULK_INSERT_SIZE, divide em chunks
    e insere cada chunk em uma transação separada, evitando
    locks prolongados na tabela.
    """
    total = len(enriched_logs)
    logger.info(
        "Sink: persisting batch %s (%d logs)",
        batch_id, total,
    )

    try:
        session = get_sync_session()
        repo = SyncLogRepository(session)

        chunk_size = settings.bulk_insert_size
        inserted = 0

        # Chunked insert para evitar transações gigantes
        for i in range(0, total, chunk_size):
            chunk = enriched_logs[i : i + chunk_size]
            count = repo.bulk_insert(chunk)
            inserted += count
            logger.debug(
                "Batch %s: chunk %d-%d persisted (%d records)",
                batch_id, i, i + len(chunk), count,
            )

        repo.close()

        result = {
            "batch_id": batch_id,
            "total_persisted": inserted,
            "chunks": (total + chunk_size - 1) // chunk_size,
        }

        logger.info("Sink: batch %s complete — %d logs persisted", batch_id, inserted)
        return result

    except Exception as exc:
        logger.error(
            "Sink: batch %s persistence failed: %s",
            batch_id, exc, exc_info=True,
        )
        raise self.retry(exc=exc, countdown=10 * (self.request.retries + 1))
