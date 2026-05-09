"""
NovaGuard — Rota de Ingestão (API Gateway).

Rota hiper-otimizada para recebimento de lotes de logs DNS.
Fluxo:
  1. Valida X-API-KEY (O(1) via secrets.compare_digest)
  2. Valida payload contra LogBatchCreate (Pydantic v2 / orjson)
  3. Responde 202 Accepted em < 50ms
  4. Despacha o lote inteiro para a fila Celery (assíncrono)

O tempo de resposta é crítico — o agente de borda não pode ficar bloqueado.
"""

from __future__ import annotations

import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from backend.core.security import validate_api_key
from backend.domain.schemas import IngestResponse, LogBatchCreate
from backend.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

router = APIRouter(tags=["Ingestão"])


@router.post(
    "/",
    response_model=IngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Recebe um lote de logs DNS do agente de borda",
    description=(
        "Endpoint de alta performance para ingestão de lotes. "
        "Valida o payload, responde 202 Accepted e enfileira o "
        "lote para processamento assíncrono via Celery."
    ),
    responses={
        202: {"description": "Lote aceito e enfileirado para processamento."},
        401: {"description": "API Key não fornecida."},
        403: {"description": "API Key inválida."},
        422: {"description": "Payload inválido (validação Pydantic)."},
        429: {"description": "Rate limit excedido."},
    },
)
async def ingest_batch(
    batch: LogBatchCreate,
    api_key: Annotated[str, Depends(validate_api_key)],
) -> IngestResponse:
    """
    Recebe e enfileira um lote de logs DNS para processamento.

    O payload é serializado via orjson e despachado para o worker Celery
    que fará o enriquecimento (cruzamento com listas de ameaças) e
    a persistência em lote no PostgreSQL.
    """
    batch_id = str(uuid.uuid4())
    log_count = len(batch.logs)

    # Serializa para dicionários (compatível com JSON/Celery)
    serialized_logs = [log.model_dump(mode="json") for log in batch.logs]

    # Despacha para o Celery — fire-and-forget
    celery_app.send_task(
        "workers.intel_tasks.process_and_enrich_batch",
        kwargs={
            "batch_id": batch_id,
            "agent_id": batch.agent_id,
            "logs": serialized_logs,
        },
        queue="enrichment",
    )

    logger.info(
        "Batch %s accepted: %d logs from agent '%s' (key: %s...)",
        batch_id,
        log_count,
        batch.agent_id,
        api_key[:8],
    )

    return IngestResponse(
        status="accepted",
        message=f"Lote de {log_count} logs enfileirado para processamento.",
        batch_id=batch_id,
        log_count=log_count,
    )
