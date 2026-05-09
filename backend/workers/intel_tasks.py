"""
NovaGuard — Task de Enriquecimento (Intel Enrichment).

Pipeline de enriquecimento do lote DNS:
  1. Extrai domínios únicos do lote
  2. Consulta Redis Cache (Cache-Aside) para classificações conhecidas
  3. Para domínios desconhecidos, cruza com a tabela threat_intel do BD
  4. Atualiza o cache com as novas classificações
  5. Enriquece cada log com threat_level e threat_source
  6. Despacha o lote enriquecido para a task de persistência (sink)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import redis as sync_redis

from backend.core.config import get_settings
from backend.infrastructure.db.session import get_sync_session
from backend.infrastructure.repositories.log_repo import SyncLogRepository
from backend.workers.celery_app import celery_app

logger = logging.getLogger(__name__)

settings = get_settings()


def _get_sync_redis() -> sync_redis.Redis:
    """Cria um cliente Redis síncrono para uso no worker Celery."""
    return sync_redis.from_url(
        settings.redis_url,
        decode_responses=True,
        max_connections=10,
    )


@celery_app.task(
    name="workers.intel_tasks.process_and_enrich_batch",
    bind=True,
    max_retries=3,
    default_retry_delay=5,
    acks_late=True,
    queue="enrichment",
)
def process_and_enrich_batch(
    self,
    batch_id: str,
    agent_id: str,
    logs: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Processa e enriquece um lote de logs DNS.

    Estratégia Cache-Aside:
      - Cache HIT → usa classificação imediatamente
      - Cache MISS → consulta threat_intel no BD → atualiza cache (TTL 24h)
    """
    logger.info(
        "Processing batch %s: %d logs from agent '%s'",
        batch_id, len(logs), agent_id,
    )

    try:
        redis_client = _get_sync_redis()
        session = get_sync_session()
        repo = SyncLogRepository(session)

        # ── 1. Extrair domínios únicos ───────────────────────────
        unique_domains = {log["domain"] for log in logs}
        logger.info("Batch %s: %d unique domains to classify", batch_id, len(unique_domains))

        # ── 2. Consultar Cache Redis (pipeline para batch) ───────
        pipe = redis_client.pipeline(transaction=False)
        for domain in unique_domains:
            pipe.get(f"domain:{domain}")
        cache_results = pipe.execute()

        domain_list = list(unique_domains)
        classifications: dict[str, str] = {}
        uncached_domains: list[str] = []

        for domain, cached_value in zip(domain_list, cache_results):
            if cached_value:
                classifications[domain] = cached_value
            else:
                uncached_domains.append(domain)

        logger.info(
            "Batch %s: %d cache hits, %d cache misses",
            batch_id,
            len(classifications),
            len(uncached_domains),
        )

        # ── 3. Consultar threat_intel no BD (cache misses) ───────
        if uncached_domains:
            known_threats = repo.get_threat_domains()

            for domain in uncached_domains:
                if domain in known_threats:
                    classifications[domain] = "malicious"
                else:
                    classifications[domain] = "safe"

            # ── 4. Atualizar Cache com novas classificações ──────
            pipe = redis_client.pipeline(transaction=False)
            for domain in uncached_domains:
                pipe.set(
                    f"domain:{domain}",
                    classifications[domain],
                    ex=settings.cache_ttl_seconds,
                )
            pipe.execute()

            logger.info(
                "Batch %s: cached %d new domain classifications",
                batch_id, len(uncached_domains),
            )

        # ── 5. Enriquecer cada log ───────────────────────────────
        enriched_logs = []
        now = datetime.now(timezone.utc).isoformat()

        for log in logs:
            domain = log["domain"]
            threat = classifications.get(domain, "unknown")

            enriched_logs.append({
                "timestamp": log["timestamp"],
                "source_ip": log["source_ip"],
                "destination_ip": log["destination_ip"],
                "domain": domain,
                "query_type": log.get("query_type", "A"),
                "protocol": log.get("protocol", "DNS"),
                "agent_id": log.get("agent_id") or agent_id,
                "threat_level": threat,
                "threat_source": "threat_intel_db" if threat == "malicious" else None,
                "enriched_at": now,
            })

        # ── 6. Despachar para o sink (persistência) ──────────────
        celery_app.send_task(
            "workers.sink_tasks.bulk_persist_logs",
            kwargs={
                "batch_id": batch_id,
                "enriched_logs": enriched_logs,
            },
            queue="sink",
        )

        session.close()
        redis_client.close()

        result = {
            "batch_id": batch_id,
            "total_logs": len(logs),
            "unique_domains": len(unique_domains),
            "cache_hits": len(unique_domains) - len(uncached_domains),
            "cache_misses": len(uncached_domains),
            "malicious_count": sum(
                1 for c in classifications.values() if c == "malicious"
            ),
        }

        logger.info("Batch %s enrichment complete: %s", batch_id, result)
        return result

    except Exception as exc:
        logger.error("Batch %s enrichment failed: %s", batch_id, exc, exc_info=True)
        raise self.retry(exc=exc)
