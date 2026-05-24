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
from datetime import UTC, datetime
from typing import Any

import redis as sync_redis

from backend.core.config import get_settings
from backend.core.entropy import extract_registered_domain, is_dga_suspicious
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
        batch_id,
        len(logs),
        agent_id,
    )

    session = get_sync_session()
    redis_client = None
    try:
        redis_client = _get_sync_redis()

        # ── 1. Extrair domínios únicos ───────────────────────────
        unique_domains = {log["domain"] for log in logs}
        logger.info("Batch %s: %d unique domains to classify", batch_id, len(unique_domains))

        # ── 2. Consultar Cache Redis (pipeline para batch) ───────
        domain_list = sorted(unique_domains)
        pipe = redis_client.pipeline(transaction=False)
        for domain in domain_list:
            pipe.get(f"domain:{domain}")
        cache_results = pipe.execute()

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
            # ── 3.1. Filtro sistemático via Whitelist de Domínios Populares (Umbrella) ──
            pipe = redis_client.pipeline(transaction=False)
            for domain in uncached_domains:
                reg_domain = extract_registered_domain(domain)
                pipe.sismember("whitelist:top_domains", reg_domain)
            whitelist_results = pipe.execute()

            remaining_uncached_domains: list[str] = []
            for domain, is_whitelisted in zip(uncached_domains, whitelist_results):
                if is_whitelisted:
                    classifications[domain] = "safe"
                else:
                    remaining_uncached_domains.append(domain)

            logger.info(
                "Batch %s: %d domains bypassed via Umbrella whitelist, "
                "%d remaining for DB/DGA check",
                batch_id,
                len(uncached_domains) - len(remaining_uncached_domains),
                len(remaining_uncached_domains),
            )

            if remaining_uncached_domains:
                repo = SyncLogRepository(session)
                known_threats = repo.get_threat_types_for_domains(remaining_uncached_domains)

                for domain in remaining_uncached_domains:
                    if domain in known_threats:
                        classifications[domain] = known_threats[domain]
                    else:
                        # Regra de Decisão Multivariada (Entropia + Filtros de Densidade)
                        verdict = is_dga_suspicious(
                            domain,
                            entropy_threshold=settings.dga_entropy_threshold,
                            min_length=settings.dga_min_length,
                        )

                        if verdict.is_suspicious:
                            classifications[domain] = "suspicious"
                            logger.info(
                                "DGA detected: %s (H=%.2f, vowel=%.0f%%, digit=%.0f%%, cc=%d)",
                                domain,
                                verdict.entropy,
                                verdict.density.vowel_ratio * 100,
                                verdict.density.digit_ratio * 100,
                                verdict.density.max_consonant_cluster,
                            )
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
                batch_id,
                len(uncached_domains),
            )

        # ── 5. Enriquecer cada log ───────────────────────────────
        enriched_logs = []
        now = datetime.now(UTC).isoformat()

        for log in logs:
            domain = log["domain"]
            classification = classifications.get(domain, "unknown")

            if classification == "safe":
                threat_level = "safe"
                threat_source = None
            elif classification == "unknown":
                threat_level = "unknown"
                threat_source = None
            elif classification == "suspicious":
                threat_level = "suspicious"
                threat_source = "dga_entropy_analysis"
            else:
                threat_level = "malicious"
                threat_source = "threat_intel_db"

            enriched_logs.append(
                {
                    "timestamp": log["timestamp"],
                    "source_ip": log["source_ip"],
                    "destination_ip": log["destination_ip"],
                    "domain": domain,
                    "query_type": log.get("query_type", "A"),
                    "protocol": log.get("protocol", "DNS"),
                    "agent_id": log.get("agent_id") or agent_id,
                    "threat_level": threat_level,
                    "threat_source": threat_source,
                    "enriched_at": now,
                }
            )

        # ── 5.1. Identificar ameaças críticas e disparar alertas ─
        alerted_keys = set()
        for log in enriched_logs:
            if log["threat_level"] in ("malicious", "suspicious"):
                if log["threat_level"] == "suspicious":
                    threat_type = "dga_suspicious"
                else:
                    threat_type = classifications.get(log["domain"], "malware")

                key = (log["source_ip"], log["domain"], threat_type)
                if key not in alerted_keys:
                    alerted_keys.add(key)

                    # Garantir que o timestamp seja serializado como string ISO
                    ts = log["timestamp"]
                    if hasattr(ts, "isoformat"):
                        ts_str = ts.isoformat()
                    else:
                        ts_str = str(ts)

                    # DISPARAR ALERTA CELERY
                    celery_app.send_task(
                        "workers.alert_tasks.send_alert_task",
                        kwargs={
                            "source_ip": log["source_ip"],
                            "domain": log["domain"],
                            "threat_type": threat_type,
                            "timestamp": ts_str,
                        },
                        queue="alerts",
                    )

                    # DISPARAR COMANDO IPS (Redis Pub/Sub) - apenas para ameaças
                    # confirmadas (malicious)
                    if log["threat_level"] == "malicious":
                        import json

                        try:
                            redis_client.publish(
                                "novaguard:ips:commands",
                                json.dumps(
                                    {
                                        "command": "quarantine",
                                        "source_ip": log["source_ip"],
                                        "domain": log["domain"],
                                        "threat_type": threat_type,
                                        "timestamp": ts_str,
                                    }
                                ),
                            )
                            logger.info(
                                "Published quarantine command to Redis Pub/Sub for IP: %s",
                                log["source_ip"],
                            )
                        except Exception as e:
                            logger.error("Failed to publish quarantine command to Redis: %s", e)

        # ── 6. Despacha para o sink (persistência) ──────────────
        celery_app.send_task(
            "workers.sink_tasks.bulk_persist_logs",
            kwargs={
                "batch_id": batch_id,
                "enriched_logs": enriched_logs,
            },
            queue="sink",
        )

        result = {
            "batch_id": batch_id,
            "total_logs": len(logs),
            "unique_domains": len(unique_domains),
            "cache_hits": len(unique_domains) - len(uncached_domains),
            "cache_misses": len(uncached_domains),
            "malicious_count": sum(
                1 for c in classifications.values() if c not in ("safe", "unknown", "suspicious")
            ),
            "suspicious_count": sum(1 for c in classifications.values() if c == "suspicious"),
        }

        logger.info("Batch %s enrichment complete: %s", batch_id, result)
        return result

    except Exception as exc:
        logger.error("Batch %s enrichment failed: %s", batch_id, exc, exc_info=True)
        raise self.retry(exc=exc)
    finally:
        # GARANTIA: recursos sempre fechados, independente de exceção
        if redis_client:
            try:
                redis_client.close()
            except Exception:
                pass
        session.close()
