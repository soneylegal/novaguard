"""
NovaGuard — Cliente Redis (Singleton).

Implementa o padrão Cache-Aside para domínios DNS:
  1. Checa o cache antes de qualquer análise pesada.
  2. Se presente → retorna imediatamente (hit).
  3. Se ausente  → analisa, persiste no BD e popula o cache com TTL de 24h.
"""

from __future__ import annotations

import logging
from typing import Optional

import redis.asyncio as aioredis

from backend.core.config import get_settings

logger = logging.getLogger(__name__)

# ── Singleton ────────────────────────────────────────────────────
_redis_client: Optional[aioredis.Redis] = None


async def get_redis() -> aioredis.Redis:
    """
    Retorna a instância singleton do cliente Redis assíncrono.
    Cria a conexão apenas na primeira invocação.
    """
    global _redis_client
    if _redis_client is None:
        settings = get_settings()
        _redis_client = aioredis.from_url(
            settings.redis_url,
            decode_responses=True,
            max_connections=50,
        )
        logger.info("Redis client initialized: %s", settings.redis_url)
    return _redis_client


async def close_redis() -> None:
    """Encerra a conexão Redis de forma limpa durante o shutdown."""
    global _redis_client
    if _redis_client is not None:
        await _redis_client.close()
        _redis_client = None
        logger.info("Redis client closed.")


# ── Cache-Aside Helpers ──────────────────────────────────────────

async def cache_get_domain(domain: str) -> Optional[str]:
    """
    Consulta o cache para verificar a classificação de um domínio.

    Returns:
        "safe", "malicious", ou None (cache miss).
    """
    client = await get_redis()
    result = await client.get(f"domain:{domain}")
    if result:
        logger.debug("Cache HIT: %s → %s", domain, result)
    else:
        logger.debug("Cache MISS: %s", domain)
    return result


async def cache_set_domain(domain: str, classification: str) -> None:
    """
    Popula o cache com a classificação do domínio.
    TTL padrão: 24 horas (configurável via CACHE_TTL_SECONDS).
    """
    settings = get_settings()
    client = await get_redis()
    await client.set(
        f"domain:{domain}",
        classification,
        ex=settings.cache_ttl_seconds,
    )
    logger.debug("Cache SET: %s → %s (TTL=%ds)", domain, classification, settings.cache_ttl_seconds)


async def cache_get_domains_batch(domains: list[str]) -> dict[str, Optional[str]]:
    """
    Consulta em lote usando pipeline Redis para minimizar roundtrips.

    Returns:
        Dicionário {domínio: classificação_ou_None}.
    """
    client = await get_redis()
    pipe = client.pipeline(transaction=False)

    for domain in domains:
        pipe.get(f"domain:{domain}")

    results = await pipe.execute()
    return {domain: result for domain, result in zip(domains, results)}


async def cache_set_domains_batch(
    classifications: dict[str, str],
) -> None:
    """
    Popula o cache em lote usando pipeline Redis.
    """
    settings = get_settings()
    client = await get_redis()
    pipe = client.pipeline(transaction=False)

    for domain, classification in classifications.items():
        pipe.set(f"domain:{domain}", classification, ex=settings.cache_ttl_seconds)

    await pipe.execute()
    logger.debug("Cache BATCH SET: %d domains", len(classifications))
