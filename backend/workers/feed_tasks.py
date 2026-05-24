"""
NovaGuard — Tasks de Atualização Automática de Threat Intelligence Feeds.

Busca periodicamente domínios maliciosos de fontes públicas e insere
na tabela threat_intel do banco de dados, eliminando manutenção manual.

Fontes ativas:
  - URLhaus (abuse.ch): Malware, C2, droppers — feed CSV público
  - PhishTank (OpenDNS): Phishing verificado — feed CSV público

Executado automaticamente via Celery Beat a cada 6 horas.
"""

from __future__ import annotations

import csv
import io
import logging
import zipfile
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy.exc import IntegrityError

from backend.core.config import get_settings
from backend.infrastructure.db.models import ThreatIntel
from backend.infrastructure.db.session import get_sync_session
from backend.workers.celery_app import celery_app

logger = logging.getLogger(__name__)
settings = get_settings()

# ── Feed URLs ────────────────────────────────────────────────────

URLHAUS_FEED = "https://urlhaus.abuse.ch/downloads/text_online/"
PHISHTANK_FEED = "http://data.phishtank.com/data/online-valid.csv"

# ── Whitelist de Domínios Confiáveis (Evitar Falsos Positivos de Feeds) ──
TRUSTED_BASE_DOMAINS = {
    "google.com",
    "google.com.br",
    "googleapis.com",
    "google-analytics.com",
    "googletagmanager.com",
    "googleadservices.com",
    "doubleclick.net",
    "googlesyndication.com",
    "github.com",
    "githubusercontent.com",
    "github.io",
    "microsoft.com",
    "microsoftonline.com",
    "live.com",
    "office.com",
    "office365.com",
    "sharepoint.com",
    "outlook.com",
    "apple.com",
    "icloud.com",
    "cloudflare.com",
    "cloudfront.net",
    "facebook.com",
    "instagram.com",
    "twitter.com",
    "linkedin.com",
    "t.co",
    "amazon.com",
    "amazonaws.com",
    "netflix.com",
    "youtube.com",
    "ytimg.com",
    "ggpht.com",
    "android.com",
    "yahoo.com",
    "yahoo.com.br",
    "reddit.com",
    "imgur.com",
    "wikipedia.org",
    "wikimedia.org",
    "wordpress.com",
    "wp.com",
    "zoom.us",
    "skype.com",
    "medium.com",
    "quora.com",
    "tumblr.com",
    "pinterest.com",
    "vimeo.com",
    "adnxs.com",
    "adnxs.net",
    "rubiconproject.com",
    "pubmatic.com",
    "openx.net",
    "criteo.com",
    "criteo.net",
    "casalemedia.com",
    "outbrain.com",
    "taboola.com",
    "adroll.com",
    "smartadserver.com",
}


def is_whitelisted(domain: str) -> bool:
    """Retorna True se o domínio ou subdomínio estiver na lista de confiáveis."""
    domain = domain.lower().strip()
    if domain in TRUSTED_BASE_DOMAINS:
        return True
    for trusted in TRUSTED_BASE_DOMAINS:
        if domain.endswith("." + trusted):
            return True
    return False


# ── Helpers ──────────────────────────────────────────────────────


def _extract_domains_from_urls(lines: list[str]) -> set[str]:
    """Extrai domínios únicos de uma lista de URLs, excluindo IPs puros."""
    domains: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            host = urlparse(line).hostname
            if host and not all(c.isdigit() or c == "." for c in host):
                domains.add(host.lower())
        except Exception:
            continue
    return domains


def _bulk_upsert_domains(
    domains: set[str],
    threat_type: str,
    source: str,
) -> dict[str, int]:
    """Insere domínios na tabela threat_intel, ignorando duplicatas."""
    session = get_sync_session()
    inserted = 0
    skipped = 0

    try:
        for domain in domains:
            if is_whitelisted(domain):
                skipped += 1
                continue

            existing = session.query(ThreatIntel).filter(ThreatIntel.domain == domain).first()

            if existing:
                skipped += 1
                continue

            record = ThreatIntel(
                domain=domain,
                threat_type=threat_type,
                source=source,
                confidence="high",
            )
            session.add(record)

            try:
                session.flush()
                inserted += 1
            except IntegrityError:
                session.rollback()
                skipped += 1

        session.commit()
    except Exception as e:
        session.rollback()
        logger.error("Bulk upsert failed for source '%s': %s", source, e, exc_info=True)
        raise
    finally:
        session.close()

    return {"inserted": inserted, "skipped": skipped}


# ── Tasks ────────────────────────────────────────────────────────


@celery_app.task(
    name="workers.feed_tasks.sync_urlhaus",
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    queue="feeds",
)
def sync_urlhaus(self) -> dict[str, Any]:
    """
    Busca domínios maliciosos ativos do URLhaus (abuse.ch).

    Feed: URLs de malware, C2, droppers online verificados.
    Frequência recomendada: a cada 6 horas.
    """
    logger.info("Feed sync starting: URLhaus (abuse.ch)")

    try:
        response = httpx.get(URLHAUS_FEED, timeout=30.0, follow_redirects=True)
        response.raise_for_status()
    except Exception as exc:
        logger.error("Failed to fetch URLhaus feed: %s", exc)
        raise self.retry(exc=exc)

    lines = response.text.splitlines()
    domains = _extract_domains_from_urls(lines)

    logger.info("URLhaus: %d unique domains extracted", len(domains))

    if not domains:
        return {"source": "urlhaus", "total_fetched": 0, "inserted": 0, "skipped": 0}

    result = _bulk_upsert_domains(domains, threat_type="malware", source="urlhaus_abuse_ch")

    logger.info(
        "URLhaus sync complete: %d inserted, %d skipped",
        result["inserted"],
        result["skipped"],
    )
    return {
        "source": "urlhaus",
        "total_fetched": len(domains),
        **result,
    }


@celery_app.task(
    name="workers.feed_tasks.sync_phishtank",
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    queue="feeds",
)
def sync_phishtank(self) -> dict[str, Any]:
    """
    Busca domínios de phishing verificados do PhishTank (OpenDNS).

    Feed: CSV com URLs de phishing verificados e online.
    Frequência recomendada: a cada 6 horas.
    """
    logger.info("Feed sync starting: PhishTank (OpenDNS)")

    try:
        response = httpx.get(
            PHISHTANK_FEED,
            timeout=60.0,
            follow_redirects=True,
            headers={"User-Agent": "NovaGuard/1.0 (Threat Intel Sync)"},
        )
        response.raise_for_status()
    except Exception as exc:
        logger.error("Failed to fetch PhishTank feed: %s", exc)
        raise self.retry(exc=exc)

    # Parse CSV: colunas → phish_id, url, phish_detail_url, submission_time, verified, ...
    domains: set[str] = set()
    reader = csv.DictReader(io.StringIO(response.text))

    for row in reader:
        url = row.get("url", "")
        try:
            host = urlparse(url).hostname
            if host and not all(c.isdigit() or c == "." for c in host):
                domains.add(host.lower())
        except Exception:
            continue

    logger.info("PhishTank: %d unique domains extracted", len(domains))

    if not domains:
        return {"source": "phishtank", "total_fetched": 0, "inserted": 0, "skipped": 0}

    result = _bulk_upsert_domains(domains, threat_type="phishing", source="phishtank_opendns")

    logger.info(
        "PhishTank sync complete: %d inserted, %d skipped",
        result["inserted"],
        result["skipped"],
    )
    return {
        "source": "phishtank",
        "total_fetched": len(domains),
        **result,
    }


@celery_app.task(
    name="workers.feed_tasks.sync_top_domains",
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    queue="feeds",
)
def sync_top_domains(self) -> dict[str, Any]:
    """
    Sincroniza a lista dos 100.000 domínios mais populares do Cisco Umbrella.
    Salva os domínios em um set do Redis ('whitelist:top_domains').
    """
    logger.info("═" * 60)
    logger.info("Starting Cisco Umbrella Top Domains sync...")
    logger.info("═" * 60)

    url = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
    try:
        response = httpx.get(url, timeout=60.0)
        response.raise_for_status()
    except Exception as exc:
        logger.error("Failed to fetch Cisco Umbrella feed: %s", exc)
        raise self.retry(exc=exc)

    redis_client = None
    try:
        from backend.workers.intel_tasks import _get_sync_redis

        redis_client = _get_sync_redis()

        with zipfile.ZipFile(io.BytesIO(response.content)) as z:
            with z.open("top-1m.csv") as f:
                reader = csv.reader(io.TextIOWrapper(f, encoding="utf-8"))
                top_domains = []
                for i, row in enumerate(reader):
                    if i >= 100000:  # Limite para os top 100.000 domínios
                        break
                    if len(row) >= 2:
                        top_domains.append(row[1].lower().strip())

        logger.info("Umbrella: Extracted %d domains from zip", len(top_domains))

        if top_domains:
            # Substitui o set antigo de uma vez
            redis_client.delete("whitelist:top_domains")
            chunk_size = 5000
            pipe = redis_client.pipeline(transaction=False)
            for j in range(0, len(top_domains), chunk_size):
                chunk = top_domains[j : j + chunk_size]
                pipe.sadd("whitelist:top_domains", *chunk)
            pipe.execute()
            logger.info("Umbrella: Successfully loaded 100,000 domains into Redis set")

        return {
            "source": "umbrella",
            "total_fetched": len(top_domains),
            "status": "success",
        }
    except Exception as exc:
        logger.error("Failed to process Cisco Umbrella feed: %s", exc)
        raise
    finally:
        if redis_client:
            redis_client.close()


@celery_app.task(
    name="workers.feed_tasks.sync_all_feeds",
    bind=True,
    queue="feeds",
)
def sync_all_feeds(self) -> dict[str, Any]:
    """
    Orquestra a sincronização de todos os feeds de Threat Intelligence.
    Chamado pelo Celery Beat a cada 6 horas.
    """
    logger.info("═" * 60)
    logger.info("Starting scheduled Threat Intelligence feed sync...")
    logger.info("═" * 60)

    results = {}

    # URLhaus
    try:
        results["urlhaus"] = sync_urlhaus()
    except Exception as e:
        logger.error("URLhaus sync failed: %s", e)
        results["urlhaus"] = {"error": str(e)}

    # PhishTank
    try:
        results["phishtank"] = sync_phishtank()
    except Exception as e:
        logger.error("PhishTank sync failed: %s", e)
        results["phishtank"] = {"error": str(e)}

    # Cisco Umbrella Top Domains
    try:
        results["umbrella"] = sync_top_domains()
    except Exception as e:
        logger.error("Cisco Umbrella sync failed: %s", e)
        results["umbrella"] = {"error": str(e)}

    total_inserted = sum(r.get("inserted", 0) for r in results.values() if isinstance(r, dict))
    logger.info("═" * 60)
    logger.info("Feed sync complete. Total new threat domains: %d", total_inserted)
    logger.info("═" * 60)

    return results
