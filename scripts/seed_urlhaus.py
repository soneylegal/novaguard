"""
NovaGuard — Seed de Inteligência de Ameaças via URLhaus (abuse.ch).

Busca domínios maliciosos ativos do feed público URLhaus e insere
na tabela threat_intel do banco de dados via ORM.

Também inclui domínios maliciosos conhecidos adicionados manualmente.

Uso:
  python -m scripts.seed_urlhaus
  # ou dentro do container:
  docker compose run --rm api python -m scripts.seed_urlhaus
"""

from __future__ import annotations

import logging
import sys
from urllib.parse import urlparse

import httpx
from sqlalchemy.exc import IntegrityError

from backend.infrastructure.db.models import ThreatIntel
from backend.infrastructure.db.session import get_sync_session

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(message)s",
)
logger = logging.getLogger("novaguard.seed.urlhaus")

URLHAUS_FEED = "https://urlhaus.abuse.ch/downloads/text_online/"

# Domínios maliciosos conhecidos que não estão no URLhaus
MANUAL_DOMAINS = [
    "kernel-control-engine.christmas",
    "c2-strike.net",
    "c2-malicious-server.net",
]


def fetch_urlhaus_domains() -> list[str]:
    """Busca domínios ativos do feed público URLhaus."""
    logger.info("Buscando feed URLhaus: %s", URLHAUS_FEED)

    try:
        response = httpx.get(URLHAUS_FEED, timeout=30.0, follow_redirects=True)
        response.raise_for_status()
    except Exception as e:
        logger.error("Falha ao buscar URLhaus: %s", e)
        return []

    domains: set[str] = set()
    for line in response.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            host = urlparse(line).hostname
            if host and not all(c.isdigit() or c == "." for c in host):
                domains.add(host.lower())
        except Exception:
            continue

    logger.info("URLhaus: %d domínios únicos extraídos (excluindo IPs puros)", len(domains))
    return sorted(domains)


def seed() -> int:
    """Insere domínios do URLhaus + manuais na tabela threat_intel."""
    urlhaus_domains = fetch_urlhaus_domains()
    all_domains = urlhaus_domains + MANUAL_DOMAINS

    if not all_domains:
        logger.warning("Nenhum domínio para inserir.")
        return 1

    session = get_sync_session()
    inserted = 0
    skipped = 0

    try:
        for domain in all_domains:
            existing = session.query(ThreatIntel).filter(ThreatIntel.domain == domain).first()

            if existing:
                skipped += 1
                continue

            record = ThreatIntel(
                domain=domain,
                threat_type="malware",
                source="urlhaus_abuse_ch",
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
        logger.info("─" * 60)
        logger.info(
            "Seed concluído: %d inseridos, %d já existiam. Total no feed: %d",
            inserted,
            skipped,
            len(all_domains),
        )

    except Exception as e:
        session.rollback()
        logger.error("Seed falhou: %s", e, exc_info=True)
        return 1
    finally:
        session.close()

    return 0


if __name__ == "__main__":
    sys.exit(seed())
