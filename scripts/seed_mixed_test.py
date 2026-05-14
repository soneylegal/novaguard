"""
NovaGuard — Seed Misto para Stress Test (ORM).

Popula a tabela threat_intel com domínios de teste de carga,
cobrindo múltiplos tipos de ameaça (C2, PHISHING, MALWARE).

Idempotente: ignora domínios já existentes.

Uso:
  python -m scripts.seed_mixed_test
  # ou dentro do container:
  docker compose run --rm api python -m scripts.seed_mixed_test
"""

from __future__ import annotations

import logging
import sys

from sqlalchemy.exc import IntegrityError

from backend.infrastructure.db.models import ThreatIntel
from backend.infrastructure.db.session import get_sync_session

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(message)s",
)
logger = logging.getLogger("novaguard.seed_mixed")

# ── Dados de Seed (Stress Test Misto) ────────────────────────────

SEED_DOMAINS = [
    {
        "domain": "c2-strike.net",
        "threat_type": "c2_server",
        "source": "stress_test",
        "confidence": "100",
    },
    {
        "domain": "phishing-banco.com",
        "threat_type": "phishing",
        "source": "stress_test",
        "confidence": "100",
    },
    {
        "domain": "malware-drop.org",
        "threat_type": "malware",
        "source": "stress_test",
        "confidence": "100",
    },
    {
        "domain": "stealer-payload.info",
        "threat_type": "malware",
        "source": "stress_test",
        "confidence": "100",
    },
]


def seed() -> int:
    """Insere os domínios de stress test, tratando colisões."""
    session = get_sync_session()
    inserted = 0

    try:
        for entry in SEED_DOMAINS:
            existing = (
                session.query(ThreatIntel).filter(ThreatIntel.domain == entry["domain"]).first()
            )

            if existing:
                logger.info("⏭  Domínio já existe, ignorando: %s", entry["domain"])
                continue

            record = ThreatIntel(**entry)
            session.add(record)

            try:
                session.flush()
                logger.info("✅ Inserido: %s (tipo=%s)", entry["domain"], entry["threat_type"])
                inserted += 1
            except IntegrityError:
                session.rollback()
                logger.warning("⚠️  Colisão detectada para: %s", entry["domain"])

        session.commit()
        logger.info("─" * 50)
        logger.info("Seed misto concluído: %d domínios inseridos.", inserted)

    except Exception as e:
        session.rollback()
        logger.error("Seed falhou: %s", e, exc_info=True)
        return 1
    finally:
        session.close()

    return 0


if __name__ == "__main__":
    sys.exit(seed())
