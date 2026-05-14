"""
NovaGuard — Seed de Inteligência de Ameaças (ORM).

Insere domínios de teste na tabela threat_intel utilizando
a infraestrutura ORM do projeto (modelos + sessão).

Trata colisões de domínios duplicados via merge (upsert).

Uso:
  python -m scripts.seed_threat_intel
  # ou dentro do container:
  docker compose run --rm api python -m scripts.seed_threat_intel
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
logger = logging.getLogger("novaguard.seed")

# ── Dados de Seed ────────────────────────────────────────────────

SEED_DOMAINS = [
    {
        "domain": "ataque-bancario-teste.com",
        "threat_type": "phishing",
        "source": "novaguard_qa_seed",
        "confidence": "high",
    },
    {
        "domain": "malware-puro-teste.net",
        "threat_type": "malware",
        "source": "novaguard_qa_seed",
        "confidence": "high",
    },
    {
        "domain": "malware-test.com",
        "threat_type": "malware",
        "source": "novaguard_qa_seed",
        "confidence": "high",
    },
    {
        "domain": "phishing-site.net",
        "threat_type": "phishing",
        "source": "novaguard_qa_seed",
        "confidence": "high",
    },
]


def seed() -> int:
    """Insere os domínios de seed, tratando colisões de forma elegante."""
    session = get_sync_session()
    inserted = 0

    try:
        for entry in SEED_DOMAINS:
            # Verifica se o domínio já existe
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
        logger.info("Seed concluído: %d domínios inseridos.", inserted)

    except Exception as e:
        session.rollback()
        logger.error("Seed falhou: %s", e, exc_info=True)
        return 1
    finally:
        session.close()

    return 0


if __name__ == "__main__":
    sys.exit(seed())
