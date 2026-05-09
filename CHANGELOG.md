# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-05-09

### Added

- **API Gateway** — FastAPI com ingestão assíncrona de lotes DNS via `POST /api/v1/ingest/` (202 Accepted, latência < 50ms).
- **Cache-Aside Pattern** — Classificação de domínios via Redis pipeline batch com TTL de 24h. Após warm-up, 95%+ dos domínios resolvidos sem acesso ao banco.
- **Bulk Inserts** — Persistência de alta performance no PostgreSQL/TimescaleDB (1.000 logs/transação via `INSERT INTO ... VALUES`). Chunking automático para evitar locks prolongados.
- **Edge Agent** — Sniffer DNS com Scapy (`udp port 53`, `store=False`) e envio resiliente via `BufferSender` com buffer em memória (1.000 logs ou 5s).
- **Exponential Backoff** — Resiliência total do agente: SQLite fallback local (WAL mode) com retry `2s → 4s → 8s → ... → 300s (cap)`. Drain FIFO ao reconectar. Garantia de **zero data loss**.
- **Repository Pattern** — Isolamento total entre lógica de negócios e persistência. Dual engine: `asyncpg` (FastAPI) + `psycopg2` (Celery workers).
- **Celery Workers** — Processamento assíncrono com filas separadas (`enrichment`, `sink`), `task_acks_late=True` e `task_reject_on_worker_lost=True` para resiliência.
- **Dashboard API** — Endpoints de consulta: listagem paginada (`/logs`), estatísticas agregadas (`/stats`), top ameaças (`/threats`), health check (`/health`).
- **Docker Compose** — Stack completa: API, PostgreSQL (TimescaleDB), Redis 7, Celery Worker, Flower (monitoring).
- **Alembic** — Migrações de banco com `autogenerate` a partir dos modelos SQLAlchemy.
- **CI/CD Pipeline** — GitHub Actions com lint (Black, Ruff, MyPy) e testes automatizados com cobertura (pytest-cov).
- **Docker Publish** — Workflow de publicação automática no GHCR (`ghcr.io`) via tags semânticas (`v*`).

### Security

- **API Key Authentication** — Header `X-API-KEY` com validação timing-safe via `secrets.compare_digest()`, imune a side-channel attacks. Erros: 401 (ausente) / 403 (inválida).
- **Rate Limiting** — Proteção anti-DDoS via `slowapi` na camada de aplicação, configurável via `.env` (`RATE_LIMIT=60/minute`).
- **Request Tracing** — UUID v4 injetado em cada resposta (`X-Request-ID`) para rastreabilidade completa.

### Testing

- **35 testes** — 29 unitários + 6 E2E, cobertura de 71.70%.
- Mock completo de infraestrutura (Redis, PostgreSQL, Celery) — zero dependência de serviços externos para executar testes.
- Coverage omissions configuradas para hardware boundaries (`agent/sniffer.py` — requer `sudo`/`CAP_NET_RAW`).

[1.0.0]: https://github.com/soneylegal/novaguarda/releases/tag/v1.0.0
