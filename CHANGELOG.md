# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] — 2026-05-14

### Changed

- **IPC Architecture (Multiprocessing)** — O Edge Agent foi completamente reescrito. Scapy e BufferSender correm agora em processos isolados (`multiprocessing.Process`) comunicando via `multiprocessing.Queue`. Eliminação total de contenção de GIL e deadlocks no shutdown.
- **Graceful Shutdown via STOP_SENTINEL** — O processo principal envia `None` na Queue como sentinela. O BufferSender drena todos os itens restantes e executa um flush final com timeout agressivo de 3s, encerrando de forma limpa sem necessidade de `SIGTSTP` (Ctrl+Z).
- **Session Management Bulletproof** — As tasks Celery (`intel_tasks`, `sink_tasks`) foram refatoradas para o padrão `try/finally` com `session.close()` incondicional. Elimina connection leaks que causavam `QueuePool exhaustion` (TimeoutError).
- **CI Pipeline com Service Containers** — O workflow GitHub Actions agora levanta PostgreSQL 16 e Redis 7 como service containers. A CI executa `alembic upgrade head` contra um banco efémero e valida a integridade do esquema (presença das 3 tabelas) antes dos testes.

### Added

- **Worker Schema Inspector** — Hook `@worker_process_init.connect` que imprime todas as tabelas visíveis no banco ao iniciar cada processo worker, com alerta explícito se `threat_intel` estiver ausente.
- **ORM Seed Scripts** — `scripts/seed_threat_intel.py` e `scripts/seed_mixed_test.py` para popular a tabela `threat_intel` via ORM, respeitando defaults Python-level (`id`, `source`, `confidence`) que o SQL raw violava. Idempotentes com tratamento de colisões.
- **Stress Test Misto** — Seed com 4 tipos de ameaça (`c2_server`, `phishing`, `malware`) para validação de performance do pipeline Cache-Aside.

### Fixed

- **UndefinedTable: `threat_intel`** — Causa raiz: volume PostgreSQL stale com migração marcada como aplicada mas DDL não executado. Resolvido com procedimento de rebuild forçado (`down -v` + `build --no-cache` + `alembic upgrade head`).
- **QueuePool Exhaustion** — Sessões orphaned em caso de exceção antes do bloco `with` nos workers. O `session.close()` no `finally` garante devolução ao pool mesmo em falha catastrófica.
- **Dockerfile Multi-Stage** — `pip install -e` no stage `deps` falhava silenciosamente (código fonte ausente). Corrigido para `pip install .` com cópia mínima dos `__init__.py`.

---

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
