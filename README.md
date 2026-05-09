# 🛡️ NovaGuard — Plataforma de Inteligência e Ameaças DNS

[![CI](https://github.com/soneylegal/novaguarda/actions/workflows/ci.yml/badge.svg)](https://github.com/soneylegal/novaguarda/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Plataforma distribuída de ingestão e análise de tráfego DNS com pipeline de dados enterprise-grade — alta resiliência, enriquecimento assíncrono e cache em memória.

---

## Arquitetura

```
┌──────────────┐     HTTP POST      ┌──────────────┐     Celery Queue     ┌──────────────┐
│  Edge Agent  │ ──── (Batch) ────▶ │  API Gateway │ ── (Enrichment) ──▶ │   Worker     │
│  (Scapy)     │     X-API-KEY      │  (FastAPI)   │                      │  (Celery)    │
└──────┬───────┘                    └──────────────┘                      └──────┬───────┘
       │                                                                         │
       │ fallback                   ┌──────────────┐     Bulk Insert      ┌──────▼───────┐
       └──▶ SQLite (local)          │    Redis     │ ◀── Cache-Aside ──▶ │  PostgreSQL  │
                                    │  (Cache +    │                      │ (TimescaleDB)│
                                    │   Broker)    │                      └──────────────┘
                                    └──────────────┘
```

### Fluxo de Dados

1. **Edge Agent** captura pacotes DNS via Scapy (`udp port 53`)
2. Logs acumulados em buffer de memória (1000 logs ou 5s)
3. Envio via HTTP POST para o **API Gateway** com `X-API-KEY`
4. API valida e enfileira no Celery (resposta **202 Accepted** em < 50ms)
5. **Worker** enriquece domínios via **Cache-Aside** (Redis → threat_intel)
6. Logs enriquecidos persistidos via **Bulk Insert** (1000/transação)
7. Se API offline: **SQLite fallback** + **exponential backoff** (2s → 300s)

---

## Stack Tecnológico

| Componente | Tecnologia | Propósito |
|---|---|---|
| API Framework | FastAPI | I/O Assíncrono, OpenAPI nativo |
| Task Queue | Celery + Redis | Processamento assíncrono |
| Cache | Redis | Cache-Aside (TTL 24h) |
| Banco de Dados | PostgreSQL + TimescaleDB | Séries temporais |
| ORM | SQLAlchemy 2.0 | Async + Repository Pattern |
| Rate Limiting | slowapi | Anti-DDoS |
| Segurança | API Keys (X-API-KEY) | Autenticação de agentes |
| Sniffer | Scapy | Captura de pacotes DNS |
| Containerização | Docker + docker-compose | Orquestração |

---

## Início Rápido

### 1. Clonar e configurar

```bash
git clone https://github.com/soneylegal/novaguarda.git
cd novaguarda
cp .env.example .env
```

### 2. Subir a stack completa

```bash
docker compose up -d --build
```

Serviços disponíveis:

| Serviço | URL | Descrição |
|---|---|---|
| API | http://localhost:8000 | FastAPI + OpenAPI docs |
| Docs | http://localhost:8000/docs | Swagger UI |
| Flower | http://localhost:5555 | Celery monitoring |
| PostgreSQL | localhost:5432 | TimescaleDB |
| Redis | localhost:6379 | Cache + Broker |

### 3. Desenvolvimento local

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 4. Executar testes

```bash
pytest tests/ -v --cov=backend --cov=agent
```

### 5. Executar o agente

```bash
sudo python -m agent.sniffer \
  --interface eth0 \
  --api-url http://localhost:8000/api/v1/ingest \
  --api-key "agent-key-alpha-001"
```

---

## Estrutura do Projeto

```
novaguarda/
├── agent/                       # Sniffer Edge (máquinas alvo)
│   ├── sniffer.py               # Captura Scapy + parsing DNS
│   └── buffer_sender.py         # Buffer memória + backoff + SQLite fallback
├── backend/
│   ├── main.py                  # FastAPI + Middlewares + CORS
│   ├── core/                    # Config, Security, Cache
│   │   ├── config.py            # Pydantic Settings (.env)
│   │   ├── security.py          # API Key auth (timing-safe)
│   │   └── cache.py             # Redis singleton + Cache-Aside
│   ├── api/v1/                  # Controllers
│   │   ├── ingest_router.py     # POST /api/v1/ingest → 202 Accepted
│   │   └── query_router.py      # GET /logs, /stats, /threats, /health
│   ├── domain/                  # Schemas Pydantic (puro)
│   │   └── schemas.py           # DNSLogItem, LogBatchCreate, EnrichedLog...
│   ├── infrastructure/          # DB, Models, Repositories
│   │   ├── db/
│   │   │   ├── session.py       # Async + Sync engines
│   │   │   └── models.py        # DNSLog, ThreatIntel, AgentRegistry
│   │   └── repositories/
│   │       ├── base.py          # CRUD genérico
│   │       └── log_repo.py      # Bulk insert + aggregations
│   └── workers/                 # Celery Tasks
│       ├── celery_app.py        # Filas: enrichment, sink
│       ├── intel_tasks.py       # Cache-Aside enrichment
│       └── sink_tasks.py        # Chunked bulk persist
├── .github/workflows/ci.yml    # GitHub Actions CI
├── docker-compose.yml           # Stack completa
├── Dockerfile                   # Multi-stage build
├── alembic/                     # Migrações de banco
├── tests/
│   ├── e2e/test_api.py          # TestClient FastAPI
│   └── unit/                    # pytest + mocks
└── pyproject.toml               # Dependencies + tooling
```

---

## API Endpoints

### Ingestão

| Método | Rota | Descrição | Auth |
|---|---|---|---|
| POST | `/api/v1/ingest/` | Recebe lote de logs DNS | X-API-KEY |

### Consulta

| Método | Rota | Descrição | Auth |
|---|---|---|---|
| GET | `/api/v1/query/logs` | Listagem paginada com filtros | X-API-KEY |
| GET | `/api/v1/query/stats` | Estatísticas agregadas | X-API-KEY |
| GET | `/api/v1/query/threats` | Top domínios maliciosos | X-API-KEY |
| GET | `/api/v1/query/health` | Health check (Redis, DB, Celery) | — |

---

## Padrões de Design

### Repository Pattern
Isolamento total entre lógica de negócios e persistência. Permite trocar PostgreSQL por ClickHouse sem alterar workers.

### Cache-Aside
Redis pipeline batch para classificação de domínios. Cache hit → resposta imediata. Miss → consulta DB → popula cache (TTL 24h).

### Exponential Backoff
Agente nunca perde dados. API offline → SQLite local → retry 2s→4s→8s→...→300s → drena ao reconectar.

### Bulk Inserts
1000 logs por transação via `INSERT INTO ... VALUES`. Chunking automático para evitar locks prolongados.

---

## Variáveis de Ambiente

| Variável | Descrição | Default |
|---|---|---|
| `DATABASE_URL` | PostgreSQL async (asyncpg) | `postgresql+asyncpg://...` |
| `DATABASE_URL_SYNC` | PostgreSQL sync (psycopg2) | `postgresql+psycopg2://...` |
| `REDIS_URL` | Redis cache | `redis://localhost:6379/0` |
| `CELERY_BROKER_URL` | Redis broker | `redis://localhost:6379/1` |
| `API_KEYS` | JSON array de chaves | `[]` |
| `RATE_LIMIT` | Limite de requisições | `60/minute` |
| `CACHE_TTL_SECONDS` | TTL do cache Redis | `86400` |
| `BULK_INSERT_SIZE` | Logs por transação | `1000` |

---

## Testes

```
31 passed — Unit (25) + E2E (6)
```

| Suite | Cobertura |
|---|---|
| `test_schemas.py` | Validação Pydantic (11 testes) |
| `test_repository.py` | Repository Pattern com mocks (4 testes) |
| `test_buffer_sender.py` | Buffer, backoff, SQLite fallback (9 testes) |
| `test_api.py` | API E2E com dependency_overrides (6 testes) |

---

## Licença

MIT
