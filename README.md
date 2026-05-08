# 🛡️ NovaGuard — Plataforma de Inteligência e Ameaças DNS

Plataforma distribuída de ingestão e análise de tráfego DNS com pipeline de dados enterprise-grade — alta resiliência, enriquecimento assíncrono e cache em memória.

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

## Início Rápido

### 1. Configurar ambiente
```bash
cp .env.example .env
```

### 2. Subir a stack completa
```bash
docker compose up -d --build
```

### 3. Desenvolvimento local
```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Estrutura do Projeto

```
novaguarda/
├── agent/                       # Sniffer Edge (máquinas alvo)
├── backend/
│   ├── main.py                  # FastAPI + Middlewares + CORS
│   ├── core/                    # Config, Security, Cache
│   ├── api/v1/                  # Controllers (ingest, query)
│   ├── domain/                  # Schemas Pydantic (puro)
│   ├── infrastructure/          # DB, Models, Repositories
│   └── workers/                 # Celery Tasks (enrichment, sink)
├── alembic/                     # Migrações de banco
├── tests/                       # Unit + E2E
├── docker-compose.yml           # Stack completa
├── Dockerfile                   # Multi-stage build
└── pyproject.toml               # Dependencies + tooling
```

## Licença

MIT
