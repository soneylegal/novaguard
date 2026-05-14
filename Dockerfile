# ─── NovaGuard — Multi-Stage Dockerfile ───
# Stage 1: Dependencies
# Stage 2: Runtime (slim)

FROM python:3.11-slim AS base

# Variáveis de ambiente
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Dependências do sistema (psycopg2, asyncpg)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# ── Stage: Dependencies ─────────────────────────────────────────
FROM base AS deps

COPY pyproject.toml ./
# Copia o mínimo para satisfazer setuptools.find_packages
COPY backend/__init__.py ./backend/__init__.py
COPY agent/__init__.py ./agent/__init__.py
RUN pip install --no-cache-dir ".[dev]"

# ── Stage: Runtime ───────────────────────────────────────────────
FROM base AS runtime

COPY --from=deps /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=deps /usr/local/bin /usr/local/bin

# Copia o código da aplicação
COPY backend/ ./backend/
COPY agent/ ./agent/
COPY alembic/ ./alembic/
COPY scripts/ ./scripts/
COPY alembic.ini ./
COPY pyproject.toml ./

# Expõe a porta da API
EXPOSE 8000

# Entrypoint padrão: API
CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
