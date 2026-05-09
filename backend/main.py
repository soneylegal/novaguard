"""
NovaGuard — FastAPI Application (Entrypoint).

Configura:
  - Middlewares (CORS, Rate Limiting, Request ID)
  - Lifecycle hooks (startup/shutdown)
  - OpenAPI metadata

NOTA: Routers e dependências de cache serão registrados
nos commits subsequentes (C5, C6, C8).
"""

from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from backend.core.config import get_settings

# ── Logging ──────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-8s │ %(name)s │ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("novaguard")

# ── Rate Limiter ─────────────────────────────────────────────────
settings = get_settings()
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.rate_limit])


# ── Lifecycle ────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup: Inicializa serviços.
    Shutdown: Encerra de forma limpa.
    """
    logger.info("╔══════════════════════════════════════════════════╗")
    logger.info("║          NovaGuard Platform Starting...          ║")
    logger.info("╚══════════════════════════════════════════════════╝")

    logger.info("✓ NovaGuard API ready (env=%s)", settings.app_env)

    yield

    logger.info("NovaGuard Platform shut down cleanly.")


# ── Application ──────────────────────────────────────────────────

app = FastAPI(
    title="NovaGuard — DNS Threat Intelligence Platform",
    description=(
        "Plataforma distribuída de ingestão e análise de tráfego DNS. "
        "Agentes de borda coletam pacotes, enviam lotes para a API, "
        "que enriquece os dados e persiste em banco time-series."
    ),
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── Middlewares ───────────────────────────────────────────────────

# Rate Limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Request ID Middleware
@app.middleware("http")
async def add_request_id(request: Request, call_next) -> Response:
    """Injeta um Request-ID único em cada resposta para rastreabilidade."""
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    return response


# ── Root ─────────────────────────────────────────────────────────

@app.get("/", tags=["Root"])
async def root():
    """Endpoint raiz — retorna info básica da plataforma."""
    return {
        "platform": "NovaGuard",
        "version": "1.0.0",
        "description": "DNS Threat Intelligence Platform",
        "docs": "/docs",
    }
