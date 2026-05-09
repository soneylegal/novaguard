"""
NovaGuard — Camada de Segurança.

Validação de API Keys para agentes autônomos.
Utiliza `X-API-KEY` no header em vez de JWT, pois agentes
não precisam de sessão — apenas de autenticação estática.
"""

from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from backend.core.config import Settings, get_settings

# ── Header scheme ────────────────────────────────────────────────
api_key_header = APIKeyHeader(name="X-API-KEY", auto_error=False)


async def validate_api_key(
    api_key: Annotated[str | None, Security(api_key_header)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> str:
    """
    Valida o API Key recebido via header X-API-KEY.

    Utiliza `secrets.compare_digest` para comparação em tempo constante,
    prevenindo ataques de timing side-channel.

    Raises:
        HTTPException 401: Se o API Key não for fornecido.
        HTTPException 403: Se o API Key for inválido.
    """
    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key não fornecida. Inclua o header X-API-KEY.",
        )

    # Comparação em tempo constante contra todas as chaves configuradas
    is_valid = any(secrets.compare_digest(api_key, valid_key) for valid_key in settings.api_keys)

    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API Key inválida ou revogada.",
        )

    return api_key
