"""
NovaGuard — API de Compartilhamento de Inteligência (STIX/TAXII 2.1).

Endpoints em conformidade com as especificações OASIS TAXII 2.1
e representação de dados via STIX 2.1.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.security import validate_api_key
from backend.infrastructure.db.session import get_async_session
from backend.infrastructure.repositories.log_repo import LogRepository

logger = logging.getLogger(__name__)

router = APIRouter()

# MIME Types padronizados do OASIS
TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
STIX_MEDIA_TYPE = "application/stix+json;version=2.1"


@router.get(
    "/",
    summary="Descoberta do Servidor TAXII 2.1",
    responses={
        200: {"description": "Retorna informações básicas do servidor e API Roots."},
        401: {"description": "API Key não fornecida."},
        403: {"description": "API Key inválida."},
    },
)
async def discovery(
    _api_key: Annotated[str, Depends(validate_api_key)],
) -> JSONResponse:
    """
    Retorna os metadados do servidor TAXII e o caminho para o API Root padrão.
    """
    data = {
        "title": "NovaGuard TAXII 2.1 Server",
        "description": "Feed público de indicadores de ameaça do NovaGuard",
        "contact": "security@novaguard.io",
        "default": "/api/v1/taxii2/root/",
        "api_roots": ["/api/v1/taxii2/root/"],
    }
    return JSONResponse(
        content=data,
        media_type=TAXII_MEDIA_TYPE,
        status_code=status.HTTP_200_OK,
    )


@router.get(
    "/root/",
    summary="Detalhes do API Root",
    responses={
        200: {"description": "Retorna as versões suportadas e limites do API Root."},
        401: {"description": "API Key não fornecida."},
        403: {"description": "API Key inválida."},
    },
)
async def api_root(
    _api_key: Annotated[str, Depends(validate_api_key)],
) -> JSONResponse:
    """
    Retorna metadados sobre o API Root, informando que suporta a versão 2.1.
    """
    data = {
        "title": "NovaGuard API Root",
        "description": "API Root contendo feeds de inteligência de ameaças",
        "versions": ["2.1"],
        "max_content_length": 104857600,
    }
    return JSONResponse(
        content=data,
        media_type=TAXII_MEDIA_TYPE,
        status_code=status.HTTP_200_OK,
    )


@router.get(
    "/root/collections/",
    summary="Lista as Coleções de Inteligência",
    responses={
        200: {"description": "Retorna as coleções disponíveis para leitura."},
        401: {"description": "API Key não fornecida."},
        403: {"description": "API Key inválida."},
    },
)
async def list_collections(
    _api_key: Annotated[str, Depends(validate_api_key)],
) -> JSONResponse:
    """
    Lista as coleções disponíveis. Atualmente disponibilizamos a coleção 'threat-logs'.
    """
    data = {
        "collections": [
            {
                "id": "threat-logs",
                "title": "NovaGuard Threat Intelligence Indicators",
                "description": (
                    "Feed contendo domínios maliciosos e suspeitos identificados na rede"
                ),
                "can_read": True,
                "can_write": False,
                "media_types": [STIX_MEDIA_TYPE],
            }
        ]
    }
    return JSONResponse(
        content=data,
        media_type=TAXII_MEDIA_TYPE,
        status_code=status.HTTP_200_OK,
    )


@router.get(
    "/root/collections/{collection_id}/",
    summary="Obtém Detalhes de uma Coleção Específica",
    responses={
        200: {"description": "Metadados da coleção solicitada."},
        401: {"description": "API Key não fornecida."},
        403: {"description": "API Key inválida."},
        404: {"description": "Coleção não encontrada."},
    },
)
async def get_collection(
    collection_id: str,
    _api_key: Annotated[str, Depends(validate_api_key)],
) -> JSONResponse:
    """
    Retorna detalhes da coleção informada se for a coleção padrão 'threat-logs'.
    """
    if collection_id != "threat-logs":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Coleção não encontrada.",
        )

    data = {
        "id": "threat-logs",
        "title": "NovaGuard Threat Intelligence Indicators",
        "description": "Feed contendo domínios maliciosos e suspeitos identificados na rede",
        "can_read": True,
        "can_write": False,
        "media_types": [STIX_MEDIA_TYPE],
    }
    return JSONResponse(
        content=data,
        media_type=TAXII_MEDIA_TYPE,
        status_code=status.HTTP_200_OK,
    )


@router.get(
    "/root/collections/{collection_id}/objects/",
    summary="Obtém Objetos STIX 2.1 (Ameaças) da Coleção",
    responses={
        200: {"description": "Retorna o STIX Bundle contendo os indicadores de ameaça."},
        401: {"description": "API Key não fornecida."},
        403: {"description": "API Key inválida."},
        404: {"description": "Coleção não encontrada."},
    },
)
async def get_collection_objects(
    collection_id: str,
    session: Annotated[AsyncSession, Depends(get_async_session)],
    _api_key: Annotated[str, Depends(validate_api_key)],
    limit: int = Query(100, ge=1, le=1000, description="Limite máximo de logs analisados"),
    added_after: datetime | None = Query(
        None, description="Filtrar por logs gerados após esta data (ISO 8601)"
    ),
) -> JSONResponse:
    """
    Busca logs de ameaças no banco e gera dinamicamente um STIX 2.1 Bundle contendo:
      - Objetos 'indicator' (domínio malicioso/suspeito)
      - Objetos 'observed-data' (IP do cliente que efetuou a consulta)
      - Objetos 'relationship' (ligando o indicador ao IP do cliente)
    """
    if collection_id != "threat-logs":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Coleção não encontrada.",
        )

    repo = LogRepository(session)
    logs = await repo.get_threat_logs_for_stix(limit=limit, added_after=added_after)

    objects = []
    unique_indicators = {}

    for log in logs:
        # 1. Gerar Indicator (idempotente por domínio)
        domain_namespace = uuid.uuid5(uuid.NAMESPACE_DNS, log.domain)
        indicator_id = f"indicator--{domain_namespace}"

        if indicator_id not in unique_indicators:
            indicator_obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created": log.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "modified": log.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "name": f"NovaGuard Threat: {log.domain}",
                "description": (
                    f"Domínio detectado como {log.threat_level.upper()} "
                    f"via {log.threat_source or 'threat_intel'}."
                ),
                "pattern": f"[domain-name:value = '{log.domain}']",
                "pattern_type": "stix",
                "valid_from": log.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            unique_indicators[indicator_id] = indicator_obj
            objects.append(indicator_obj)

        # 2. Gerar Observed Data (evento de observação único por IP/Log)
        observed_namespace = uuid.uuid5(
            uuid.NAMESPACE_DNS,
            f"{log.source_ip}:{log.domain}:{log.timestamp.isoformat()}",
        )
        observed_id = f"observed-data--{observed_namespace}"
        observed_obj = {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": observed_id,
            "created": log.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "modified": log.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "first_observed": log.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "last_observed": log.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "number_observed": 1,
            "objects": {
                "0": {
                    "type": "ipv4-addr",
                    "value": log.source_ip,
                }
            },
        }
        objects.append(observed_obj)

        # 3. Gerar Relationship linking indicator -> observed-data
        rel_namespace = uuid.uuid5(uuid.NAMESPACE_DNS, f"{indicator_id}:indicates:{observed_id}")
        rel_id = f"relationship--{rel_namespace}"
        relationship_obj = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": rel_id,
            "created": log.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "modified": log.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "relationship_type": "indicates",
            "source_ref": indicator_id,
            "target_ref": observed_id,
        }
        objects.append(relationship_obj)

    bundle_id = f"bundle--{uuid.uuid4()}"
    bundle_data = {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects,
    }

    return JSONResponse(
        content=bundle_data,
        media_type=STIX_MEDIA_TYPE,
        status_code=status.HTTP_200_OK,
    )
