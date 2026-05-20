"""
NovaGuard — Task de Alertas em Tempo Real.

Dispara notificações HTTP Webhook quando ameaças críticas de rede são identificadas.
Oferece suporte a formatação premium para Discord Webhooks e formato JSON genérico.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from backend.core.config import get_settings
from backend.workers.celery_app import celery_app

logger = logging.getLogger(__name__)
settings = get_settings()

SEVERITY_MAPPING = {
    "c2_server": "CRITICAL",
    "malware": "HIGH",
    "phishing": "MEDIUM",
}

EMOJI_MAPPING = {
    "c2_server": "🚨",
    "malware": "⚠️",
    "phishing": "🔍",
}

COLOR_MAPPING = {
    "c2_server": 15158332,  # Red (0xE74C3C)
    "malware": 15105570,  # Orange (0xE67E22)
    "phishing": 15844367,  # Yellow (0xF1C40F)
}

PORTUGUESE_SEVERITY = {
    "CRITICAL": "CRÍTICO",
    "HIGH": "ALTO",
    "MEDIUM": "MÉDIO",
    "INFO": "INFORMAÇÃO",
}


@celery_app.task(
    name="workers.alert_tasks.send_alert_task",
    bind=True,
    max_retries=3,
    default_retry_delay=5,
    acks_late=True,
    queue="alerts",
)
def send_alert_task(
    self,
    source_ip: str,
    domain: str,
    threat_type: str,
    timestamp: str,
) -> dict[str, Any]:
    """
    Formata e envia uma notificação de alerta sobre uma ameaça detectada.
    """
    severity = SEVERITY_MAPPING.get(threat_type.lower(), "INFO")
    emoji = EMOJI_MAPPING.get(threat_type.lower(), "ℹ️")
    severity_pt = PORTUGUESE_SEVERITY.get(severity, "INFORMAÇÃO")

    # Formatar mensagem amigável em português
    if threat_type.lower() == "c2_server":
        message = (
            f"🚨 [CRÍTICO] A máquina {source_ip} tentou se comunicar "
            f"com o Servidor C2 {domain}!"
        )
    elif threat_type.lower() == "malware":
        message = (
            f"⚠️ [ALTO] A máquina {source_ip} tentou acessar um domínio "
            f"de distribuição de Malware: {domain}!"
        )
    elif threat_type.lower() == "phishing":
        message = (
            f"🔍 [MÉDIO] A máquina {source_ip} tentou acessar um domínio "
            f"suspeito de Phishing: {domain}!"
        )
    else:
        message = (
            f"{emoji} [INFO] A máquina {source_ip} tentou acessar o domínio "
            f"malicioso/suspeito: {domain}!"
        )

    webhook_url = settings.webhook_url

    alert_data = {
        "event": "CRITICAL_THREAT_DETECTED" if severity == "CRITICAL" else "THREAT_DETECTED",
        "timestamp": timestamp,
        "details": {
            "source_ip": source_ip,
            "domain": domain,
            "threat_type": threat_type.upper(),
            "severity": severity,
        },
        "message": message,
    }

    if not webhook_url:
        logger.warning(
            "WEBHOOK_URL não configurado. Alerta local registrado: "
            "[%s] IP: %s | Domínio: %s | Tipo: %s",
            severity,
            source_ip,
            domain,
            threat_type,
        )
        return {"status": "skipped", "reason": "no_webhook_url", "alert": alert_data}

    try:
        # Detectar se é webhook do Discord para formatação de embed premium
        if "discord.com/api/webhooks" in webhook_url:
            color = COLOR_MAPPING.get(
                threat_type.lower(), 9807270
            )  # Default greyish-blue (0x95A5A6)
            payload = {
                "username": "NovaGuard NDR & IPS",
                "avatar_url": "https://raw.githubusercontent.com/soneylegal/novaguard/main/assets/logo.png",
                "embeds": [
                    {
                        "title": f"{emoji} NovaGuard — Ameaça Detectada!",
                        "description": (
                            "Uma conexão para um domínio malicioso "
                            "foi interceptada na rede interna."
                        ),
                        "color": color,
                        "fields": [
                            {"name": "IP de Origem", "value": f"`{source_ip}`", "inline": True},
                            {"name": "Domínio Acessado", "value": f"`{domain}`", "inline": True},
                            {
                                "name": "Tipo de Ameaça",
                                "value": f"`{threat_type.upper()}`",
                                "inline": True,
                            },
                            {"name": "Severidade", "value": f"**{severity_pt}**", "inline": True},
                            {"name": "Timestamp", "value": timestamp, "inline": True},
                        ],
                        "footer": {"text": "NovaGuard Real-Time Protection Active"},
                    }
                ],
            }
        else:
            # Payload padrão genérico conforme ROADMAP
            payload = alert_data

        logger.info(
            "Enviando POST para webhook (%s) para IP %s, domínio %s",
            webhook_url[:30],
            source_ip,
            domain,
        )

        # Enviar via HTTP POST com httpx (timeout 5s para evitar travar o worker)
        response = httpx.post(webhook_url, json=payload, timeout=5.0)
        response.raise_for_status()

        logger.info("Alerta enviado com sucesso para %s, status: %d", domain, response.status_code)
        return {"status": "sent", "status_code": response.status_code, "alert": alert_data}

    except httpx.HTTPStatusError as exc:
        logger.error(
            "Falha ao enviar alerta para webhook (%d %s) para o domínio %s. Retentando...",
            exc.response.status_code,
            exc.response.text,
            domain,
            exc_info=True,
        )
        raise self.retry(exc=exc)
    except Exception as exc:
        logger.error(
            "Erro de conexão ou timeout ao enviar alerta para o "
            "webhook para o domínio %s. Retentando...",
            domain,
            exc_info=True,
        )
        raise self.retry(exc=exc)
