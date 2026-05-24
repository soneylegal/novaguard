"""
NovaGuard — Módulo Matemático de Entropia & Filtros de Densidade.

Implementa a Fórmula de Entropia de Shannon de forma nativa e otimizada
para cálculo de aleatoriedade linguística em domínios DNS.

Inclui Regra de Decisão Multivariada (Filtros de Densidade) para reduzir
falsos positivos em domínios legítimos de alta entropia (ex: githubusercontent).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from typing import NamedTuple

# Lista de sufixos de TLDs comuns para ignorar na segmentação
COMMON_SUFFIXES = {
    "com",
    "net",
    "org",
    "gov",
    "edu",
    "mil",
    "int",
    "arpa",
    "co",
    "coop",
    "info",
    "biz",
    "mobi",
    "name",
    "pro",
    "travel",
    "br",
    "us",
    "uk",
    "ca",
    "de",
    "jp",
    "fr",
    "au",
    "ru",
    "ch",
    "it",
    "nl",
    "se",
    "no",
    "es",
    "mx",
    "in",
    "cn",
    "io",
    "cc",
    "me",
    "tv",
    "app",
    "dev",
    "xyz",
    "online",
    "site",
    "tech",
}

VOWELS = set("aeiou")

# Lista de domínios/CDNs/infraestruturas confiáveis que geram falsos positivos de DGA
DGA_EXCLUDED_DOMAINS = {
    "cloudfront.net",
    "amazonaws.com",
    "googleapis.com",
    "googleusercontent.com",
    "githubusercontent.com",
    "github.io",
    "azureedge.net",
    "azure.com",
    "akamaized.net",
    "akamaihd.net",
    "edgekey.net",
    "fastly.net",
    "fbcdn.net",
    "discordapp.com",
    "discord.gg",
    "discord.com",
    "discord.media",
    "discordapp.net",
    "trafficmanager.net",
    "googleadservices.com",
    "doubleclick.net",
    "googlesyndication.com",
    "adnxs.com",
    "adnxs.net",
    "rubiconproject.com",
    "pubmatic.com",
    "openx.net",
    "criteo.com",
    "criteo.net",
    "casalemedia.com",
    "outbrain.com",
    "taboola.com",
    "adroll.com",
    "smartadserver.com",
}

# Regex para clusters de consoantes consecutivas (sem vogais e sem dígitos)
_CONSONANT_CLUSTER_RE = re.compile(r"[^aeiou0-9\-]+")


class DensityFeatures(NamedTuple):
    """Características de densidade estrutural de um SLD."""

    vowel_ratio: float
    digit_ratio: float
    max_consonant_cluster: int


class DGAVerdict(NamedTuple):
    """Resultado da análise multivariada de DGA."""

    is_suspicious: bool
    entropy: float
    sld: str
    density: DensityFeatures


def extract_sld(domain: str) -> str:
    """
    Extrai o segmento mais longo não-TLD do domínio (Second-Level Domain).

    Exemplos:
        'avatars.githubusercontent.com' → 'githubusercontent'
        'xjz897fka31s.co.uk'           → 'xjz897fka31s'
        'google.com'                    → 'google'
    """
    if not domain:
        return ""

    parts = domain.strip().lower().split(".")
    segments = [p for p in parts if p and p not in COMMON_SUFFIXES]

    if not segments:
        return parts[0] if parts else ""

    return max(segments, key=len)


def calculate_shannon_entropy(domain: str) -> float:
    """
    Calcula a Entropia de Shannon do segmento mais longo não-TLD do domínio.
    Fórmula: H(X) = -sum(P(xi) * log2(P(xi)))
    """
    if not domain:
        return 0.0

    # Normalizar e quebrar o domínio
    domain_lower = domain.strip().lower()
    parts = domain_lower.split(".")

    # Filtrar sufixos comuns
    segments = [p for p in parts if p and p not in COMMON_SUFFIXES]

    # Se todos os segmentos forem sufixos comuns, usar o primeiro segmento disponível
    if not segments:
        sld = parts[0] if parts else ""
    else:
        sld = max(segments, key=len)

    if not sld:
        return 0.0

    total_len = len(sld)
    counts = Counter(sld)

    entropy = -sum((count / total_len) * math.log2(count / total_len) for count in counts.values())
    return entropy


def calculate_density_features(sld: str) -> DensityFeatures:
    """
    Calcula as características de densidade estrutural de um SLD.

    Retorna:
        - vowel_ratio: proporção de vogais (a,e,i,o,u) no segmento
        - digit_ratio: proporção de dígitos (0-9) no segmento
        - max_consonant_cluster: comprimento do maior cluster de consoantes
          consecutivas (sem vogais e sem dígitos)
    """
    if not sld:
        return DensityFeatures(vowel_ratio=0.0, digit_ratio=0.0, max_consonant_cluster=0)

    total = len(sld)
    vowel_count = sum(1 for c in sld if c in VOWELS)
    digit_count = sum(1 for c in sld if c.isdigit())

    clusters = _CONSONANT_CLUSTER_RE.findall(sld)
    max_cluster = max((len(c) for c in clusters), default=0)

    return DensityFeatures(
        vowel_ratio=vowel_count / total,
        digit_ratio=digit_count / total,
        max_consonant_cluster=max_cluster,
    )


def is_dga_suspicious(
    domain: str,
    entropy_threshold: float = 3.2,
    min_length: int = 8,
) -> DGAVerdict:
    """
    Regra de Decisão Multivariada para detecção de DGA.

    Um domínio é marcado como suspeito SE E SOMENTE SE:
      1. A Entropia de Shannon >= limiar (alta aleatoriedade)
      2. E pelo menos UM filtro de densidade confirmar anomalia estrutural:
         - Vowel Ratio < 20%  (geração não-linguística)
         - Digit Ratio > 20%  (seed numérica misturada)
         - Max Consonant Cluster > 4  (sequência impronunciável)

    Isso elimina falsos positivos como 'githubusercontent' (H=3.45, mas
    35% de vogais, 0% de dígitos, cluster max 2) enquanto captura DGA
    reais como 'xjz897fka31s' (H=3.58, 8% vogais, 42% dígitos).
    """
    sld = extract_sld(domain)
    entropy = calculate_shannon_entropy(domain)
    density = calculate_density_features(sld)

    # Ignora verificação de DGA se for um domínio de infraestrutura/CDN confiável
    domain_lower = domain.strip().lower()
    for excluded in DGA_EXCLUDED_DOMAINS:
        if domain_lower == excluded or domain_lower.endswith("." + excluded):
            return DGAVerdict(
                is_suspicious=False,
                entropy=entropy,
                sld=sld,
                density=density,
            )

    # Gate 1: Entropia + comprimento mínimo
    if len(sld) < min_length or entropy < entropy_threshold:
        return DGAVerdict(
            is_suspicious=False,
            entropy=entropy,
            sld=sld,
            density=density,
        )

    # Gate 2: Pelo menos um filtro de densidade deve confirmar anomalia
    density_anomaly = (
        density.vowel_ratio < 0.20
        or density.digit_ratio > 0.20
        or density.max_consonant_cluster > 4
    )

    return DGAVerdict(
        is_suspicious=density_anomaly,
        entropy=entropy,
        sld=sld,
        density=density,
    )


def extract_registered_domain(domain: str) -> str:
    """
    Extrai o domínio base registrado (SLD + TLD) de um domínio completo.
    Exemplos:
      - 'platform-cdn.sharethis.com' -> 'sharethis.com'
      - 'encrypted-tbn0.gstatic.com' -> 'gstatic.com'
      - 'sub.domain.github.io' -> 'github.io'
      - 'xjz897fka31s.co.uk' -> 'xjz897fka31s.co.uk'
    """
    domain = domain.lower().strip()
    # Remove qualquer ponto no início ou final
    domain = domain.strip(".")
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain

    tld_parts: list[str] = []
    i = len(parts) - 1
    # Percorre de trás para frente identificando partes que pertencem ao TLD (ex: co, uk, com, br)
    while i >= 0 and parts[i] in COMMON_SUFFIXES:
        tld_parts.insert(0, parts[i])
        i -= 1

    if i >= 0:
        # O domínio registrado é o nome logo antes do TLD + todas as partes do TLD
        registered_parts = [parts[i]] + tld_parts
        return ".".join(registered_parts)

    return domain
