"""
NovaGuard — Testes Unitários do Módulo de Entropia & Filtros de Densidade.
"""

from __future__ import annotations

import math

from backend.core.entropy import (
    calculate_density_features,
    calculate_shannon_entropy,
    extract_sld,
    is_dga_suspicious,
)

# ── Testes: extract_sld ──────────────────────────────────────────


def test_extract_sld_simple():
    assert extract_sld("google.com") == "google"


def test_extract_sld_subdomain():
    assert extract_sld("avatars.githubusercontent.com") == "githubusercontent"


def test_extract_sld_cctld():
    assert extract_sld("xjz897fka31s.co.uk") == "xjz897fka31s"


def test_extract_sld_empty():
    assert extract_sld("") == ""


def test_extract_sld_all_suffixes():
    assert extract_sld("com.br") == "com"


# ── Testes: calculate_shannon_entropy (mantidos intactos) ────────


def test_calculate_shannon_entropy_empty():
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy("   ") == 0.0


def test_calculate_shannon_entropy_known_values():
    # Single character: H should be 0.0
    assert calculate_shannon_entropy("a") == 0.0

    # 2 unique chars: -2 * (0.5 * log2(0.5)) = 1.0
    assert calculate_shannon_entropy("ab") == 1.0


def test_calculate_shannon_entropy_tld_exclusion():
    # "google.com" should evaluate entropy on "google"
    # "google" length = 6. Char counts: g: 2, o: 2, l: 1, e: 1.
    # Probabilities: 1/3, 1/3, 1/6, 1/6.
    # Entropy: -2*(1/3 * log2(1/3)) - 2*(1/6 * log2(1/6))
    expected = -2 * (1 / 3 * math.log2(1 / 3)) - 2 * (1 / 6 * math.log2(1 / 6))
    assert math.isclose(calculate_shannon_entropy("google.com"), expected)

    # "sub.xjz897fka31s.co.uk" should evaluate on "xjz897fka31s"
    # (longest segment after excluding co and uk)
    # "xjz897fka31s" has 12 unique chars, so entropy should be log2(12) = 3.5849625
    assert math.isclose(calculate_shannon_entropy("sub.xjz897fka31s.co.uk"), math.log2(12))


def test_calculate_shannon_entropy_fallback():
    # If all parts are common suffixes, e.g., "com.br", should fall back to first part: "com"
    # "com" has 3 unique chars, entropy = log2(3) = 1.5849625
    assert math.isclose(calculate_shannon_entropy("com.br"), math.log2(3))


# ── Testes: calculate_density_features ───────────────────────────


def test_density_features_empty():
    d = calculate_density_features("")
    assert d.vowel_ratio == 0.0
    assert d.digit_ratio == 0.0
    assert d.max_consonant_cluster == 0


def test_density_features_legitimate_domain():
    """githubusercontent tem perfil linguístico: muitos vogais, zero dígitos."""
    d = calculate_density_features("githubusercontent")
    # i, u, u, e, o, e = 6 vowels / 17 chars = ~35%
    assert d.vowel_ratio > 0.30
    assert d.digit_ratio == 0.0
    assert d.max_consonant_cluster <= 3


def test_density_features_dga_with_digits():
    """DGA com dígitos: poucos vogais, muitos dígitos."""
    d = calculate_density_features("xjz897fka31s")
    assert d.vowel_ratio < 0.15
    assert d.digit_ratio > 0.30


def test_density_features_dga_consonant_cluster():
    """DGA com cluster consonantal massivo."""
    d = calculate_density_features("qweasdzxcrty")
    assert d.max_consonant_cluster > 4


# ── Testes: is_dga_suspicious (Regra Multivariada) ───────────────


def test_dga_verdict_safe_low_entropy():
    """Domínios de baixa entropia nunca são flagrados."""
    verdict = is_dga_suspicious("google.com")
    assert verdict.is_suspicious is False


def test_dga_verdict_false_positive_githubusercontent():
    """githubusercontent tem alta entropia mas perfil linguístico normal — NÃO deve ser flagrado."""
    verdict = is_dga_suspicious("avatars.githubusercontent.com")
    assert verdict.is_suspicious is False
    assert verdict.entropy > 3.2  # Confirma que entropia é alta
    assert verdict.density.vowel_ratio > 0.20  # Mas perfil linguístico é normal


def test_dga_verdict_false_positive_stackoverflow():
    """stackoverflow tem alta entropia mas é legítimo."""
    verdict = is_dga_suspicious("stackoverflow.com")
    assert verdict.is_suspicious is False


def test_dga_verdict_true_positive_digits():
    """DGA com dígitos misturados — DEVE ser flagrado."""
    verdict = is_dga_suspicious("xjz897fka31s.co.uk")
    assert verdict.is_suspicious is True
    assert verdict.density.digit_ratio > 0.20


def test_dga_verdict_true_positive_consonants():
    """DGA com cluster consonantal massivo — DEVE ser flagrado."""
    verdict = is_dga_suspicious("qweasdzxcrty.org")
    assert verdict.is_suspicious is True
    assert verdict.density.max_consonant_cluster > 4


def test_dga_verdict_short_domain_skipped():
    """Domínios curtos demais são ignorados mesmo com alta entropia."""
    verdict = is_dga_suspicious("abc.com", min_length=8)
    assert verdict.is_suspicious is False


def test_dga_verdict_excluded_infrastructure():
    """Domínios de infraestrutura ou CDNs conhecidas nunca devem ser DGA."""
    # cloudfront tem alta entropia e anomalia estrutural (poucos vogais,
    # muitos dígitos), mas está excluído
    verdict = is_dga_suspicious("d3e54v103j8qbb.cloudfront.net")
    assert verdict.is_suspicious is False

    # discordapp e outros domínios da lista também
    verdict2 = is_dga_suspicious("d3e54v103j8qbb.discordapp.net")
    assert verdict2.is_suspicious is False
