"""Dynamic risk score calculator — project.md §2.4.

Supports two formulas via ``SCORING_FORMULA`` config:

* ``phase1`` — original: ``(threat × 0.5) + (criticality × 0.3) + (exposure × 0.2)``
* ``phase2`` — enhanced: ``(threat × 0.35) + (criticality × 0.20) + (exposure × 0.15) + (financial × 0.30)``
"""

from __future__ import annotations

from app.config import SCORING_FORMULA

# Mapping to normalized 1–10 values
EXPOSURE_MAP: dict[str, float] = {
    "public": 10.0,
    "internal": 5.0,
    "isolated": 2.0,
}

CRITICALITY_MAP: dict[str, float] = {
    "high": 10.0,
    "medium": 6.0,
    "low": 3.0,
}


def calculate_score(
    threat_level: float,
    exposure: str,
    criticality: str,
    financial_impact_score: float = 0.0,
) -> float:
    """Calculate dynamic risk score on a 0–10 scale.

    Phase 1 formula (default when ``financial_impact_score`` is 0 or
    ``SCORING_FORMULA=phase1``):

        (LLM threat × 0.5) + (criticality × 0.3) + (exposure × 0.2)

    Phase 2 formula (``SCORING_FORMULA=phase2``):

        (LLM threat × 0.35) + (criticality × 0.20) + (exposure × 0.15)
        + (financial_impact × 0.30)
    """
    exp_val = EXPOSURE_MAP.get(exposure, 5.0)
    crit_val = CRITICALITY_MAP.get(criticality, 5.0)

    if SCORING_FORMULA == "phase2" and financial_impact_score > 0:
        score = (
            (threat_level * 0.35)
            + (crit_val * 0.20)
            + (exp_val * 0.15)
            + (financial_impact_score * 0.30)
        )
    else:
        score = (threat_level * 0.5) + (crit_val * 0.3) + (exp_val * 0.2)

    return round(score, 1)
