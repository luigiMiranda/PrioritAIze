"""Business Impact Modeler — project.md §2.3.

Quantifies operational (downtime), regulatory (GDPR/HIPAA/PCI-DSS/SOX/NIS2),
and reputational costs for a vulnerability on a given asset.
"""

from __future__ import annotations

import math
from pathlib import Path

import yaml


def load_cost_model() -> dict:
    """Load financial parameters from YAML."""
    path = Path(__file__).parent.parent.parent / "data" / "cost_model.yaml"
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def calculate_business_impact(asset: dict, threat_level: float) -> dict:
    """Compute downtime, regulatory, and reputational costs.

    Args:
        asset: Asset dict from assets.yaml (must include ``type`` and optionally
               ``compliance`` tags).
        threat_level: 1–10 value from the LLM risk analysis.

    Returns:
        Dict with keys ``downtime_cost``, ``downtime_hours``, ``hourly_revenue``,
        ``regulatory_fines``, ``reputational_cost``, ``total_financial_impact``.
    """
    model = load_cost_model()
    asset_type = asset["type"]
    compliance_tags: list[str] = asset.get("compliance", [])

    type_cfg = model["asset_types"].get(asset_type, model["asset_types"]["web_server"])

    # Allow asset dict to carry its own financial parameters (custom evaluation).
    # When present, they override the per-type defaults from cost_model.yaml.
    # Penalties, churn, and downtime hours always come from cost_model.yaml.
    if "hourly_revenue" in asset:
        hourly_revenue = float(asset["hourly_revenue"])
    else:
        hourly_revenue = type_cfg.get("hourly_revenue", 1000.0)

    if "annual_turnover" in asset:
        annual_turnover = float(asset["annual_turnover"])
    else:
        annual_turnover = type_cfg.get("annual_turnover", 0.0)

    if "customer_count" in asset:
        customer_count = int(asset["customer_count"])
    else:
        customer_count = int(type_cfg.get("customer_count", 0))

    if "customer_lifetime_value" in asset:
        clv = float(asset["customer_lifetime_value"])
    else:
        clv = float(type_cfg.get("customer_lifetime_value", 0))

    # 1. Downtime cost ─────────────────────────────────────────────────
    downtime_hours = _estimate_downtime(threat_level, model)
    downtime_cost = hourly_revenue * downtime_hours

    # 2. Regulatory fines ──────────────────────────────────────────────
    regulatory_fines, regulatory_breakdown = _calculate_fines(
        compliance_tags, type_cfg, model, annual_turnover
    )

    # 3. Reputational damage ───────────────────────────────────────────
    reputational_cost, reputation_detail = _calculate_reputation(
        threat_level, type_cfg, model, customer_count, clv
    )

    total = downtime_cost + regulatory_fines + reputational_cost

    return {
        "downtime_cost": round(downtime_cost, 2),
        "downtime_hours": downtime_hours,
        "hourly_revenue": hourly_revenue,
        "downtime_formula": (
            f"{format_money(hourly_revenue)}/hour × {downtime_hours}h outage "
            f"(threat {int(threat_level)} → {downtime_hours}h bracket) "
            f"= {format_money(downtime_cost)}"
        ),
        "regulatory_fines": round(regulatory_fines, 2),
        "regulatory_breakdown": regulatory_breakdown,
        "reputational_cost": round(reputational_cost, 2),
        "reputation_detail": reputation_detail,
        "total_financial_impact": round(total, 2),
        "total_formula": (
            f"downtime {format_money(downtime_cost)} + fines "
            f"{format_money(regulatory_fines)} + reputation "
            f"{format_money(reputational_cost)} = {format_money(total)}"
        ),
    }


def format_money(amount: float) -> str:
    """Format a money value as a human-readable EUR string for formula display."""
    if amount >= 1_000_000:
        return f"€{amount / 1_000_000:,.2f}M"
    if amount >= 1_000:
        return f"€{amount / 1_000:,.0f}K"
    return f"€{amount:,.0f}"


def normalize_financial_impact(total_impact: float) -> float:
    """Log-scale normalisation to 0–10 for use in the risk-score formula.

    ``log10(total + 1) * 1.5`` keeps scores in a meaningful band even when
    impact spans several orders of magnitude (thousands → tens of millions).
    """
    if total_impact <= 0:
        return 0.0
    return min(10.0, round(math.log10(total_impact + 1) * 1.5, 1))


# ── helpers ────────────────────────────────────────────────────────────────


def _estimate_downtime(threat_level: float, model: dict) -> int:
    for entry in model.get("downtime_mapping", []):
        if threat_level <= entry["threat_max"]:
            return int(entry["hours"])
    return 48


def _calculate_fines(
    tags: list[str],
    type_cfg: dict,
    model: dict,
    annual_turnover_override: float | None = None,
) -> tuple[float, list[dict]]:
    """Return (total_fines, per_tag_breakdown).

    Each breakdown entry records the raw model parameters used so the UI can show
    the exact computation, e.g. ``GDPR = max(€20M, 4% × €50M) = €20M``.
    """
    fine_cfg = model.get("regulatory_fines", {})
    annual_turnover: float = (
        annual_turnover_override
        if annual_turnover_override is not None
        else type_cfg.get("annual_turnover", 0.0)
    )
    total = 0.0
    breakdown: list[dict] = []

    for tag in tags:
        cfg = fine_cfg.get(tag, {})
        base = float(cfg.get("base_penalty", 0))
        pct = float(cfg.get("turnover_pct", 0))
        turnover_component = annual_turnover * pct
        computed = max(base, turnover_component)
        total += computed
        breakdown.append(
            {
                "tag": tag,
                "base_penalty": base,
                "turnover_pct": pct,
                "annual_turnover": annual_turnover,
                "turnover_component": round(turnover_component, 2),
                "computed_fine": round(computed, 2),
                "formula": (
                    f"max({format_money(base)}, {pct:.2%} × {format_money(annual_turnover)}) "
                    f"= {format_money(computed)}"
                ),
            }
        )

    return total, breakdown


def _calculate_reputation(
    threat_level: float,
    type_cfg: dict,
    model: dict,
    customer_count_override: int | None = None,
    clv_override: float | None = None,
) -> tuple[float, dict]:
    """Return (reputational_cost, detail).

    ``detail`` records the churn tier and the three factors multiplied together
    so the UI can show ``customers × churn% × CLV = cost``.
    """
    rep = model.get("reputation", {})
    if threat_level >= 8:
        churn_key = "churn_pct_critical"
        tier = "critical (threat ≥ 8)"
    elif threat_level >= 5:
        churn_key = "churn_pct_high"
        tier = "high (threat 5–7)"
    else:
        churn_key = "churn_pct_medium"
        tier = "medium (threat < 5)"
    churn_pct = float(rep.get(churn_key, 0.0))
    customers = (
        customer_count_override
        if customer_count_override is not None
        else int(type_cfg.get("customer_count", 0))
    )
    clv = (
        clv_override
        if clv_override is not None
        else float(type_cfg.get("customer_lifetime_value", 0))
    )
    cost = customers * churn_pct * clv
    return cost, {
        "churn_pct": churn_pct,
        "tier": tier,
        "customer_count": customers,
        "customer_lifetime_value": clv,
        "formula": (
            f"{customers:,} customers × {churn_pct:.0%} churn ({tier}) "
            f"× {format_money(clv)} CLV = {format_money(cost)}"
        ),
    }
