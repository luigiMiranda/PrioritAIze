"""Full evaluation pipeline orchestrator — project.md §2.2–2.4.

Phase 2 adds business-impact modelling, remediation generation, and enhanced
scoring with financial input.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from app.services.nvd import fetch_cve
from app.services.llm import analyze_risk
from app.services.impact import calculate_business_impact, normalize_financial_impact
from app.services.scorer import calculate_score
from app.db import insert_evaluation


class AssetNotFoundError(Exception):
    """Raised when the requested asset ID is not in the seed catalog."""


def load_assets() -> dict[str, dict]:
    assets_path = Path(__file__).parent.parent.parent / "data" / "assets.yaml"
    with open(assets_path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    return {a["id"]: a for a in raw["assets"]}


async def run_evaluation(cve_id: str, asset_id: str) -> dict:
    """Execute the full evaluation pipeline.

    1. Load asset context.
    2. Fetch CVE data from NVD.
    3. LLM risk analysis (threat level + narrative + remediation).
    4. Business Impact Modeler (financial costs).
    5. Score calculation (enhanced Phase 2 formula).
    6. Persist to database.

    Returns the complete evaluation dict including the generated id.
    """
    all_assets = load_assets()

    if asset_id not in all_assets:
        raise AssetNotFoundError(f"Asset '{asset_id}' not found in seed catalog.")

    asset = all_assets[asset_id]

    # Step 1: NVD enrichment
    cve_data = await fetch_cve(cve_id)

    # Step 2: LLM risk reasoning (now includes remediation)
    llm_result = await analyze_risk(
        cve_data["description"], asset, cve_data["cvss_score"]
    )

    # Step 3: Business Impact Modeler
    impact = calculate_business_impact(asset, llm_result["threat_level"])
    financial_score = normalize_financial_impact(impact["total_financial_impact"])

    # Step 4: Score calculation (Phase 2 enhanced formula)
    final_score = calculate_score(
        llm_result["threat_level"],
        asset["exposure"],
        asset["criticality"],
        financial_impact_score=financial_score,
    )

    # Build a JSON-serializable breakdown explaining every figure in the impact
    # object, plus the score inputs, so the evaluation page can render the exact
    # computation behind each monetary value and each score component.
    impact_breakdown = {
        "downtime": {
            "cost": impact["downtime_cost"],
            "hours": impact["downtime_hours"],
            "hourly_revenue": impact["hourly_revenue"],
            "formula": impact["downtime_formula"],
        },
        "regulatory": {
            "total": impact["regulatory_fines"],
            "per_tag": impact["regulatory_breakdown"],
        },
        "reputation": {
            "cost": impact["reputational_cost"],
            **impact["reputation_detail"],
        },
        "total": {
            "value": impact["total_financial_impact"],
            "formula": impact["total_formula"],
        },
        "financial_score_normalization": {
            "raw_total": impact["total_financial_impact"],
            "formula": "log10(total + 1) × 1.5, capped at 10",
            "score": financial_score,
        },
    }

    # Step 5: Persist
    eval_id = insert_evaluation(
        {
            "cve_id": cve_id.upper(),
            "cve_description": cve_data["description"],
            "cvss_score": cve_data["cvss_score"],
            "asset_id": asset_id,
            "asset_name": asset["name"],
            "asset_type": asset["type"],
            "asset_exposure": asset["exposure"],
            "asset_criticality": asset["criticality"],
            "llm_threat_level": llm_result["threat_level"],
            "llm_narrative": llm_result["narrative"],
            "final_score": final_score,
            "downtime_cost": impact["downtime_cost"],
            "regulatory_fines": impact["regulatory_fines"],
            "reputational_cost": impact["reputational_cost"],
            "total_financial_impact": impact["total_financial_impact"],
            "remediation": llm_result.get("remediation", ""),
            "llm_justification": llm_result.get("justification", ""),
            "impact_breakdown": json.dumps(impact_breakdown, ensure_ascii=False),
        }
    )

    return {
        "id": eval_id,
        "cve_id": cve_id.upper(),
        "cve_description": cve_data["description"],
        "cvss_score": cve_data["cvss_score"],
        "asset": asset,
        "llm_threat_level": llm_result["threat_level"],
        "llm_justification": llm_result.get("justification", ""),
        "llm_narrative": llm_result["narrative"],
        "remediation": llm_result.get("remediation", ""),
        "raw_response": llm_result.get("raw_response", ""),
        "final_score": final_score,
        "impact": impact,
        "impact_breakdown": impact_breakdown,
        "financial_score": financial_score,
    }


async def run_custom_evaluation(cve_id: str, custom_asset: dict) -> dict:
    """Execute the full evaluation pipeline with a user-defined custom asset.

    Unlike ``run_evaluation``, this does not look up the asset from YAML.
    The caller provides all asset fields directly (name, type, exposure,
    criticality, compliance tags) along with optional financial overrides
    (hourly_revenue, annual_turnover, customer_count, customer_lifetime_value).

    Penalties, churn percentages, and downtime hours remain sourced from
    ``data/cost_model.yaml`` and are **not** user-configurable.
    """
    # Step 1: NVD enrichment
    cve_data = await fetch_cve(cve_id)

    # Step 2: LLM risk reasoning
    llm_result = await analyze_risk(
        cve_data["description"], custom_asset, cve_data["cvss_score"]
    )

    # Step 3: Business Impact Modeler (reads financial overrides from asset)
    impact = calculate_business_impact(custom_asset, llm_result["threat_level"])
    financial_score = normalize_financial_impact(impact["total_financial_impact"])

    # Step 4: Score calculation
    final_score = calculate_score(
        llm_result["threat_level"],
        custom_asset["exposure"],
        custom_asset["criticality"],
        financial_impact_score=financial_score,
    )

    # Step 5: Build impact breakdown for UI
    impact_breakdown = {
        "downtime": {
            "cost": impact["downtime_cost"],
            "hours": impact["downtime_hours"],
            "hourly_revenue": impact["hourly_revenue"],
            "formula": impact["downtime_formula"],
        },
        "regulatory": {
            "total": impact["regulatory_fines"],
            "per_tag": impact["regulatory_breakdown"],
        },
        "reputation": {
            "cost": impact["reputational_cost"],
            **impact["reputation_detail"],
        },
        "total": {
            "value": impact["total_financial_impact"],
            "formula": impact["total_formula"],
        },
        "financial_score_normalization": {
            "raw_total": impact["total_financial_impact"],
            "formula": "log10(total + 1) × 1.5, capped at 10",
            "score": financial_score,
        },
    }

    # Step 6: Persist
    eval_id = insert_evaluation(
        {
            "cve_id": cve_id.upper(),
            "cve_description": cve_data["description"],
            "cvss_score": cve_data["cvss_score"],
            "asset_id": custom_asset.get("id", "__custom__"),
            "asset_name": custom_asset["name"],
            "asset_type": custom_asset["type"],
            "asset_exposure": custom_asset["exposure"],
            "asset_criticality": custom_asset["criticality"],
            "llm_threat_level": llm_result["threat_level"],
            "llm_narrative": llm_result["narrative"],
            "final_score": final_score,
            "downtime_cost": impact["downtime_cost"],
            "regulatory_fines": impact["regulatory_fines"],
            "reputational_cost": impact["reputational_cost"],
            "total_financial_impact": impact["total_financial_impact"],
            "remediation": llm_result.get("remediation", ""),
            "llm_justification": llm_result.get("justification", ""),
            "impact_breakdown": json.dumps(impact_breakdown, ensure_ascii=False),
        }
    )

    return {
        "id": eval_id,
        "cve_id": cve_id.upper(),
        "cve_description": cve_data["description"],
        "cvss_score": cve_data["cvss_score"],
        "asset": custom_asset,
        "llm_threat_level": llm_result["threat_level"],
        "llm_justification": llm_result.get("justification", ""),
        "llm_narrative": llm_result["narrative"],
        "remediation": llm_result.get("remediation", ""),
        "raw_response": llm_result.get("raw_response", ""),
        "final_score": final_score,
        "impact": impact,
        "impact_breakdown": impact_breakdown,
        "financial_score": financial_score,
    }
