"""Mock CMDB connector — project.md §2.1 / Phase 2 §6.1.

Simulates pulling asset metadata from a ServiceNow-style CMDB.
In a real deployment this would call a REST / GraphQL API.
"""

from __future__ import annotations

from pathlib import Path

import yaml

# Simulated "CMDB" — reads from the same seed file for now but could be
# replaced with a live connector without changing the interface.


def fetch_cmdb_asset(asset_id: str) -> dict | None:
    """Return CMDB asset record or ``None`` if not found."""
    assets_path = Path(__file__).parent.parent.parent.parent / "data" / "assets.yaml"
    with open(assets_path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    for a in raw["assets"]:
        if a["id"] == asset_id:
            return {
                "cmdb_id": a["id"],
                "hostname": a["name"],
                "asset_class": a["type"],
                "environment": "production" if "prod" in a["id"] else "non-prod",
                "business_service": a.get("business_service", "Unknown"),
                "tags": {
                    "criticality": a["criticality"],
                    "exposure": a["exposure"],
                    "compliance": a.get("compliance", []),
                },
            }
    return None


def list_cmdb_assets() -> list[dict]:
    """List all CMDB assets."""
    assets_path = Path(__file__).parent.parent.parent.parent / "data" / "assets.yaml"
    with open(assets_path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    return [
        {
            "cmdb_id": a["id"],
            "hostname": a["name"],
            "asset_class": a["type"],
        }
        for a in raw["assets"]
    ]
