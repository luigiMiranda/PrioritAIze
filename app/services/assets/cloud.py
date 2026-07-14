"""Mock cloud inventory connector — project.md §2.1 / Phase 2 §6.1.

Simulates pulling resource metadata from AWS Resource Groups / Azure Resource
Graph.  Returns the same seed data with cloud-specific fields added.
"""

from __future__ import annotations

from pathlib import Path

import yaml


def fetch_cloud_instance(asset_id: str) -> dict | None:
    """Return a simulated cloud resource record or ``None``."""
    assets_path = Path(__file__).parent.parent.parent.parent / "data" / "assets.yaml"
    with open(assets_path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    for a in raw["assets"]:
        if a["id"] == asset_id:
            is_public = a.get("exposure") == "public"
            return {
                "provider": "aws",  # could be "azure" / "gcp"
                "instance_id": f"i-{a['id']}",
                "region": "eu-west-1",
                "public_ip": f"203.0.113.{hash(a['id']) % 254 + 1}"
                if is_public
                else None,
                "private_ip": "10.0.1.42",
                "vpc_id": "vpc-production",
                "security_groups": [
                    "sg-web-public" if is_public else "sg-internal-only"
                ],
            }
    return None
