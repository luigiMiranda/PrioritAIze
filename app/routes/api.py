"""JSON API endpoints — project.md Phase 1 & 2.

Phase 2 adds: batch evaluation, dashboard statistics, and audit-log recording.
"""

from __future__ import annotations

from fastapi import APIRouter, Request

from app.services.pipeline import run_evaluation, AssetNotFoundError
from app.services.batch import run_batch
from app.services.nvd import CVENotFoundError
from app.db import (
    count_by_score_range,
    count_by_asset_type,
    count_by_exposure,
    total_evaluations,
    delete_evaluation,
    get_evaluation_by_id,
    insert_audit_log,
)

router = APIRouter(prefix="/api")


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# ── Single evaluation (Phase 1) ────────────────────────────────────────────


@router.post("/evaluate")
async def api_evaluate(payload: dict, request: Request):
    """{"cve_id": "CVE-XXXX-XXXXX", "asset_id": "web-payment-prod"}."""
    cve_id = payload.get("cve_id", "").strip()
    asset_id = payload.get("asset_id", "").strip()

    if not cve_id or not asset_id:
        return {"error": "cve_id and asset_id are required."}

    try:
        result = await run_evaluation(cve_id, asset_id)
        insert_audit_log(
            "api_evaluation",
            f"CVE={cve_id} asset={asset_id}",
            _client_ip(request),
        )
        return {"status": "ok", "result": result}
    except CVENotFoundError:
        return {"error": f"CVE '{cve_id}' not found in NVD."}
    except AssetNotFoundError:
        return {"error": f"Asset '{asset_id}' not found."}
    except Exception as e:
        return {"error": str(e)}


# ── Batch evaluation (Phase 2) ─────────────────────────────────────────────


@router.post("/evaluate/batch")
async def api_evaluate_batch(payload: dict, request: Request):
    """{"items": [{"cve_id": "...", "asset_id": "..."}, ...]}."""
    items_raw: list[dict] = payload.get("items", [])
    if not items_raw:
        return {"error": "items array is required."}

    items = [
        (item.get("cve_id", "").strip(), item.get("asset_id", "").strip())
        for item in items_raw
    ]

    results = await run_batch(items)
    ok = sum(1 for r in results if r.get("status") == "ok")
    insert_audit_log(
        "api_batch",
        f"count={len(items)} ok={ok}",
        _client_ip(request),
    )

    return {"status": "ok", "total": len(results), "ok_count": ok, "results": results}


# ── Delete evaluation (Phase 2) ────────────────────────────────────────────


@router.delete("/evaluation/{eval_id}")
async def api_delete_evaluation(eval_id: int, request: Request):
    evaluation = get_evaluation_by_id(eval_id)
    if evaluation is None:
        return {"error": "Evaluation not found."}
    delete_evaluation(eval_id)
    insert_audit_log(
        "api_evaluation_deleted",
        f"id={eval_id} CVE={evaluation['cve_id']}",
        _client_ip(request),
    )
    return {"status": "ok", "deleted_id": eval_id}


# ── Dashboard stats (Phase 2) ──────────────────────────────────────────────


@router.get("/stats")
async def api_stats():
    """Return aggregated data for dashboard charts."""
    return {
        "total_evaluations": total_evaluations(),
        "score_distribution": count_by_score_range(),
        "by_asset_type": count_by_asset_type(),
        "by_exposure": count_by_exposure(),
    }
