"""Web page routes — Jinja2-rendered views.

Phase 2 adds: batch evaluation, enhanced result with financial breakdown,
metrics page, login handler, and dashboard with chart data placeholders.
"""

from __future__ import annotations

from fastapi import APIRouter, Request, Form
from fastapi.responses import RedirectResponse

from app.config import APP_API_KEY, SCORING_FORMULA, LLM_BASE_URL, LLM_MODEL
from app.services.pipeline import run_evaluation, AssetNotFoundError, load_assets
from app.services.batch import run_batch
from app.services.nvd import CVENotFoundError
from app.templating import templates
from app.db import (
    get_all_evaluations,
    get_evaluation_by_id,
    delete_evaluation,
    count_by_score_range,
    count_by_asset_type,
    count_by_exposure,
    top_vulnerabilities,
    total_evaluations,
    insert_audit_log,
)

router = APIRouter()


# ── Dashboard ──────────────────────────────────────────────────────────────


@router.get("/")
async def dashboard(request: Request):
    evaluations = get_all_evaluations()
    stats = {
        "total": total_evaluations(),
        "score_distribution": count_by_score_range(),
        "by_asset_type": count_by_asset_type(),
        "by_exposure": count_by_exposure(),
        "top": top_vulnerabilities(5),
    }
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "evaluations": evaluations,
            "stats": stats,
            "scoring_formula": SCORING_FORMULA,
        },
    )


# ── Single evaluation ──────────────────────────────────────────────────────


@router.get("/evaluate")
async def evaluate_form(request: Request):
    assets = load_assets()
    return templates.TemplateResponse(
        request=request, name="evaluate.html", context={"assets": assets}
    )


@router.post("/evaluate")
async def evaluate_submit(
    request: Request, cve_id: str = Form(...), asset_id: str = Form(...)
):
    error = None
    try:
        result = await run_evaluation(cve_id.strip(), asset_id.strip())
        insert_audit_log(
            "evaluation_created",
            f"CVE={cve_id} asset={asset_id} score={result['final_score']}",
            _client_ip(request),
        )
        return RedirectResponse(url=f"/evaluation/{result['id']}", status_code=303)
    except CVENotFoundError:
        error = f"CVE '{cve_id.strip()}' was not found in the NVD database."
    except AssetNotFoundError:
        error = f"Asset '{asset_id.strip()}' was not found."
    except Exception as e:
        error = f"Unexpected error: {e}"

    assets = load_assets()
    return templates.TemplateResponse(
        request=request,
        name="evaluate.html",
        context={
            "assets": assets,
            "error": error,
            "cve_id": cve_id,
            "asset_id": asset_id,
        },
        status_code=400,
    )


@router.get("/evaluation/{eval_id}")
async def evaluation_detail(request: Request, eval_id: int):
    import json

    evaluation = get_evaluation_by_id(eval_id)
    if evaluation is None:
        return templates.TemplateResponse(
            request=request, name="404.html", context={}, status_code=404
        )

    from app.services.scorer import EXPOSURE_MAP, CRITICALITY_MAP
    from app.services.impact import normalize_financial_impact

    exp_val = EXPOSURE_MAP.get(evaluation["asset_exposure"], 5.0)
    crit_val = CRITICALITY_MAP.get(evaluation["asset_criticality"], 5.0)
    fin_val = evaluation.get("total_financial_impact") or 0
    fin_score = normalize_financial_impact(fin_val)

    if SCORING_FORMULA == "phase2" and fin_score > 0:
        weights = {"llm": 0.35, "crit": 0.20, "exp": 0.15, "fin": 0.30}
        breakdown = {
            "llm_contribution": round((evaluation["llm_threat_level"] or 0) * 0.35, 1),
            "criticality_contribution": round(crit_val * 0.20, 1),
            "exposure_contribution": round(exp_val * 0.15, 1),
            "financial_contribution": round(fin_score * 0.30, 1),
        }
    else:
        weights = {"llm": 0.5, "crit": 0.3, "exp": 0.2, "fin": 0.0}
        breakdown = {
            "llm_contribution": round((evaluation["llm_threat_level"] or 0) * 0.5, 1),
            "criticality_contribution": round(crit_val * 0.3, 1),
            "exposure_contribution": round(exp_val * 0.2, 1),
            "financial_contribution": 0,
        }

    # Parse the persisted JSON breakdown (how each monetary value was computed).
    # For older rows created before this column existed, fall back to None and
    # the template will compute the explanation from the scalar columns.
    impact_breakdown = None
    raw_breakdown = evaluation.get("impact_breakdown") or ""
    if raw_breakdown:
        try:
            impact_breakdown = json.loads(raw_breakdown)
        except (json.JSONDecodeError, TypeError):
            impact_breakdown = None

    return templates.TemplateResponse(
        request=request,
        name="result.html",
        context={
            "evaluation": evaluation,
            "breakdown": breakdown,
            "weights": weights,
            "scoring_formula": SCORING_FORMULA,
            "llm_base_url": LLM_BASE_URL,
            "llm_model": LLM_MODEL,
            "exp_val": exp_val,
            "crit_val": crit_val,
            "fin_score": fin_score,
            "impact_breakdown": impact_breakdown,
        },
    )


@router.post("/evaluation/{eval_id}/delete")
async def evaluation_delete(request: Request, eval_id: int):
    evaluation = get_evaluation_by_id(eval_id)
    if evaluation is None:
        return templates.TemplateResponse(
            request=request, name="404.html", context={}, status_code=404
        )
    delete_evaluation(eval_id)
    insert_audit_log(
        "evaluation_deleted",
        f"id={eval_id} CVE={evaluation['cve_id']}",
        _client_ip(request),
    )
    return RedirectResponse(url="/", status_code=303)


# ── Batch evaluation (Phase 2) ─────────────────────────────────────────────


@router.get("/batch")
async def batch_form(request: Request):
    assets = load_assets()
    return templates.TemplateResponse(
        request=request, name="batch.html", context={"assets": assets}
    )


@router.post("/batch")
async def batch_submit(
    request: Request,
    cve_list: str = Form(...),
    asset_id: str = Form(...),
):
    # Parse CVE list: one per line, strip whitespace / empty lines
    cve_ids = [c.strip() for c in cve_list.strip().split("\n") if c.strip()]

    if not cve_ids:
        assets = load_assets()
        return templates.TemplateResponse(
            request=request,
            name="batch.html",
            context={
                "assets": assets,
                "error": "Please enter at least one CVE ID.",
                "cve_list": cve_list,
                "asset_id": asset_id,
            },
            status_code=400,
        )

    items = [(cve, asset_id.strip()) for cve in cve_ids]
    results = await run_batch(items)

    insert_audit_log(
        "batch_evaluation",
        f"count={len(cve_ids)} asset={asset_id}",
        _client_ip(request),
    )

    return templates.TemplateResponse(
        request=request,
        name="batch_result.html",
        context={"results": results, "asset_id": asset_id, "total": len(results)},
    )


# ── Metrics page (Phase 2 §6.3) ────────────────────────────────────────────


@router.get("/metrics")
async def metrics_page(request: Request):
    from app.db import avg_score_by_exposure

    return templates.TemplateResponse(
        request=request,
        name="metrics.html",
        context={
            "total": total_evaluations(),
            "score_distribution": count_by_score_range(),
            "by_exposure": avg_score_by_exposure(),
            "by_asset_type": count_by_asset_type(),
        },
    )


# ── Login (Phase 2 §5) ────────────────────────────────────────────────────


@router.post("/login")
async def login(request: Request, key: str = Form(...)):
    if APP_API_KEY and key == APP_API_KEY:
        resp = RedirectResponse(url="/", status_code=303)
        resp.set_cookie("cvrs_auth", key, httponly=True, max_age=86400 * 30)
        return resp

    from fastapi.responses import HTMLResponse

    return HTMLResponse(
        "<h3>Invalid API key</h3><a href='/'>Try again</a>", status_code=401
    )


# ── helpers ────────────────────────────────────────────────────────────────


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
