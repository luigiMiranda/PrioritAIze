"""Batch evaluation orchestrator — project.md Phase 2 §3.

Runs the full pipeline for multiple CVEs concurrently with a semaphore to
avoid overwhelming the LLM endpoint or NVD API.
"""

from __future__ import annotations

import asyncio

from app.services.pipeline import run_evaluation

MAX_CONCURRENT = 2  # NVD rate-limits aggressively; keep low
_STAGGER_SECONDS = 0.6  # small gap between starting items to avoid burst


async def run_batch(
    items: list[tuple[str, str]],
) -> list[dict]:
    """Evaluate multiple ``(cve_id, asset_id)`` pairs concurrently.

    Each item that raises an exception produces an entry with ``"status":
    "error"`` and an ``error`` field — the batch never fails entirely because
    of one bad CVE.
    """
    sem = asyncio.Semaphore(MAX_CONCURRENT)

    async def _one(cve_id: str, asset_id: str, delay: float = 0.0) -> dict:
        if delay > 0:
            await asyncio.sleep(delay)
        async with sem:
            try:
                result = await run_evaluation(cve_id, asset_id)
                result["status"] = "ok"
                return result
            except Exception as exc:
                return {
                    "cve_id": cve_id.upper(),
                    "asset_id": asset_id,
                    "status": "error",
                    "error": str(exc),
                }

    tasks = [
        _one(cve, asset, delay=i * _STAGGER_SECONDS)
        for i, (cve, asset) in enumerate(items)
    ]
    return await asyncio.gather(*tasks)
