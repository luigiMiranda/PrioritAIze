from __future__ import annotations

import asyncio

import httpx

from app.config import NVD_API_URL

# Retry configuration for NVD API rate limiting (they return 503 when overloaded)
_MAX_RETRIES = 3
_RETRY_BACKOFF_BASE = 1.5  # seconds (1.5, 3, 6, ...)


class CVENotFoundError(Exception):
    """Raised when a CVE ID is not found in the NVD database."""


async def fetch_cve(cve_id: str) -> dict:
    """Fetch CVE details from the NVD API v2 with retry on rate-limit errors.

    Returns a dict with keys: cve_id, description, cvss_score, published.
    """
    url = f"{NVD_API_URL}?cveId={cve_id}"
    last_exc: Exception | None = None

    async with httpx.AsyncClient(timeout=30.0) as client:
        for attempt in range(_MAX_RETRIES + 1):
            try:
                response = await client.get(url)

                # Retry on rate-limiting or transient server errors
                if response.status_code in (429, 503):
                    last_exc = httpx.HTTPStatusError(
                        f"NVD API returned {response.status_code}",
                        request=response.request,
                        response=response,
                    )
                    if attempt < _MAX_RETRIES:
                        delay = _RETRY_BACKOFF_BASE ** (attempt + 1)
                        await asyncio.sleep(delay)
                        continue
                    response.raise_for_status()

                response.raise_for_status()
                data = response.json()
                break  # success — exit retry loop

            except (httpx.TimeoutException, httpx.ConnectError) as exc:
                last_exc = exc
                if attempt < _MAX_RETRIES:
                    delay = _RETRY_BACKOFF_BASE ** (attempt + 1)
                    await asyncio.sleep(delay)
                    continue
                raise

        else:
            # All retries exhausted
            raise last_exc  # type: ignore[misc]

    vulnerabilities = data.get("vulnerabilities", [])  # type: ignore[possibly-unbound]
    if not vulnerabilities:
        raise CVENotFoundError(f"CVE {cve_id} not found in NVD")

    cve = vulnerabilities[0]["cve"]

    # Extract English description
    descriptions = cve.get("descriptions", [])
    description = "No description available."
    for d in descriptions:
        if d.get("lang") == "en":
            description = d["value"]
            break
    else:
        if descriptions:
            description = descriptions[0]["value"]

    # Extract CVSS score (prefer v3.1 > v3.0 > v2)
    metrics = cve.get("metrics", {})
    cvss_score = None
    for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(version, [])
        if metric_list:
            cvss_score = metric_list[0]["cvssData"]["baseScore"]
            break

    return {
        "cve_id": cve["id"],
        "description": description,
        "cvss_score": cvss_score,
        "published": cve.get("published", ""),
    }
