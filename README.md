# Contextual Vulnerability Risk Scoring via LLM (CVRS)

A dockerized framework that dynamically prioritizes vulnerabilities by combining LLM reasoning, asset context, and business impact analysis — moving beyond static CVSS scores to actionable, business-aware risk assessments.

## Prerequisites

- **Docker** and **Docker Compose** (v2+)
- An **OpenAI-compatible LLM endpoint** (Ollama, vLLM, LiteLLM, OpenAI, or any custom proxy)
- No NVD API key required (public API, rate-limited)

## Quick Start

### 1. Clone

```bash
git clone https://github.com/luigiMiranda/PrioritAIze.git && cd PrioritAIze
```

### 2. Configure your LLM endpoint

```bash
cp .env.example .env
```

Edit `.env` with your actual values:

```env
LLM_BASE_URL=http://localhost:11434/v1    # your endpoint
LLM_MODEL=llama3.2                        # model name
LLM_API_KEY=ollama                        # your API key
SCORING_FORMULA=phase2                    # phase1 or phase2 (with financial impact)
APP_API_KEY=                              # optional: set for API key auth
```

> **Ollama example:** Install [Ollama](https://ollama.com), run `ollama pull llama3.2`, and use `LLM_BASE_URL=http://host.docker.internal:11434/v1` (on Windows/macOS) or `http://172.17.0.1:11434/v1` (on Linux).

> **OpenAI example:** Set `LLM_BASE_URL=https://api.openai.com/v1`, `LLM_MODEL=gpt-4o`, and your API key.

### 3. Start the application

```bash
docker compose up -d --build
```

The app starts at **http://localhost:8000**.

### 4. Run an evaluation

1. Open http://localhost:8000/evaluate
2. Enter a CVE ID (e.g., `CVE-2021-44228` for Log4Shell)
3. Select a target asset from the dropdown
4. Click **Evaluate Risk**

The system will:
1. Fetch the CVE description & CVSS score from the **NVD**
2. Send it to your **LLM** for contextual risk reasoning + remediation recommendation
3. Compute **business impact** (downtime costs, regulatory fines, reputational damage)
4. Calculate a **dynamic risk score** (0–10) using the enhanced formula
5. Persist the result in **PostgreSQL**
6. Show the detailed breakdown with financial analysis

## Project Structure

```
├── app/
│   ├── main.py              # FastAPI app factory (v0.2.0 with auth middleware)
│   ├── config.py            # Env-based configuration (Phase 2: scoring formula, API key)
│   ├── db.py                # PostgreSQL access (psycopg2, raw SQL, aggregation helpers)
│   ├── templating.py        # Jinja2Templates singleton
│   ├── middleware.py         # API-key / bearer-token auth middleware (Phase 2)
│   ├── routes/
│   │   ├── views.py         # Web page routes (dashboard, evaluate, batch, metrics, login)
│   │   └── api.py           # JSON API routes (evaluate, batch, stats)
│   ├── services/
│   │   ├── nvd.py           # NVD API v2: CVE description + CVSS
│   │   ├── llm.py           # OpenAI-compatible LLM risk analysis + remediation
│   │   ├── scorer.py        # Weighted risk score formula (Phase 1 & 2 toggle)
│   │   ├── impact.py        # Business Impact Modeler: downtime, fines, reputation (Phase 2)
│   │   ├── pipeline.py      # Full evaluation pipeline orchestrator
│   │   ├── batch.py         # Batch evaluation with concurrent semaphore (Phase 2)
│   │   └── assets/
│   │       ├── cmdb.py      # Mock CMDB connector (Phase 2)
│   │       └── cloud.py     # Mock cloud inventory (Phase 2)
│   ├── templates/           # Jinja2 HTML (Bootstrap 5 + Chart.js + dark mode)
│   └── static/              # CSS, JS (dashboard.js for Chart.js rendering)
├── data/
│   ├── assets.yaml          # 8 seed assets (types, exposures, criticalities, compliance)
│   └── cost_model.yaml      # Financial cost parameters per asset type (Phase 2)
├── postgres/
│   └── init.sql             # Database schema + Phase 2 financial columns + audit_log
├── docker-compose.yaml      # App + PostgreSQL 16
├── Dockerfile               # Python 3.12-slim + uv
├── .env.example             # Configuration template
└── docs/
    └── phase2-plan.md       # Phase 2 implementation plan
```

## Scoring Formula

### Phase 1 (original)

```
Score = (LLM Threat Level × 0.5) + (Asset Criticality × 0.3) + (Asset Exposure × 0.2)
```

### Phase 2 (enhanced — default)

```
Score = (LLM Threat × 0.35) + (Criticality × 0.20) + (Exposure × 0.15) + (Financial Impact × 0.30)
```

Financial impact is the total estimated cost (downtime + regulatory fines + reputational damage), normalized to a 0–10 scale using logarithmic scaling.

Toggle between formulas with `SCORING_FORMULA=phase1` or `SCORING_FORMULA=phase2` in `.env`.

| Weight (P2) | Component | Source |
|-------------|-----------|--------|
| 35% | LLM Threat Level | AI analysis of vulnerability + asset context |
| 20% | Asset Criticality | Seed data: high (10), medium (6), low (3) |
| 15% | Asset Exposure | Seed data: public (10), internal (5), isolated (2) |
| 30% | Financial Impact | Downtime cost + regulatory fines + reputational damage |

## Business Impact Modeler

The modeler quantifies three cost dimensions:

1. **Downtime cost** = `hourly_revenue × estimated_downtime_hours` (downtime hours derived from threat level)
2. **Regulatory fines** — per-compliance-tag penalties (GDPR: 4% turnover or €20M; HIPAA, PCI-DSS, SOX, NIS2)
3. **Reputational damage** = `customer_churn_pct × customer_count × customer_lifetime_value`

Parameters are configurable in `data/cost_model.yaml`.

## API

### Evaluate a vulnerability

```bash
curl -X POST http://localhost:8000/api/evaluate \
  -H "Content-Type: application/json" \
  -d '{"cve_id": "CVE-2021-44228", "asset_id": "web-payment-prod"}'
```

### Batch evaluation

```bash
curl -X POST http://localhost:8000/api/evaluate/batch \
  -H "Content-Type: application/json" \
  -d '{"items": [
    {"cve_id": "CVE-2021-44228", "asset_id": "web-payment-prod"},
    {"cve_id": "CVE-2021-45046", "asset_id": "db-customer-prod"}
  ]}'
```

### Dashboard stats

```bash
curl http://localhost:8000/api/stats
```

Response:
```json
{
  "total_evaluations": 42,
  "score_distribution": [
    {"range": "0–2", "count": 2},
    {"range": "2–4", "count": 5},
    {"range": "4–6", "count": 8},
    {"range": "6–8", "count": 15},
    {"range": "8–10", "count": 12}
  ],
  "by_asset_type": [{"asset_type": "web_server", "count": 20}, ...],
  "by_exposure": [{"asset_exposure": "public", "count": 25}, ...]
}
```

## Seed Assets

| ID | Name | Type | Exposure | Criticality | Compliance |
|----|------|------|----------|-------------|------------|
| `web-payment-prod` | Payment Gateway (Prod) | web_server | public | high | PCI-DSS, GDPR |
| `db-customer-prod` | Customer Database (Prod) | database | internal | high | GDPR, HIPAA |
| `web-corp-portal` | Corporate Portal | web_server | public | medium | GDPR |
| `db-internal-dev` | Dev Database Server | database | internal | low | — |
| `iot-building-mgmt` | Building Management | iot_device | isolated | medium | — |
| `ws-finance-prod` | Finance Workstation | workstation | internal | high | SOX |
| `api-third-party` | Third-Party API | api_endpoint | public | medium | GDPR |
| `scada-plant-floor` | SCADA Plant Controller | control_system | isolated | high | NIS2 |

Edit `data/assets.yaml` to customize. Edit `data/cost_model.yaml` to adjust financial parameters per asset type.

## Batch Processing

Visit `/batch` or use the API to evaluate multiple CVEs against a single asset concurrently. Up to 5 CVEs are processed in parallel to respect LLM and NVD rate limits.

## Dashboard Features (Phase 2)

- **Score distribution histogram** (Chart.js bar chart)
- **Asset type breakdown** (doughnut chart)
- **Exposure distribution** (pie chart)
- **Sortable evaluation table** with financial impact column
- **CSV export** button
- **Dark/light theme toggle** (persisted in localStorage)

## Authentication (optional)

Set `APP_API_KEY` in `.env` to restrict access:

- Web routes require `Authorization: Bearer <key>` header or `cvrs_auth` cookie
- API routes require `X-API-Key` header
- Leave empty for local development (no auth)

## Commands

| Command | Purpose |
|---------|---------|
| `docker compose up -d --build` | Build and start both services |
| `docker compose down` | Stop and remove containers |
| `docker compose down -v` | Stop, remove, and **delete** database volume |
| `docker compose logs app` | View app logs |
| `docker compose logs db` | View database logs |
| `docker compose ps` | Check service status |

## Tech Stack

- **Python 3.12** — application runtime
- **FastAPI** — web framework with middleware support
- **Jinja2** + **Bootstrap 5** + **Chart.js** — server-rendered UI with interactive charts
- **PostgreSQL 16** — persistence (raw SQL via psycopg2)
- **OpenAI SDK** — LLM integration (any compatible endpoint)
- **uv** — dependency management
- **Docker Compose** — orchestration

## Phase 2 Highlights

This release adds the following over Phase 1:

- **Business Impact Modeler** — quantifies downtime, regulatory fines, and reputational costs
- **Enhanced scoring formula** — 30% weight on financial impact
- **Batch evaluation** — evaluate multiple CVEs concurrently
- **Advanced dashboard** — Chart.js charts, dark mode, CSV export
- **Remediation playbook** — LLM-generated actionable fix recommendations
- **Authentication middleware** — optional API-key / bearer-token gate
- **Mock CMDB & cloud connectors** — ready for live asset source integration
- **Metrics page** — stakeholder feedback form, score trend placeholder
- **Audit log** — tracks evaluation creation and config changes
