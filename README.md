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

**Standard evaluation** (seed assets from `data/assets.yaml`):

1. Open http://localhost:8000/evaluate
2. Enter a CVE ID (e.g., `CVE-2021-44228` for Log4Shell)
3. Select a target asset from the dropdown
4. Click **Evaluate Risk**

**Custom evaluation** (define your own asset with financial parameters on the fly):

1. Open http://localhost:8000/evaluate/custom
2. Enter a CVE ID
3. Fill in asset metadata: name, type, exposure, criticality, compliance tags
4. Enter financial parameters: hourly revenue, annual turnover, customer count, customer lifetime value (CLV)
5. Click **Evaluate Risk**

> Penalties, churn percentages, and downtime-hour brackets are always sourced from `data/cost_model.yaml` — only business-specific financial figures (revenue, turnover, customers, CLV) are user-configurable.

The system will:
1. Fetch the CVE description & CVSS score from the **NVD** (with exponential backoff retry)
2. Send it to your **LLM** for contextual risk reasoning + remediation recommendation
3. Compute **business impact** (downtime costs, regulatory fines, reputational damage)
4. Calculate a **dynamic risk score** using the enhanced formula
5. Persist the result in **PostgreSQL**
6. Show the detailed breakdown with financial analysis and per-value calculation trace

## Project Structure

```
├── app/
│   ├── main.py              # FastAPI app factory (v0.2.0 with auth middleware)
│   ├── config.py            # Env-based configuration (Phase 2: scoring formula, API key)
│   ├── db.py                # PostgreSQL access (psycopg2, raw SQL, aggregation helpers)
│   ├── templating.py        # Jinja2Templates singleton
│   ├── middleware.py         # API-key / bearer-token auth middleware (Phase 2)
│   ├── routes/
│   │   ├── views.py         # Web page routes (dashboard, evaluate, custom, batch, metrics, login)
│   │   └── api.py           # JSON API routes (evaluate, batch, stats, delete)
│   ├── services/
│   │   ├── nvd.py           # NVD API v2: CVE description + CVSS (with retry + backoff)
│   │   ├── llm.py           # OpenAI-compatible LLM risk analysis + structured justification
│   │   ├── scorer.py        # Weighted risk score formula (Phase 1 & 2 toggle)
│   │   ├── impact.py        # Business Impact Modeler: downtime, fines, reputation (Phase 2)
│   │   ├── pipeline.py      # Full evaluation pipeline (standard + custom evaluation)
│   │   ├── batch.py         # Batch evaluation with concurrent semaphore + stagger (Phase 2)
│   │   └── assets/
│   │       ├── cmdb.py      # Mock CMDB connector (Phase 2)
│   │       └── cloud.py     # Mock cloud inventory (Phase 2)
│   ├── templates/           # Jinja2 HTML (Bootstrap 5 + Chart.js + dark mode)
│   │   ├── custom_evaluate.html  # Custom evaluation form (user-defined asset + finances)
│   │   └── ...
│   └── static/              # CSS, JS (dashboard.js for Chart.js rendering)
├── data/
│   ├── assets.yaml          # 8 seed assets (types, exposures, criticalities, compliance)
│   └── cost_model.yaml      # Financial cost parameters per asset type (Phase 2)
├── postgres/
│   └── init.sql             # Database schema + Phase 2 financial columns + audit_log
├── docker-compose.yaml      # App + PostgreSQL 16
├── Dockerfile               # Python 3.12-slim + uv
├── .env.example             # Configuration template
├── spiegazione.md           # Comprehensive project guide (Italian)
└── docs/
    ├── phase2-plan.md       # Phase 2 implementation plan
    └── scoring_formulas.md  # Full mathematical derivation of all scores & costs
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

Financial impact is the total estimated cost (downtime + regulatory fines + reputational damage), normalized via `log₁₀(total + 1) × 1.5` — logarithmic scaling with **no upper cap**, so a €100M breach (score ~12.0) is clearly differentiated from a €10M breach (score ~10.5).

Toggle between formulas with `SCORING_FORMULA=phase1` or `SCORING_FORMULA=phase2` in `.env`.

See [`docs/scoring_formulas.md`](docs/scoring_formulas.md) for the complete mathematical derivation of every parameter, including downtime brackets, regulatory penalty regimes per compliance tag, churn-tier thresholds, and worked examples.

| Weight (P2) | Component | Source |
|-------------|-----------|--------|
| 35% | LLM Threat Level | AI analysis of vulnerability + asset context |
| 20% | Asset Criticality | Seed data: high (10), medium (6), low (3) |
| 15% | Asset Exposure | Seed data: public (10), internal (5), isolated (2) |
| 30% | Financial Impact | Downtime cost + regulatory fines + reputational damage |

## Business Impact Modeler

The modeler quantifies three cost dimensions:

1. **Downtime cost** = `hourly_revenue × estimated_downtime_hours` (downtime hours bracketed by threat level)
2. **Regulatory fines** — per-compliance-tag penalties (GDPR: `max(€20M, 4% × turnover)`; HIPAA, PCI-DSS, SOX, NIS2)
3. **Reputational damage** = `customer_churn_pct × customer_count × customer_lifetime_value` (churn % tiered by severity)

Parameters are configurable in `data/cost_model.yaml`. Each evaluation result page shows the full derivation of every monetary value in a collapsible "Per-value calculation details" table.

### LLM Justification

Every evaluation includes a structured **6-factor justification** from the LLM explaining *why* the threat level was chosen:

1. CVE characteristics (attack vector, complexity, privileges, CIA impact)
2. Asset type implications
3. Exposure impact on attack surface
4. Criticality impact on business damage
5. Compliance tags with specific regulatory consequences
6. Final verdict comparing assigned threat to raw CVSS (raised/lowered rationale)

The justification is displayed prominently on the result page under "Why the LLM chose threat level = N/10".

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

## Dashboard & UI Features

- **Score distribution histogram** (Chart.js bar chart)
- **Asset type breakdown** (doughnut chart)
- **Exposure distribution** (pie chart)
- **Sortable evaluation table** with financial impact column
- **Delete records** (trash button per row with confirmation)
- **CSV export** of visible evaluations
- **Dark/light theme toggle** (persisted across page navigations via localStorage)
- **Batch reasoning expand** — click 💬 on any batch row to see the full LLM justification, narrative, and remediation
- **Per-value financial trace** — every evaluation result shows exactly how each monetary figure was computed (downtime formula, regulatory fine breakdown, reputation calculation, total, and log₁₀ normalization)
- **Metrics page** (`/metrics`): aggregate stats, score distribution, average score by exposure
- **Custom evaluation** (`/evaluate/custom`): define your own asset with financial parameters on the fly — no YAML editing needed

## Authentication (optional)

Set `APP_API_KEY` in `.env` to restrict access:

- Web routes require `Authorization: Bearer <key>` header or `cvrs_auth` cookie
- API routes require `X-API-Key` header
- Leave empty for local development (no auth)

## Custom Evaluation

Need to assess a vulnerability against an asset not in the seed data? Use `/evaluate/custom` to define everything inline:

- **Asset metadata**: name, type (web_server, database, api_endpoint, iot_device, workstation, control_system), exposure (public/internal/isolated), criticality (high/medium/low), compliance tags (GDPR, HIPAA, PCI-DSS, SOX, NIS2)
- **Financial parameters**: hourly revenue (€/h), annual turnover (€), customer count, customer lifetime value (€)

Penalties, churn percentages, and downtime-hour brackets always come from `data/cost_model.yaml` — only your business-specific numbers are exposed. The pipeline reuses the same NVD → LLM → impact → scoring → persistence codepath, so results appear on the dashboard with the same detailed breakdown.

## Documentation

- **[`spiegazione.md`](spiegazione.md)** — comprehensive project guide in Italian covering architecture, every component, parameter glossary, design rationale, user workflows, oral presentation guide, and written report chapter mapping
- **[`docs/scoring_formulas.md`](docs/scoring_formulas.md)** — complete mathematical derivation of all scores, financial costs, normalization, and weight rationale
- **[`docs/phase2-plan.md`](docs/phase2-plan.md)** — original Phase 2 implementation plan
- **[`history.md`](history.md)** — full audit trail of every implementation step
- **[`report.typ`](report.typ)** — final Typst report (8 chapters, compilable with `typst compile report.typ`)

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
