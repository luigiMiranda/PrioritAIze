# Phase 2 — Implementation Plan

## Goal

Extend the Phase 1 pipeline with the Business Impact Modeler, batch vulnerability processing, advanced dashboard charts, and authentication. The system moves from a single-vulnerability demo to a multi-source, business-aware risk prioritization platform.

---

## 1. Business Impact Modeler

**Source:** project.md §2.3

### Objective
Quantify operational, financial, and reputational costs of a vulnerability exploiting a given asset.

### Inputs
- Asset criticality and compliance tags (from seed data, later from CMDB)
- LLM threat narrative (from Phase 1)
- Industry/region context (new config)

### Model Elements

#### 1.1 Downtime Costs
```
downtime_cost = hourly_revenue × estimated_downtime_hours
```
- `hourly_revenue`: configurable per asset or asset type (e.g., payment gateway = $50K/hr, dev DB = $100/hr)
- `estimated_downtime_hours`: derived from LLM threat level (threat 9-10 → 48h, 7-8 → 24h, 5-6 → 8h, 1-4 → 2h)

#### 1.2 Regulatory Fines
```
regulatory_fine = sum of per-compliance penalties
```
| Tag | Penalty Basis |
|-----|--------------|
| GDPR | 4% of annual turnover (or €20M, whichever higher) — use a configurable `annual_turnover` per asset |
| HIPAA | Tiered: $50K–$1.5M per violation category per year |
| PCI-DSS | $5K–$100K per month of non-compliance |
| NIS 2 | Up to €10M or 2% of global turnover |
| SOX | Up to $5M and/or 20 years imprisonment |

For Phase 2, use simplified flat estimates configurable per asset.

#### 1.3 Reputational Damage
```
reputational_cost = estimated_customer_churn × customer_lifetime_value
```
- `estimated_customer_churn`: percentage derived from breach severity (e.g., 20% for critical public-facing breach)
- `customer_lifetime_value`: configurable per asset

### Output
A dict with `downtime_cost`, `regulatory_fines`, `reputational_cost`, and `total_financial_impact` — all in the configured currency (default: EUR/USD).

### Implementation
- New module: `app/services/impact.py`
- Configurable cost parameters in `data/cost_model.yaml`
- Extend `run_evaluation` pipeline to call impact modeler after LLM step
- Extend scoring formula: add `financial_impact_score` (normalized to 0-10) as additional weighted component
- Extend `init.sql`: add columns `downtime_cost`, `regulatory_fines`, `reputational_cost`, `total_financial_impact` to `evaluations`
- Display financial breakdown on result page

---

## 2. Prioritization Score Calculator — Enhanced

**Source:** project.md §2.4

### Objective
Integrate financial impact into the dynamic risk score.

### Enhanced Formula
```
Risk Score = (LLM_threat × 0.35) + (criticality × 0.20) + (exposure × 0.15) + (financial_impact × 0.30)
```
Financial impact is normalized to 0-10 using logarithmic scaling (to handle wide ranges).

### Implementation
- Update `app/services/scorer.py` with new formula and toggle (Phase 1 vs Phase 2 formula via config)
- Show enhanced breakdown on result page

---

## 3. Batch Vulnerability Processing

### Objective
Accept multiple CVE IDs at once (text area or file upload) and run the full pipeline for each against a selected asset (or auto-detect asset type).

### UI Changes
- Add a "Batch Evaluation" tab
- Text area for CVE list (one per line)
- Optional: CSV/JSON file upload (e.g., Nessus/Tenable export)
- Select target asset(s) — or "auto" to run each CVE against a chosen asset

### Backend
- New endpoint: `POST /evaluate/batch` (handles up to N CVEs concurrently)
- New endpoint: `POST /api/evaluate/batch` (JSON array)
- Concurrency: `asyncio.gather` with semaphore (max 5 concurrent LLM calls)
- New template: `batch_result.html` — summary table with sortable columns
- Rate limiting for NVD API (already handles reasonable usage)

### Implementation
- New module: `app/services/batch.py`
- Extend `views.py` with batch routes
- Extend `api.py` with batch endpoint

---

## 4. Advanced Dashboard

### Objective
Replace the simple HTML table with interactive charts and filtering.

### Features
- Risk score distribution chart (bar/histogram)
- Top N vulnerabilities by score
- Filterable table (by asset type, exposure, criticality, date range)
- Export to CSV button
- Dark/light theme toggle (persisted in localStorage)

### Implementation
- Include Chart.js via CDN in `base.html`
- New endpoint: `GET /api/stats` — returns aggregation data (count by score range, by asset type, etc.)
- `app/static/dashboard.js` — Chart.js rendering and interactive features
- `db.py`: add aggregation query helpers (`count_by_asset_type`, `avg_score_by_exposure`, etc.)

---

## 5. Authentication (Optional / Low Priority)

### Objective
Protect the application if deployed beyond localhost.

### Options
- HTTP Basic Auth (simplest, good for internal tools)
- API key header for `/api/*` routes
- JWT with login page (more effort)

### Recommendation
Start with a single configurable `APP_API_KEY` in `.env`. If set, require `X-API-Key` header on `/api/*` and a session cookie on web routes.

### Implementation
- FastAPI middleware (`app/middleware.py`) for API key check
- Login page if using session-based auth
- Exempt static files and health check

---

## 6. Additional Enhancements

### 6.1 Asset Context — Live Sources
- Replace `data/assets.yaml` with optional live fetchers:
  - `app/services/assets/cmdb.py` — mock ServiceNow/Jira connector
  - `app/services/assets/cloud.py` — mock AWS/Azure resource graph
- Configurable data source selection per asset

### 6.2 History & Audit Log
- New table: `audit_log` (action, timestamp, IP, user, details)
- Log evaluation creation, config changes, auth events

### 6.3 Evaluation Metrics (project.md §3)
- Add a `/metrics` page showing:
  - F1-score placeholder (comparison with static CVSS against ground truth)
  - Reduction in critical vulnerabilities over time
  - Stakeholder feedback survey form (Likert scale)

### 6.4 Remediation Playbook
- Auto-generate a remediation suggestion per vulnerability
- LLM prompt extension: "Provide a 2-3 sentence remediation recommendation"
- Display on result page and in CSV exports

### 6.5 Scheduled Re-scans
- Configurable cron-like schedule for periodic re-evaluation of top vulnerabilities
- Track score changes over time (trend line on dashboard)

---

## Files / Areas Affected (Phase 2)

```
app/
├── services/
│   ├── impact.py              # NEW: Business Impact Modeler
│   ├── batch.py               # NEW: Batch evaluation orchestrator
│   ├── scorer.py              # MODIFIED: Enhanced formula with financial input
│   ├── pipeline.py            # MODIFIED: Add impact step, batch support
│   └── assets/
│       ├── cmdb.py            # NEW: Mock CMDB connector
│       └── cloud.py           # NEW: Mock cloud inventory
├── routes/
│   ├── views.py               # MODIFIED: Batch form, enhanced result, metrics
│   └── api.py                 # MODIFIED: Batch endpoint, stats endpoint
├── middleware.py              # NEW: Auth middleware
├── templates/
│   ├── batch.html             # NEW: Batch evaluation form
│   ├── batch_result.html      # NEW: Batch results table
│   ├── metrics.html           # NEW: Evaluation metrics page
│   └── result.html            # MODIFIED: Financial breakdown section
└── static/
    └── dashboard.js           # NEW: Chart.js interactive features
data/
├── cost_model.yaml            # NEW: Financial cost parameters
└── assets.yaml                # MODIFIED: Add revenue, customers fields
postgres/
└── init.sql                   # MODIFIED: Add financial columns, audit_log table
```

---

## Implementation Order (Recommended)

1. **Business Impact Modeler** — core of Phase 2, feeds into everything else
2. **Enhanced Scoring Formula** — dependent on impact modeler
3. **Advanced Dashboard** — uses the richer data from steps 1-2
4. **Batch Processing** — builds on all prior work
5. **Auth** — optional, last priority
6. **Live Asset Sources** — optional polish
7. **Metrics & Playbook** — final academic polish for the report

---

## Validation Checklist

- [ ] Submit CVE-2021-44228 against "Payment Gateway" → result shows financial impact (downtime + GDPR fine + reputational)
- [ ] Enhanced score visible with breakdown including financial component
- [ ] Batch submit 5 CVEs → all processed, results table sortable
- [ ] Dashboard shows Chart.js histogram of scores
- [ ] CSV export downloads correctly
- [ ] Auth middleware blocks unauthenticated access to `/api/*`
- [ ] `docker compose ps` — all services healthy
- [ ] Data persists across restarts (volume)
- [ ] ruff check all passes
