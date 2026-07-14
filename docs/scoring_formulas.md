# CVRS Score & Financial Impact Formulas — Implementation Reference

> **Audience:** report chapter §5 (Detailed Summary) / §7 (References).  
> Explains every number that appears on an evaluation page: where it came from, how it
> is computed, and which parameters drive it. Use this as the authoritative reference
> when describing the system's internals in the final penetration-testing report.

---

## Overview

The CVRS (Contextual Vulnerability Risk Scoring) pipeline produces two categories of
output for each evaluation:

1.  **Final Risk Score** (0–10) — a weighted sum of four components.
2.  **Financial Impact Estimate** (EUR) — a deterministic simulation of downtime,
    regulatory fines, and reputational damage caused by the vulnerability on the
    specific asset.

All parameters are seeded in two YAML files under `data/`:

| File | Purpose |
|---|---|
| `assets.yaml` | Catalog of in-scope assets: name, type, exposure, criticality, compliance tags. |
| `cost_model.yaml` | Financial parameters per asset type and per regulatory tag. |

In a production deployment these values would be fed by a CMDB and cloud inventory
APIs (§2.1 of `project.md`); in this prototype they are static templates.

---

## 1. Final Risk Score

### Formula (Phase 2 — `SCORING_FORMULA=phase2`)

```
Score = (LLM_Threat × 0.35)
      + (Criticality_norm × 0.20)
      + (Exposure_norm × 0.15)
      + (Financial_norm × 0.30)
```

All four terms are on a 0–10 scale; the result is rounded to 1 decimal.

### Component breakdown

| Component | Weight | How its 0–10 value is determined |
|---|---|---|
| **LLM Threat Level** | 35% | The LLM assigns an integer 1–10 after reasoning on the CVE against the asset's exposure, criticality, and compliance tags. |
| **Asset Criticality** | 20% | Static map: `high` → 10, `medium` → 6, `low` → 3 |
| **Asset Exposure** | 15% | Static map: `public` → 10, `internal` → 5, `isolated` → 2 |
| **Financial Impact** | 30% | Normalised from the raw total financial impact (€) to a 0–10 scale via the log₁₀ function (see §3 below). |

### Phase 1 formula (for reference)

```
Score = (LLM_Threat × 0.5) + (Criticality_norm × 0.3) + (Exposure_norm × 0.2)
```

Phase 1 predates the Business Impact Modeler; it is used only when
`SCORING_FORMULA=phase1` is set in `.env`.

### Why these weights?

- The LLM threat level receives the largest single weight (35%) because it is the
  most context-sensitive input — it adapts to the vulnerability's severity and the
  asset's specific properties in a way static mappings cannot.
- Financial impact is second (30%) because it quantifies the actual business
  consequence of exploitation: downtime, fines, and customer churn.
- Criticality and exposure together carry the remaining 35%, rewarding linear
  differentiation of asset importance.

---

## 2. LLM Threat Level

### How it is produced

The system sends a structured prompt to the LLM:

```
You are a cybersecurity risk analyst. Given a vulnerability (CVE) and asset
context, assess the real-world risk to the business.

Reply with exactly four lines in this format — nothing else:
THREAT_LEVEL: <integer 1-10>
JUSTIFICATION: <3-5 sentences explaining WHY you chose this threat level…>
NARRATIVE: <2-4 sentence risk assessment in business terms…>
REMEDIATION: <2-3 sentence actionable remediation recommendation.>
```

The LLM receives the **CVE description** (fetched from NVD), the static **CVSS
score** (for reference), and the full asset context: name, type, exposure,
criticality, and compliance tags.

The model is expected to **re-calibrate** the raw CVSS: a CVSS 4.3 information
disclosure on a public GDPR-tagged API may be a higher business risk than a CVSS
9.8 DoS on an isolated IoT sensor. The `JUSTIFICATION` line documents this
re-calibration.

### Processing

1. The structured response is parsed via regex (`THREAT_LEVEL:`, `JUSTIFICATION:`,
   `NARRATIVE:`, `REMEDIATION:`).
2. Threat level is clamped to 1–10.
3. If the structured answer is empty (reasoning model token budget exhausted),
   a fallback scans the model's internal reasoning for an explicit level (e.g.
   "I'll go with 8").
4. If the model omits the justification line, a minimal default is synthesised.

---

## 3. Financial Impact — How Each Monetary Value Is Computed

**All values are in EUR** (currency declared in `cost_model.yaml`).

The total financial impact is the deterministic sum of three sub-components that
depend on the asset type, its compliance tags, and the LLM threat level.

```
Total_Financial_Impact = Downtime_Cost + Regulatory_Fines + Reputational_Cost
```

### 3.1 Downtime Cost

```
Downtime_Cost = hourly_revenue × downtime_hours
```

| Input | Source |
|---|---|
| `hourly_revenue` | `cost_model.yaml` → `asset_types.<type>.hourly_revenue` |
| `downtime_hours` | Lookup in `downtime_mapping` by threat bracket |

**Downtime brackets** (in `cost_model.yaml`):

| Threat level | Outage hours |
|---|---|
| ≤ 4 | 2 h |
| 4 < threat ≤ 6 | 8 h |
| 6 < threat ≤ 8 | 24 h |
| 8 < threat ≤ 10 | 48 h |

**Example (api_endpoint, threat 6):** €3,000/h × 8 h = **€24,000**.

### 3.2 Regulatory Fines

For each compliance tag on the asset, the fine is computed as:

```
Fine_per_tag = max(base_penalty, annual_turnover × turnover_pct)
```

Regulatory parameters are in `cost_model.yaml` → `regulatory_fines`:

| Tag | base_penalty | turnover_pct | Rationale |
|---|---|---|---|
| GDPR | €20,000,000 | 4% | GDPR Art. 83: up to €20M or 4% of annual worldwide turnover |
| HIPAA | €500,000 | — | HIPAA tiered penalties; base estimate |
| PCI-DSS | €50,000 | — | $5K–$100K/month; single-month estimate |
| SOX | €5,000,000 | — | Sarbanes-Oxley; up to $5M |
| NIS2 | €7,000,000 | — | NIS 2 Directive; up to €10M or 2% turnover; mid-estimate |

`annual_turnover` is per asset type from `cost_model.yaml` (e.g. €30M for
`api_endpoint`, €50M for `web_server`).

**Why is GDPR usually the dominant term?** The `max()` operator almost always
selects the €20M base penalty over the turnover percentage, because 4% of the
asset's attributable turnover rarely exceeds €20M in this seed dataset. This is
a deliberate simplification — in real assessments, specific revenue attribution
per asset would yield more granular results.

**Example (api-third-party, GDPR tag):**  
GDPR fine = max(€20,000,000, €30,000,000 × 4%) = max(€20M, €1.2M) = **€20M**.

### 3.3 Reputational Damage (Customer Churn Model)

```
Reputational_Cost = customer_count × churn_pct × customer_lifetime_value
```

| Input | Source |
|---|---|
| `customer_count` | `cost_model.yaml` → `asset_types.<type>.customer_count` |
| `customer_lifetime_value (CLV)` | `cost_model.yaml` → `asset_types.<type>.customer_lifetime_value` |
| `churn_pct` | Churn tier selected by threat bracket |

**Churn tiers:**

| Threat level | Tier | Churn % | Label in UI |
|---|---|---|---|
| < 5 | Low | 3% | "medium (threat < 5)" |
| 5–7 | Medium | 10% | "high (threat 5–7)" |
| ≥ 8 | High | 20% | "critical (threat ≥ 8)" |

> **Note:** Assets with `customer_count = 0` (e.g. `workstation`, `iot_device`,
> `control_system`) always have zero reputational cost — the model assumes no
> direct consumer impact for those types.

**Example (api_endpoint, threat 6 → 10% churn):**  
80,000 customers × 10% × €400 CLV = **€3,200,000**.

### 3.4 Complete worked example

**Evaluation:** CVE-2021-44228 (Log4Shell RCE) on `db-internal-dev`
(Database, Internal, Low, no compliance tags), LLM threat = 8.

| Component | Computation | Value |
|---|---|---|
| Downtime | 2,000 €/h × 24 h (threat 8 → 24 h bracket) | €48,000 |
| Regulatory | No compliance tags | €0 |
| Reputation | 50,000 × 20% (threat ≥ 8) × €300 CLV | €3,000,000 |
| **Total** | | **€3,048,000** |

---

## 4. Financial Score Normalization (log₁₀)

The raw total financial impact is normalised to 0–10 for use in the risk-score
formula:

```
Financial_Score = min(10, log₁₀(Total_Financial_Impact + 1) × 1.5)
```

**Why a logarithmic scale?** Financial impacts span orders of magnitude: from
€4,000 (isolated IoT sensor, threat ≤ 4) to €30M+ (public web server with GDPR
+ PCI-DSS, threat 10). A linear map would collapse the entire range or
over-saturate the 0–10 band. The log₁₀ function compresses the range so that
differences in orders of magnitude are rewarded, but within the same order of
magnitude the score is stable.

The `+1` term ensures log(0) is avoided when total impact is €0 (no compliance,
no customers). The `×1.5` multiplier spreads the outputs over the 0–10 band
(€0 → 0, €1K → 4.5, €1M → 9.0, €10M → 10.5 cap at 10, €30M → 10.5 cap at 10).

---

## 5. Why Financial Totals Can Appear to Repeat

The financial model uses **discrete brackets** for both downtime hours and churn
percentage. Two evaluations on the same asset type with the same compliance tags
and threat levels within the **same bracket** will produce the **identical**
total.

**Example:** `CVE-2026-45264` (threat 5) and `CVE-2018-1423` (threat 6) on
`api-third-party` both fall into the "threat ≤ 6" downtime bracket (8 h) and the
"threat 5–7" churn tier (10%). Both therefore produce exactly **€23,224,000**.

This is expected behaviour, not a bug. The system is designed to produce coarse
financial estimates; real-world precision would come from integrating actual
CMDB and revenue data rather than template parameters.

---

## 6. Parameter Sources by Asset Type

Per `cost_model.yaml`:

| Asset type | Hourly revenue | Annual turnover | Customers | CLV |
|---|---|---|---|---|
| web_server | €5,000 | €50,000,000 | 100,000 | €500 |
| database | €2,000 | €20,000,000 | 50,000 | €300 |
| api_endpoint | €3,000 | €30,000,000 | 80,000 | €400 |
| workstation | €200 | €2,000,000 | 0 | €0 |
| iot_device | €500 | €5,000,000 | 0 | €0 |
| control_system | €10,000 | €100,000,000 | 0 | €0 |

> These are prototype values. In a real deployment they would come from the
> organisation's CMDB, financial systems, and cloud inventory APIs.

---

## 7. Scoring Weights Summary Card

```
                   Phase 2                Phase 1
LLM Threat         35%                    50%
Asset Criticality  20%                    30%
Asset Exposure     15%                    20%
Financial Impact   30%                     —
```

Activated by `SCORING_FORMULA=phase2` (or `phase1`) in `.env`.

---

## 8. References (for the final report)

- **project.md §2.2** — LLM-Based Risk Reasoning Engine
- **project.md §2.3** — Business Impact Modeler
- **project.md §2.4** — Prioritization Score Calculator
- **data/cost_model.yaml** — All financial parameters and brackets
- **data/assets.yaml** — Seed asset catalog with compliance tags
- **app/services/scorer.py** — `calculate_score()` implementation
- **app/services/impact.py** — `calculate_business_impact()` and `normalize_financial_impact()`
- **app/services/llm.py** — System prompt and response parser
- **FIRST (2018):** _Common Vulnerability Scoring System v3.1: Specification Document_ — for the static CVSS the LLM receives as reference
- **ENISA (2023):** _Threat Landscape_ — methodology for mapping technical severity to business risk
- **GDPR Art. 83, HIPAA § 160.404, PCI DSS 12.9, SOX § 906, NIS 2 Art. 34** — sources for the regulatory penalty estimates
