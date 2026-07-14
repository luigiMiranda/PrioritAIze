CREATE TABLE IF NOT EXISTS evaluations (
    id              SERIAL PRIMARY KEY,
    cve_id          VARCHAR(20)  NOT NULL,
    cve_description TEXT         NOT NULL,
    cvss_score      FLOAT,
    asset_id        VARCHAR(50)  NOT NULL,
    asset_name      VARCHAR(200) NOT NULL,
    asset_type      VARCHAR(50)  NOT NULL,
    asset_exposure  VARCHAR(20)  NOT NULL,
    asset_criticality VARCHAR(20) NOT NULL,
    llm_threat_level FLOAT,
    llm_narrative   TEXT,
    final_score     FLOAT        NOT NULL,
    -- Phase 2: financial impact columns
    downtime_cost   FLOAT        DEFAULT 0,
    regulatory_fines FLOAT       DEFAULT 0,
    reputational_cost FLOAT      DEFAULT 0,
    total_financial_impact FLOAT DEFAULT 0,
    remediation     TEXT         DEFAULT '',
    created_at      TIMESTAMP    DEFAULT CURRENT_TIMESTAMP
);

-- Phase 2: add financial columns if table already exists (idempotent)
DO $$
BEGIN
    ALTER TABLE evaluations ADD COLUMN IF NOT EXISTS downtime_cost FLOAT DEFAULT 0;
    ALTER TABLE evaluations ADD COLUMN IF NOT EXISTS regulatory_fines FLOAT DEFAULT 0;
    ALTER TABLE evaluations ADD COLUMN IF NOT EXISTS reputational_cost FLOAT DEFAULT 0;
    ALTER TABLE evaluations ADD COLUMN IF NOT EXISTS total_financial_impact FLOAT DEFAULT 0;
    ALTER TABLE evaluations ADD COLUMN IF NOT EXISTS remediation TEXT DEFAULT '';
    -- Phase 2.1: store the LLM's concise justification of why the threat level
    -- was chosen, and a JSON breakdown of how each monetary value was computed,
    -- so the evaluation page can explain the score and financial impact.
    ALTER TABLE evaluations ADD COLUMN IF NOT EXISTS llm_reasoning TEXT DEFAULT '';
    ALTER TABLE evaluations ADD COLUMN IF NOT EXISTS llm_justification TEXT DEFAULT '';
    ALTER TABLE evaluations ADD COLUMN IF NOT EXISTS impact_breakdown TEXT DEFAULT '';
EXCEPTION WHEN OTHERS THEN NULL;
END $$;

-- Phase 2: audit log table
CREATE TABLE IF NOT EXISTS audit_log (
    id          SERIAL PRIMARY KEY,
    action      VARCHAR(100) NOT NULL,
    details     TEXT,
    ip_address  VARCHAR(45),
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
