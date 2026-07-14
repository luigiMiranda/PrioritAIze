"""PostgreSQL access — psycopg2 with raw SQL.

Phase 2 adds financial-impact columns, aggregation helpers for the dashboard,
and a minimal audit-log table.
"""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path

import psycopg2
import psycopg2.extras

from app.config import DATABASE_URL


def get_connection() -> psycopg2.extensions.connection:
    return psycopg2.connect(DATABASE_URL)


@contextmanager
def get_cursor():
    conn = get_connection()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def run_init_sql() -> None:
    """Execute init.sql to create / migrate tables."""
    init_path = Path(__file__).parent.parent / "postgres" / "init.sql"
    if not init_path.exists():
        return

    sql = init_path.read_text(encoding="utf-8")
    with get_cursor() as cur:
        cur.execute(sql)


# ── evaluations CRUD ───────────────────────────────────────────────────────


def insert_evaluation(data: dict) -> int:
    with get_cursor() as cur:
        cur.execute(
            """
            INSERT INTO evaluations (
                cve_id, cve_description, cvss_score,
                asset_id, asset_name, asset_type, asset_exposure, asset_criticality,
                llm_threat_level, llm_narrative, final_score,
                downtime_cost, regulatory_fines, reputational_cost,
                total_financial_impact, remediation,
                llm_justification, impact_breakdown
            )
            VALUES (
                %(cve_id)s, %(cve_description)s, %(cvss_score)s,
                %(asset_id)s, %(asset_name)s, %(asset_type)s,
                %(asset_exposure)s, %(asset_criticality)s,
                %(llm_threat_level)s, %(llm_narrative)s, %(final_score)s,
                %(downtime_cost)s, %(regulatory_fines)s, %(reputational_cost)s,
                %(total_financial_impact)s, %(remediation)s,
                %(llm_justification)s, %(impact_breakdown)s
            )
            RETURNING id
            """,
            data,
        )
        row = cur.fetchone()
        if row is None:
            raise RuntimeError("INSERT did not return an id")
        return int(row["id"])


def get_all_evaluations() -> list[dict]:
    with get_cursor() as cur:
        cur.execute("SELECT * FROM evaluations ORDER BY created_at DESC")
        return list(cur.fetchall())


def get_evaluation_by_id(eval_id: int) -> dict | None:
    with get_cursor() as cur:
        cur.execute("SELECT * FROM evaluations WHERE id = %s", (eval_id,))
        return cur.fetchone()


def delete_evaluation(eval_id: int) -> bool:
    """Delete an evaluation by id. Returns True if a row was deleted."""
    with get_cursor() as cur:
        cur.execute("DELETE FROM evaluations WHERE id = %s", (eval_id,))
        return cur.rowcount > 0


# ── dashboard aggregations (Phase 2) ──────────────────────────────────────


def count_by_score_range() -> list[dict]:
    """Bucket scores into bins for a histogram chart."""
    with get_cursor() as cur:
        cur.execute(
            """
            SELECT
                CASE
                    WHEN final_score <= 2 THEN '0–2'
                    WHEN final_score <= 4 THEN '2–4'
                    WHEN final_score <= 6 THEN '4–6'
                    WHEN final_score <= 8 THEN '6–8'
                    ELSE '8–10'
                END AS range,
                COUNT(*) AS count
            FROM evaluations
            GROUP BY range
            ORDER BY MIN(final_score)
            """
        )
        return list(cur.fetchall())


def count_by_asset_type() -> list[dict]:
    with get_cursor() as cur:
        cur.execute(
            """
            SELECT asset_type, COUNT(*) AS count
            FROM evaluations GROUP BY asset_type
            ORDER BY count DESC
            """
        )
        return list(cur.fetchall())


def count_by_exposure() -> list[dict]:
    with get_cursor() as cur:
        cur.execute(
            """
            SELECT asset_exposure, COUNT(*) AS count
            FROM evaluations GROUP BY asset_exposure
            ORDER BY count DESC
            """
        )
        return list(cur.fetchall())


def top_vulnerabilities(limit: int = 10) -> list[dict]:
    with get_cursor() as cur:
        cur.execute(
            "SELECT * FROM evaluations ORDER BY final_score DESC LIMIT %s",
            (limit,),
        )
        return list(cur.fetchall())


def avg_score_by_exposure() -> list[dict]:
    with get_cursor() as cur:
        cur.execute(
            """
            SELECT asset_exposure, ROUND(AVG(final_score)::numeric, 1)::float AS avg_score
            FROM evaluations GROUP BY asset_exposure
            ORDER BY avg_score DESC
            """
        )
        return list(cur.fetchall())


def total_evaluations() -> int:
    with get_cursor() as cur:
        cur.execute("SELECT COUNT(*) AS count FROM evaluations")
        row = cur.fetchone()
        return row["count"] if row else 0


# ── audit log (Phase 2) ────────────────────────────────────────────────────


def insert_audit_log(action: str, details: str = "", ip_address: str = "") -> None:
    with get_cursor() as cur:
        cur.execute(
            "INSERT INTO audit_log (action, details, ip_address) VALUES (%s, %s, %s)",
            (action, details, ip_address),
        )
