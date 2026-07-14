from __future__ import annotations

import re
import logging

from openai import OpenAI

from app.config import LLM_API_KEY, LLM_BASE_URL, LLM_MODEL

logger = logging.getLogger(__name__)

_client = OpenAI(base_url=LLM_BASE_URL, api_key=LLM_API_KEY)

# Reasoning models (deepseek-r1, deepseek-v3, many "flash"/"thinking" variants)
# emit their chain-of-thought in a separate `reasoning_content` field and only
# place the final answer in `content`. The chain-of-thought tokens count against
# the completion budget, so a small max_tokens can leave `content` empty while
# the actual reasoning is discarded. 4096 is plenty for a structured 3-line
# answer plus the internal deliberation that produces it.
MAX_OUTPUT_TOKENS = 4096

SYSTEM_PROMPT = """\
You are a cybersecurity risk analyst. Given a vulnerability (CVE) and asset \
context, assess the real-world risk to the business.

Reply with exactly four lines in this format — nothing else:
THREAT_LEVEL: <integer 1-10>
JUSTIFICATION: <3-5 sentences explaining WHY you chose this threat level. \
Reference the specific CVE characteristics (exploitability, attack vector, \
impact), the asset type, its exposure, its criticality, and any applicable \
compliance tags. Compare the technical severity against the business context \
to justify raising or lowering the level versus the raw CVSS score.>
NARRATIVE: <2-4 sentence risk assessment in business terms, referencing the \
specific asset type, exposure, and criticality.>
REMEDIATION: <2-3 sentence actionable remediation recommendation.>
"""


def build_user_prompt(cve_description: str, asset: dict) -> str:
    compliance = ", ".join(asset.get("compliance", [])) or "none"
    return f"""\
Vulnerability: {cve_description}

Asset Context:
- Name: {asset["name"]}
- Type: {asset["type"]}
- Exposure: {asset["exposure"]}
- Criticality: {asset["criticality"]}
- Compliance tags: {compliance}

Analyze the risk of this vulnerability on this specific asset."""


# ── response parser ────────────────────────────────────────────────────────

_THREAT_RE = re.compile(
    r"(?:THREAT[_ ]?LEVEL)\s*[:\-=]\s*(\d+(?:\.\d+)?)",
    re.IGNORECASE,
)
_JUSTIFICATION_RE = re.compile(
    r"(?:JUSTIFICATION)\s*[:\-=]\s*(.+?)(?=\n\s*(?:NARRATIVE|REMEDIATION|THREAT[_ ]?LEVEL)\b|$)",
    re.IGNORECASE | re.DOTALL,
)
_NARRATIVE_RE = re.compile(
    r"(?:NARRATIVE)\s*[:\-=]\s*(.+?)(?=\n\s*(?:REMEDIATION|JUSTIFICATION|THREAT[_ ]?LEVEL)\b|$)",
    re.IGNORECASE | re.DOTALL,
)
_REMEDIATION_RE = re.compile(
    r"(?:REMEDIATION)\s*[:\-=]\s*(.+?)(?=\n\s*(?:THREAT[_ ]?LEVEL|NARRATIVE|JUSTIFICATION)\b|$)",
    re.IGNORECASE | re.DOTALL,
)


def _threat_from_reasoning(reasoning: str) -> int:
    """Best-effort threat-level extraction from a reasoning model's CoT text."""
    if not reasoning:
        return 5
    # Look for explicit statements like "threat level is 9" / "I'll go with 8".
    patterns = [
        r"(?:threat[_ ]?level|threat)\s*(?:is|=|:)?\s*(\d+)",
        r"(?:score|severity)\s*(?:of|is|=|:)?\s*(\d+)",
        r"\bI(?:'ll| will)?\s*(?:go with|choose|pick|assign|set)\s*(\d+)",
        r"\b(\d+)\s*/\s*10\b",
    ]
    for pat in patterns:
        m = re.search(pat, reasoning, re.IGNORECASE)
        if m:
            try:
                val = int(float(m.group(1)))
                if 1 <= val <= 10:
                    return val
            except ValueError:
                continue
    return 5


def _parse_llm_response(content: str) -> tuple[int, str, str, str]:
    """Extract threat_level, justification, narrative, and remediation.

    Uses regex first for the structured format; if that fails, scans the full
    text for any threat-level indication.
    """
    text = content.strip()

    if not text:
        return 5, "", "", ""

    # ── threat level ────────────────────────────────────────────────
    threat_level = 5
    m = _THREAT_RE.search(text)
    if m:
        try:
            threat_level = int(float(m.group(1)))
        except ValueError:
            pass

    # Fallback: scan entire text for any score-like number near risk keywords
    if threat_level == 5 and not m:
        fallback = re.search(
            r"(?:threat|risk|severity|score)\b[^0-9]{0,30}?(\d+)",
            text,
            re.IGNORECASE,
        )
        if fallback:
            try:
                threat_level = int(float(fallback.group(1)))
            except ValueError:
                pass

    threat_level = max(1, min(10, threat_level))

    # ── justification ───────────────────────────────────────────────
    justification = ""
    m = _JUSTIFICATION_RE.search(text)
    if m:
        justification = m.group(1).strip()

    # ── narrative ───────────────────────────────────────────────────
    narrative = text  # fallback: full response
    m = _NARRATIVE_RE.search(text)
    if m:
        narrative = m.group(1).strip()

    # ── remediation ─────────────────────────────────────────────────
    remediation = ""
    m = _REMEDIATION_RE.search(text)
    if m:
        remediation = m.group(1).strip()

    return threat_level, justification, narrative, remediation


async def analyze_risk(
    cve_description: str, asset: dict, cvss_score: float | None = None
) -> dict:
    """Send vulnerability + asset context to the LLM and return a structured result.

    Returns dict with keys: threat_level (int 1-10), narrative (str), remediation (str),
    raw_response (str).
    """
    user_prompt = build_user_prompt(cve_description, asset)

    if cvss_score is not None:
        user_prompt += f"\n\nStatic CVSS score for reference: {cvss_score}"

    response = _client.chat.completions.create(
        model=LLM_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        temperature=0.3,
        max_tokens=MAX_OUTPUT_TOKENS,
    )

    message = response.choices[0].message
    content = (message.content or "").strip()
    # Reasoning models emit their chain-of-thought in `reasoning_content`. We do
    # NOT surface that long deliberation to the user; instead we ask the model
    # (via the JUSTIFICATION line in the prompt) to produce a concise summary of
    # *why* it chose the threat level. `reasoning_content` is only used here as a
    # last-resort fallback when the structured `content` is empty (e.g. token
    # budget exhausted before the final answer was emitted).
    reasoning = getattr(message, "reasoning_content", None) or ""

    threat_level, justification, narrative, remediation = _parse_llm_response(content)

    # If the structured answer is empty (e.g. token budget exhausted before the
    # final answer), fall back to scanning the reasoning text so the score is
    # still meaningful and the page can explain it.
    if not content and reasoning:
        threat_level = _threat_from_reasoning(reasoning)
        justification = (
            "The model's structured answer was truncated before completion. "
            "The threat level above was derived from its internal reasoning."
        )
        narrative = ""
        remediation = ""
        logger.warning(
            "LLM 'content' empty for %s; falling back to reasoning_content "
            "(reasoning_tokens=%s). Consider raising MAX_OUTPUT_TOKENS.",
            LLM_MODEL,
            getattr(response.usage, "completion_tokens_details", None),
        )
    elif threat_level == 5 and narrative == content:
        # Parser couldn't find structured markers; the raw text *is* the response.
        pass  # narrative already set to full content

    # If the model produced no explicit justification, synthesise a minimal one
    # so the evaluation page can still explain the score.
    if not justification and narrative:
        justification = (
            f"The model assigned a threat level of {threat_level}/10 based on the "
            f"vulnerability's characteristics and this asset's business context. "
            f"See the business narrative and remediation for details."
        )

    return {
        "threat_level": threat_level,
        "justification": justification,
        "narrative": narrative,
        "remediation": remediation,
        "raw_response": content,
    }
