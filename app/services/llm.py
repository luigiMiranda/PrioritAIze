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
# the actual reasoning is discarded. 8192 is plenty for reasoning + a detailed
# 4-line structured answer with expanded justifications.
MAX_OUTPUT_TOKENS = 8192

SYSTEM_PROMPT = """\
You are a cybersecurity risk analyst. Given a vulnerability (CVE) and asset \
context, assess the real-world risk to the business.

Reply with exactly four lines in this format — nothing else:

THREAT_LEVEL: <integer 1-10>

JUSTIFICATION: <A detailed explanation (6-10 sentences) of WHY you chose this \
threat level. For each factor below, explicitly state how it influenced your \
decision — whether it raised or lowered the threat versus the raw CVSS score:

1. CVE CHARACTERISTICS — describe the vulnerability type (RCE, XSS, SQLi, \
privilege escalation, info disclosure, etc.), attack vector (network/adjacent/\
local), attack complexity, privileges required, and user interaction. Explain \
how severe the technical impact is (confidentiality, integrity, availability).

2. ASSET TYPE — explain how this specific asset type (web_server, database, \
api_endpoint, etc.) affects the real-world impact. For example: a database \
holding sensitive data amplifies data-breach risk; an IoT device may have \
physical-safety implications; a control_system could cause operational \
disruption.

3. EXPOSURE — state whether the asset is public-facing, internal, or isolated, \
and explain concretely how that changes the attack surface. A public asset \
can be attacked by anyone on the internet; an internal asset requires \
network access; an isolated asset has minimal reachability.

4. CRITICALITY — state the asset's business criticality (high/medium/low) and \
explain what happens if it goes down or is compromised. High-criticality \
assets cause immediate revenue loss or safety risk; low-criticality assets \
have limited blast radius.

5. COMPLIANCE — if any compliance tags apply (GDPR, HIPAA, PCI-DSS, SOX, \
NIS2), explain the regulatory consequences of a breach on this asset. Mention \
specific fines or legal exposure where relevant.

6. FINAL VERDICT — compare your assigned threat level to the static CVSS \
score. If you raised it, explain which business-context factors drove the \
escalation. If you lowered it, explain why the real-world risk is less than \
the technical score suggests.

Do NOT use bullet points — write in flowing prose as a single cohesive \
paragraph.>

NARRATIVE: <3-5 sentence risk assessment in business terms. Describe the \
real-world scenario: what an attacker could do, what data or services are at \
risk, who would be affected (customers, employees, regulators), and what the \
business consequences would be. Reference the specific asset type, exposure, \
and criticality.>

REMEDIATION: <3-4 sentence actionable remediation recommendation. Be specific: \
mention patching, configuration changes, network segmentation, monitoring, \
or compensating controls appropriate for this asset type and exposure.>
"""


def build_user_prompt(cve_description: str, asset: dict) -> str:
    # Provide business-meaningful descriptions for each exposure / criticality level
    exposure_map = {
        "public": "Public-facing — directly reachable from the internet, maximum attack surface.",
        "internal": "Internal network — accessible only within the corporate LAN/VPN, reduced attack surface.",
        "isolated": "Isolated / air-gapped — no external network access, minimal reachability.",
    }
    criticality_map = {
        "high": "High — business-critical; downtime causes immediate revenue loss, operational failure, or safety risk.",
        "medium": "Medium — important but not mission-critical; moderate business impact if compromised.",
        "low": "Low — non-essential, dev/test, or low-value asset; limited blast radius.",
    }
    type_map = {
        "web_server": "Web server — serves web applications or APIs; typically holds application logic and may have database credentials.",
        "database": "Database server — stores structured data; compromise means data exfiltration, corruption, or deletion.",
        "api_endpoint": "API endpoint — serves programmatic interfaces; often a gateway to backend systems and data.",
        "iot_device": "IoT device — embedded/connected device; may control physical systems or collect sensor data.",
        "workstation": "Workstation — end-user desktop or laptop; entry point for lateral movement into the network.",
        "control_system": "Control system (OT/SCADA) — manages industrial or physical processes; compromise risks safety and operational continuity.",
    }

    compliance_impact: dict[str, str] = {
        "GDPR": "GDPR — personal data of EU citizens; fines up to €20M or 4% of annual global turnover.",
        "HIPAA": "HIPAA — protected health information (PHI); fines up to $50K–$1.5M per violation category.",
        "PCI-DSS": "PCI-DSS — payment card data; fines $5K–$100K per month, plus potential loss of card-processing privileges.",
        "SOX": "SOX — financial reporting integrity; fines up to $5M and potential executive criminal liability.",
        "NIS2": "NIS2 — essential/critical infrastructure; fines up to €10M or 2% of annual global turnover.",
    }

    compliance_details = (
        "\n".join(
            f"  - {tag}: {compliance_impact.get(tag, tag)}"
            for tag in asset.get("compliance", [])
        )
        or "  - None — no specific regulatory framework applies."
    )

    return f"""\
Vulnerability: {cve_description}

Asset Context:
- Name: {asset["name"]}
- Type: {asset["type"]} ({type_map.get(asset["type"], asset["type"])})
- Exposure: {asset["exposure"]} ({exposure_map.get(asset["exposure"], asset["exposure"])})
- Criticality: {asset["criticality"]} ({criticality_map.get(asset["criticality"], asset["criticality"])})
- Compliance tags & implications:
{compliance_details}

Analyze the risk of this vulnerability on this specific asset. Consider how \
every contextual factor — asset type, exposure, criticality, and compliance — \
changes the real-world impact versus the raw CVSS severity."""


# ── response parser ────────────────────────────────────────────────────────

_THREAT_RE = re.compile(
    r"(?:THREAT[_ ]?LEVEL)\s*[:\-=]\s*(\d+(?:\.\d+)?)",
    re.IGNORECASE,
)
# The JUSTIFICATION regex captures everything between JUSTIFICATION: and the next
# section marker (NARRATIVE/REMEDIATION/THREAT_LEVEL). It is greedy up to the
# lookahead, so multi-sentence, multi-line justifications are captured in full.
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
    if not justification:
        if narrative:
            justification = (
                f"The model assigned a threat level of {threat_level}/10 based on the "
                f"vulnerability's characteristics and this asset's business context "
                f"(type={asset.get('type')}, exposure={asset.get('exposure')}, "
                f"criticality={asset.get('criticality')}, "
                f"compliance={', '.join(asset.get('compliance', []) or ['none'])}). "
                f"See the business narrative and remediation for details."
            )
        else:
            justification = (
                f"The model assigned a threat level of {threat_level}/10. "
                f"No detailed explanation was produced — the LLM response "
                f"was empty or truncated. Re-run the evaluation to get a "
                f"full analysis."
            )

    return {
        "threat_level": threat_level,
        "justification": justification,
        "narrative": narrative,
        "remediation": remediation,
        "raw_response": content,
    }
