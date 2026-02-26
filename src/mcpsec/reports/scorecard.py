"""MCPSec — Compliance Score Card.

Generates a reusable compliance scorecard from scan results.
Deterministic scoring with optional LLM-generated narrative.

Scoring breakdown:
    - Overall score (0-100): weighted severity deductions
    - MCP Spec compliance: only findings referencing MCP-SPEC standards
    - OWASP MCP Top 10 coverage: 0-10 risk categories clear
    - FastMCP baseline: only findings referencing FMCP standards
    - Per-auditor breakdown
    - Optional LLM analysis narrative
"""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field

from mcpsec.models.findings import Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# OWASP MCP Top 10 category → finding standard ID mapping
# ---------------------------------------------------------------------------

_OWASP_MCP_CATEGORIES: dict[str, str] = {
    "MCP01": "Token Mismanagement & Secret Exposure",
    "MCP02": "Privilege Escalation via Scope Creep",
    "MCP03": "Tool Poisoning",
    "MCP04": "Software Supply Chain Attacks",
    "MCP05": "Command Injection & Execution",
    "MCP06": "Intent Flow Subversion",
    "MCP07": "Insufficient Authentication & Authorization",
    "MCP08": "Lack of Audit and Telemetry",
    "MCP09": "Shadow MCP Servers",
    "MCP10": "Context Injection & Over-Sharing",
}

# Severity → point deductions
_SEVERITY_DEDUCTIONS = {
    Severity.CRITICAL: 15,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFORMATIONAL: 0,
}

# Grade thresholds
_GRADE_THRESHOLDS = [
    (90, "A", "🟢"),
    (75, "B", "🟡"),
    (60, "C", "🟠"),
    (40, "D", "🟠"),
    (0,  "F", "🔴"),
]


# ---------------------------------------------------------------------------
# Score Card models
# ---------------------------------------------------------------------------

class AuditorScore(BaseModel):
    """Per-auditor score breakdown."""
    auditor: str
    finding_count: int
    max_cvss: float
    score: int = Field(ge=0, le=100)


class OwaspCategory(BaseModel):
    """OWASP MCP Top 10 category status."""
    id: str
    name: str
    clear: bool
    finding_ids: list[str] = Field(default_factory=list)


class ScoreCard(BaseModel):
    """Compliance scorecard computed from scan findings."""
    # Overall
    overall_score: int = Field(ge=0, le=100)
    grade: str
    grade_icon: str

    # Framework-specific scores
    mcp_spec_score: int = Field(ge=0, le=100)
    owasp_mcp_coverage: int = Field(ge=0, le=10, description="Risk categories with zero findings")
    owasp_mcp_total: int = Field(default=10)
    fastmcp_baseline_score: int = Field(ge=0, le=100)

    # Breakdowns
    auditor_breakdown: list[AuditorScore] = Field(default_factory=list)
    owasp_categories: list[OwaspCategory] = Field(default_factory=list)

    # LLM narrative (optional)
    analysis: Optional[str] = Field(
        default=None,
        description="LLM-generated risk narrative and remediation reasoning",
    )


# ---------------------------------------------------------------------------
# Scoring logic
# ---------------------------------------------------------------------------

def _compute_score(findings: list[Finding]) -> int:
    """Compute a 0-100 score from findings using severity deductions."""
    score = 100
    for f in findings:
        score -= _SEVERITY_DEDUCTIONS.get(f.severity, 0)
    return max(0, score)


def _compute_grade(score: int) -> tuple[str, str]:
    """Return (grade, icon) for a score."""
    for threshold, grade, icon in _GRADE_THRESHOLDS:
        if score >= threshold:
            return grade, icon
    return "F", "🔴"


def _filter_by_standard_prefix(findings: list[Finding], prefix: str) -> list[Finding]:
    """Filter findings to those referencing standards with the given prefix."""
    return [
        f for f in findings
        if any(s.id.startswith(prefix) for s in f.standards)
    ]


def _compute_owasp_coverage(findings: list[Finding]) -> tuple[int, list[OwaspCategory]]:
    """Compute OWASP MCP Top 10 coverage.

    Returns (clear_count, category_details).
    """
    # Map findings to OWASP categories via standard references
    category_findings: dict[str, list[str]] = {cat: [] for cat in _OWASP_MCP_CATEGORIES}

    for f in findings:
        for std in f.standards:
            # Match OWASP-MCP01 through OWASP-MCP10
            for cat_id in _OWASP_MCP_CATEGORIES:
                if f"OWASP-{cat_id}" == std.id:
                    category_findings[cat_id].append(f.finding_id)

    categories = []
    clear_count = 0
    for cat_id, cat_name in _OWASP_MCP_CATEGORIES.items():
        finding_ids = list(set(category_findings[cat_id]))
        is_clear = len(finding_ids) == 0
        if is_clear:
            clear_count += 1
        categories.append(OwaspCategory(
            id=cat_id,
            name=cat_name,
            clear=is_clear,
            finding_ids=finding_ids,
        ))

    return clear_count, categories


def _compute_auditor_breakdown(findings: list[Finding]) -> list[AuditorScore]:
    """Compute per-auditor scores."""
    auditor_findings: dict[str, list[Finding]] = {}
    for f in findings:
        auditor_findings.setdefault(f.auditor.value, []).append(f)

    breakdown = []
    for auditor, afindings in sorted(auditor_findings.items()):
        score = _compute_score(afindings)
        max_cvss = max(f.cvss_score for f in afindings) if afindings else 0.0
        breakdown.append(AuditorScore(
            auditor=auditor,
            finding_count=len(afindings),
            max_cvss=max_cvss,
            score=score,
        ))

    return breakdown


# ---------------------------------------------------------------------------
# LLM narrative generation
# ---------------------------------------------------------------------------

_SCORECARD_ANALYSIS_PROMPT = """You are an MCP security analyst. Analyze this scan scorecard and provide
a concise executive summary (3-5 sentences) covering:

1. The most critical risk and its business impact
2. How findings interact (e.g. broken auth chain makes other issues worse)
3. The single most impactful fix to prioritize

Scan target: {target}
Overall score: {score}/100 (Grade: {grade})
MCP Spec compliance: {mcp_score}/100
OWASP MCP coverage: {owasp_coverage}/10 categories clear
FastMCP baseline: {fastmcp_score}/100

Findings ({count} total):
{findings_summary}

Respond in plain text, no JSON. Be specific about THIS server's risks."""


async def _generate_analysis(
    result: ScanResult,
    scorecard: ScoreCard,
    classifier,
) -> Optional[str]:
    """Generate LLM narrative for the scorecard."""
    if not classifier or not classifier.is_available:
        return None

    findings_summary = "\n".join(
        f"  - [{f.severity.value.upper()}] {f.finding_id}: {f.title} (CVSS {f.cvss_score})"
        for f in sorted(result.findings, key=lambda x: -x.cvss_score)
    )

    target = result.target_url or result.target_path or "unknown"
    prompt = _SCORECARD_ANALYSIS_PROMPT.format(
        target=target,
        score=scorecard.overall_score,
        grade=scorecard.grade,
        mcp_score=scorecard.mcp_spec_score,
        owasp_coverage=scorecard.owasp_mcp_coverage,
        fastmcp_score=scorecard.fastmcp_baseline_score,
        count=len(result.findings),
        findings_summary=findings_summary or "  No findings.",
    )

    try:
        response, _ = await classifier._provider.classify(
            system_prompt="You are an MCP security analyst writing executive summaries.",
            user_prompt=prompt,
        )
        # Response may be a dict (JSON mode) or plain text
        if isinstance(response, dict):
            return response.get("reasoning", response.get("analysis", str(response)))
        return str(response)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Factory function
# ---------------------------------------------------------------------------

async def generate_scorecard(
    result: ScanResult,
    classifier=None,
) -> ScoreCard:
    """Generate a compliance scorecard from scan results.

    Args:
        result: Completed scan result.
        classifier: Optional HybridClassifier for LLM narrative.

    Returns:
        ScoreCard with deterministic scores + optional LLM analysis.
    """
    findings = result.findings

    # Overall score
    overall = _compute_score(findings)
    grade, icon = _compute_grade(overall)

    # Framework-specific scores
    mcp_findings = _filter_by_standard_prefix(findings, "MCP-SPEC")
    mcp_score = _compute_score(mcp_findings)

    fastmcp_findings = _filter_by_standard_prefix(findings, "FMCP")
    fastmcp_score = _compute_score(fastmcp_findings)

    # OWASP coverage
    owasp_coverage, owasp_categories = _compute_owasp_coverage(findings)

    # Per-auditor breakdown
    auditor_breakdown = _compute_auditor_breakdown(findings)

    scorecard = ScoreCard(
        overall_score=overall,
        grade=grade,
        grade_icon=icon,
        mcp_spec_score=mcp_score,
        owasp_mcp_coverage=owasp_coverage,
        fastmcp_baseline_score=fastmcp_score,
        auditor_breakdown=auditor_breakdown,
        owasp_categories=owasp_categories,
    )

    # LLM narrative (optional)
    if classifier:
        scorecard.analysis = await _generate_analysis(result, scorecard, classifier)

    return scorecard
