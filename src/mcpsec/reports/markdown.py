"""MCPSec — Markdown report generator.

Generates compliance reports in Markdown format from scan results.
Designed for terminal output, GitHub PR comments, and documentation.
"""

from __future__ import annotations

from mcpsec.models.findings import Finding, ScanResult, Severity
from mcpsec.reports.scorecard import ScoreCard, _compute_score, _compute_grade, _compute_owasp_coverage, _compute_auditor_breakdown



# ---------------------------------------------------------------------------
# Severity display helpers
# ---------------------------------------------------------------------------

_SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFORMATIONAL: "ℹ️",
}

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFORMATIONAL,
]


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_markdown_report(result: ScanResult, scorecard: ScoreCard | None = None) -> str:
    """Generate a full compliance report in Markdown.

    Sections:
        1. Header & scan metadata
        2. Summary table (severity counts, CVSS, CI gate)
        3. Compliance score card
        4. Findings by severity (grouped)
        5. Recommendations summary (prioritized)
        6. Standards coverage
    """
    sections = [
        _header(result),
        _summary_table(result),
        _compliance_scorecard(result, scorecard),
        _findings_section(result),
        _recommendations_section(result),
        _standards_section(result),
        _footer(result),
    ]
    return "\n".join(sections)


def generate_compact_report(result: ScanResult) -> str:
    """Generate a compact report suitable for PR comments or CI logs.

    Shows summary + one-line-per-finding only.
    """
    sections = [
        _compact_header(result),
        _compact_findings(result),
    ]
    return "\n".join(sections)


# ---------------------------------------------------------------------------
# Full report sections
# ---------------------------------------------------------------------------

def _header(result: ScanResult) -> str:
    target = result.target_url or result.target_path or "unknown"
    gate = "✅ PASSED" if result.passed_ci_gate else "❌ FAILED"
    return (
        f"# MCPSec Compliance Report\n"
        f"\n"
        f"| Field | Value |\n"
        f"|---|---|\n"
        f"| **Target** | `{target}` |\n"
        f"| **Scan ID** | `{result.scan_id}` |\n"
        f"| **Date** | {result.scan_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')} |\n"
        f"| **Duration** | {result.scan_duration_seconds}s |\n"
        f"| **Spec Version** | {result.spec_version} |\n"
        f"| **Scanner Version** | MCPSec v{result.scanner_version} |\n"
        f"| **Access Level** | {result.access_level.value} |\n"
        f"| **Scan Depth** | {result.depth.value} |\n"
        f"| **CI Gate** | {gate} |\n"
        f"\n"
    )


def _summary_table(result: ScanResult) -> str:
    counts = result.finding_count
    total = len(result.findings)
    lines = [
        "## Summary\n",
        "| Severity | Count |",
        "|---|---|",
    ]
    for sev in _SEVERITY_ORDER:
        icon = _SEVERITY_ICONS[sev]
        lines.append(f"| {icon} {sev.value.capitalize()} | {counts[sev]} |")
    lines.append(f"| **Total** | **{total}** |")
    lines.append(f"\n**Max CVSS:** {result.max_cvss}\n")
    return "\n".join(lines)


def _compliance_scorecard(result: ScanResult, scorecard: ScoreCard | None = None) -> str:
    """Render compliance scorecard section from a ScoreCard model."""
    if scorecard is None:
        # Sync fallback — compute without LLM
        findings = result.findings
        overall = _compute_score(findings)
        grade, icon = _compute_grade(overall)
        mcp_findings = [f for f in findings if any(s.id.startswith("MCP-SPEC") for s in f.standards)]
        mcp_score = _compute_score(mcp_findings)
        fastmcp_findings = [f for f in findings if any(s.id.startswith("FMCP") for s in f.standards)]
        fastmcp_score = _compute_score(fastmcp_findings)
        owasp_coverage, owasp_categories = _compute_owasp_coverage(findings)
        auditor_breakdown = _compute_auditor_breakdown(findings)
    else:
        overall = scorecard.overall_score
        grade = scorecard.grade
        icon = scorecard.grade_icon
        mcp_score = scorecard.mcp_spec_score
        fastmcp_score = scorecard.fastmcp_baseline_score
        owasp_coverage = scorecard.owasp_mcp_coverage
        owasp_categories = scorecard.owasp_categories
        auditor_breakdown = scorecard.auditor_breakdown

    lines = [
        "## Compliance Score\n",
        f"### {icon} Overall: {overall}/100 (Grade: {grade})\n",
        "| Framework | Score |",
        "|---|---|",
        f"| MCP Spec Compliance | {mcp_score}/100 |",
        f"| OWASP MCP Top 10 | {owasp_coverage}/10 categories clear |",
        f"| FastMCP Baseline | {fastmcp_score}/100 |",
        "",
    ]

    if auditor_breakdown:
        lines.append("| Auditor | Findings | Highest CVSS | Score |")
        lines.append("|---|---|---|---|")
        for a in auditor_breakdown:
            lines.append(f"| {a.auditor} | {a.finding_count} | {a.max_cvss} | {a.score}/100 |")
        lines.append("")

    if owasp_categories:
        lines.append("**OWASP MCP Top 10 Coverage:**\n")
        for cat in owasp_categories:
            status = "✅" if cat.clear else f"❌ ({', '.join(cat.finding_ids)})"
            lines.append(f"- **{cat.id}** {cat.name}: {status}")
        lines.append("")

    if scorecard and scorecard.analysis:
        lines.append("### Risk Analysis\n")
        lines.append(f"{scorecard.analysis}\n")

    return "\n".join(lines)

def _findings_section(result: ScanResult) -> str:
    """Generate detailed findings grouped by severity."""
    if not result.findings:
        return "## Findings\n\nNo findings. ✅\n"

    lines = ["## Findings\n"]

    sorted_findings = sorted(
        result.findings, key=lambda f: (-f.cvss_score, f.finding_id)
    )

    for finding in sorted_findings:
        lines.append(_render_finding(finding))

    return "\n".join(lines)


def _render_finding(finding: Finding) -> str:
    """Render a single finding as Markdown."""
    icon = _SEVERITY_ICONS[finding.severity]
    lines = [
        f"### {icon} {finding.finding_id} — {finding.title}\n",
        f"| Field | Value |",
        f"|---|---|",
        f"| **Severity** | {finding.severity.value.capitalize()} (CVSS {finding.cvss_score}) |",
        f"| **CWE** | {finding.cwe_id} — {finding.cwe_name} |",
        f"| **Confidence** | {finding.confidence.value} |",
        f"| **Detection** | {finding.detection_mode.value} |",
        f"| **Remediation Effort** | {finding.remediation_effort.value} |",
    ]

    if finding.cvss_vector:
        lines.append(f"| **CVSS Vector** | `{finding.cvss_vector}` |")

    lines.append("")

    # Evidence
    lines.append("**Evidence:**\n")
    lines.append(f"> {finding.evidence}\n")

    # Risk
    lines.append("**Risk:**\n")
    lines.append(f"{finding.risk}\n")

    # Recommendation
    lines.append("**Recommendation:**\n")
    lines.append(f"{finding.recommendation}\n")

    # Code example
    if finding.code_example:
        lines.append("**Fix Example:**\n")
        lines.append(f"```python\n{finding.code_example}\n```\n")

    # Standards
    if finding.standards:
        lines.append("**Standards:**\n")
        for std in finding.standards:
            level = f" ({std.requirement_level.value})" if std.requirement_level.value != "N/A" else ""
            lines.append(f"- `{std.id}`: {std.section}{level}")
        lines.append("")

    lines.append("---\n")
    return "\n".join(lines)


def _recommendations_section(result: ScanResult) -> str:
    """Prioritized recommendations summary."""
    if not result.findings:
        return ""

    sorted_findings = sorted(
        result.findings,
        key=lambda f: (f.remediation_priority or 999, -f.cvss_score),
    )

    lines = [
        "## Remediation Priorities\n",
        "| # | Finding | Severity | CVSS | Effort | Action |",
        "|---|---|---|---|---|---|",
    ]

    for i, f in enumerate(sorted_findings, 1):
        icon = _SEVERITY_ICONS[f.severity]
        action = f.recommendation[:80] + ("..." if len(f.recommendation) > 80 else "")
        lines.append(
            f"| {i} | {icon} {f.finding_id} | {f.severity.value} | {f.cvss_score} | "
            f"{f.remediation_effort.value} | {action} |"
        )

    lines.append("")
    return "\n".join(lines)


def _standards_section(result: ScanResult) -> str:
    """Cross-reference table: which standards were checked."""
    if not result.findings:
        return ""

    # Collect all unique standard references across findings
    std_map: dict[str, set[str]] = {}
    for finding in result.findings:
        for std in finding.standards:
            std_map.setdefault(std.id, set()).add(finding.finding_id)

    if not std_map:
        return ""

    lines = [
        "## Standards Cross-Reference\n",
        "| Standard | Findings |",
        "|---|---|",
    ]

    for std_id in sorted(std_map.keys()):
        finding_ids = ", ".join(sorted(std_map[std_id]))
        lines.append(f"| `{std_id}` | {finding_ids} |")

    lines.append("")
    return "\n".join(lines)


def _footer(result: ScanResult) -> str:
    return (
        "---\n"
        f"\n"
        f"*Generated by MCPSec v{result.scanner_version} — "
        f"MCP Security Scanner*\n"
        f"*Spec version: {result.spec_version}*\n"
    )


# ---------------------------------------------------------------------------
# Compact report (for PR comments / CI logs)
# ---------------------------------------------------------------------------

def _compact_header(result: ScanResult) -> str:
    counts = result.finding_count
    target = result.target_url or result.target_path or "unknown"
    gate = "✅ PASSED" if result.passed_ci_gate else "❌ FAILED"

    return (
        f"**MCPSec Scan** | `{target}` | {gate}\n\n"
        f"🔴 {counts[Severity.CRITICAL]} "
        f"🟠 {counts[Severity.HIGH]} "
        f"🟡 {counts[Severity.MEDIUM]} "
        f"🔵 {counts[Severity.LOW]} "
        f"ℹ️ {counts[Severity.INFORMATIONAL]} "
        f"| Max CVSS: {result.max_cvss}\n\n"
    )


def _compact_findings(result: ScanResult) -> str:
    if not result.findings:
        return "No findings. ✅\n"

    lines = [
        "| Finding | Severity | CVSS | Action |",
        "|---|---|---|---|",
    ]

    for f in sorted(result.findings, key=lambda x: -x.cvss_score):
        icon = _SEVERITY_ICONS[f.severity]
        action = f.recommendation[:60] + ("..." if len(f.recommendation) > 60 else "")
        lines.append(f"| {icon} {f.finding_id} | {f.severity.value} | {f.cvss_score} | {action} |")

    lines.append("")
    return "\n".join(lines)
