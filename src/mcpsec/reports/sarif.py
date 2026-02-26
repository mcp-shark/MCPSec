"""MCPSec — SARIF report generator.

Generates Static Analysis Results Interchange Format (SARIF) v2.1.0 reports.
Compatible with GitHub Code Scanning, Azure DevOps, VS Code SARIF Viewer,
and SonarQube SARIF import.

SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from typing import Any

from mcpsec.models.findings import Finding, ScanResult, Severity


# ---------------------------------------------------------------------------
# SARIF severity mapping
# ---------------------------------------------------------------------------

_SEVERITY_TO_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFORMATIONAL: "none",
}

_SEVERITY_TO_SARIF_RANK = {
    Severity.CRITICAL: 90.0,
    Severity.HIGH: 70.0,
    Severity.MEDIUM: 50.0,
    Severity.LOW: 30.0,
    Severity.INFORMATIONAL: 10.0,
}


# ---------------------------------------------------------------------------
# SARIF generation
# ---------------------------------------------------------------------------

def generate_sarif_report(result: ScanResult) -> str:
    """Generate a SARIF v2.1.0 JSON report from a ScanResult.

    Returns:
        JSON string in SARIF v2.1.0 format.
    """
    sarif = _build_sarif(result)
    return json.dumps(sarif, indent=2)


def _build_sarif(result: ScanResult) -> dict[str, Any]:
    """Build the complete SARIF document structure."""
    rules = _build_rules(result.findings)
    results = _build_results(result.findings)
    taxonomies = _build_taxonomies(result.findings)

    target = result.target_url or result.target_path or "unknown"

    sarif: dict[str, Any] = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cos02/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCPSec",
                        "version": result.scanner_version,
                        "informationUri": "https://github.com/mcpsec/mcpsec",
                        "semanticVersion": result.scanner_version,
                        "rules": rules,
                    },
                },
                "results": results,
                "taxonomies": taxonomies,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "commandLine": f"mcpsec scan {target}",
                        "properties": {
                            "scanId": result.scan_id,
                            "accessLevel": result.access_level.value,
                            "depth": result.depth.value,
                            "specVersion": result.spec_version,
                            "scanDurationSeconds": result.scan_duration_seconds,
                        },
                    }
                ],
                "automationDetails": {
                    "id": result.scan_id,
                    "description": {
                        "text": f"MCPSec security scan of {target}",
                    },
                },
                "properties": {
                    "target": target,
                    "maxCvss": result.max_cvss,
                    "passedCiGate": result.passed_ci_gate,
                    "findingCounts": {
                        sev.value: count
                        for sev, count in result.finding_count.items()
                    },
                },
            }
        ],
    }

    return sarif


# ---------------------------------------------------------------------------
# Rules (one per unique finding ID)
# ---------------------------------------------------------------------------

def _build_rules(findings: list[Finding]) -> list[dict[str, Any]]:
    """Build SARIF rule definitions from findings.

    Each unique finding_id becomes a rule. Deduplicates if multiple
    findings share the same ID (shouldn't happen, but defensive).
    """
    seen: dict[str, Finding] = {}
    for finding in findings:
        if finding.finding_id not in seen:
            seen[finding.finding_id] = finding

    rules = []
    for finding in seen.values():
        rule: dict[str, Any] = {
            "id": finding.finding_id,
            "name": finding.finding_id.replace("-", ""),
            "shortDescription": {
                "text": finding.title,
            },
            "fullDescription": {
                "text": finding.risk,
            },
            "help": {
                "text": finding.recommendation,
                "markdown": _build_rule_help_markdown(finding),
            },
            "defaultConfiguration": {
                "level": _SEVERITY_TO_SARIF_LEVEL[finding.severity],
                "rank": _SEVERITY_TO_SARIF_RANK[finding.severity],
            },
            "properties": {
                "severity": finding.severity.value,
                "cvssScore": finding.cvss_score,
                "auditor": finding.auditor.value,
                "detectionMode": finding.detection_mode.value,
                "confidence": finding.confidence.value,
                "remediationEffort": finding.remediation_effort.value,
                "tags": _build_rule_tags(finding),
            },
        }

        if finding.cvss_vector:
            rule["properties"]["cvssVector"] = finding.cvss_vector

        # CWE relationship
        rule["relationships"] = [
            {
                "target": {
                    "id": finding.cwe_id,
                    "guid": _cwe_guid(finding.cwe_id),
                    "toolComponent": {"name": "CWE"},
                },
                "kinds": ["superset"],
            }
        ]

        rules.append(rule)

    return rules


def _build_rule_help_markdown(finding: Finding) -> str:
    """Build Markdown help text for a rule."""
    lines = [
        f"## {finding.title}\n",
        f"**Severity:** {finding.severity.value} (CVSS {finding.cvss_score})\n",
        f"**CWE:** {finding.cwe_id} — {finding.cwe_name}\n",
        f"### Risk\n",
        f"{finding.risk}\n",
        f"### Recommendation\n",
        f"{finding.recommendation}\n",
    ]

    if finding.code_example:
        lines.extend([
            "### Fix Example\n",
            f"```python\n{finding.code_example}\n```\n",
        ])

    if finding.standards:
        lines.append("### Standards\n")
        for std in finding.standards:
            level = f" ({std.requirement_level.value})" if std.requirement_level.value != "N/A" else ""
            lines.append(f"- `{std.id}`: {std.section}{level}")

    return "\n".join(lines)


def _build_rule_tags(finding: Finding) -> list[str]:
    """Build tags array for a rule from standards references."""
    tags = [
        f"security",
        f"mcp",
        f"auditor/{finding.auditor.value}",
        f"detection/{finding.detection_mode.value}",
        finding.cwe_id,
    ]

    for std in finding.standards:
        tags.append(std.id)

    return tags


# ---------------------------------------------------------------------------
# Results (one per finding)
# ---------------------------------------------------------------------------

def _build_results(findings: list[Finding]) -> list[dict[str, Any]]:
    """Build SARIF result entries from findings."""
    results = []

    for finding in sorted(findings, key=lambda f: -f.cvss_score):
        result: dict[str, Any] = {
            "ruleId": finding.finding_id,
            "ruleIndex": _rule_index(findings, finding.finding_id),
            "level": _SEVERITY_TO_SARIF_LEVEL[finding.severity],
            "message": {
                "text": finding.evidence,
                "markdown": (
                    f"**{finding.title}**\n\n"
                    f"{finding.evidence}\n\n"
                    f"**Risk:** {finding.risk}"
                ),
            },
            "properties": {
                "cvssScore": finding.cvss_score,
                "confidence": finding.confidence.value,
                "detectionMode": finding.detection_mode.value,
                "remediationEffort": finding.remediation_effort.value,
            },
        }

        if finding.remediation_priority is not None:
            result["rank"] = float(finding.remediation_priority)

        # Fixes array — recommendation as a fix
        result["fixes"] = [
            {
                "description": {
                    "text": finding.recommendation,
                },
            }
        ]

        if finding.code_example:
            result["fixes"][0]["description"]["text"] += (
                f"\n\nExample:\n{finding.code_example}"
            )

        # Taxa references (CWE + OWASP)
        result["taxa"] = _build_taxa_references(finding)

        results.append(result)

    return results


def _build_taxa_references(finding: Finding) -> list[dict[str, Any]]:
    """Build taxa references for a result (CWE and OWASP mappings)."""
    taxa = [
        {
            "id": finding.cwe_id,
            "guid": _cwe_guid(finding.cwe_id),
            "toolComponent": {"name": "CWE"},
        }
    ]

    for std in finding.standards:
        if std.id.startswith("OWASP"):
            taxa.append({
                "id": std.id,
                "toolComponent": {"name": "OWASP"},
            })

    return taxa


# ---------------------------------------------------------------------------
# Taxonomies (CWE + OWASP definitions)
# ---------------------------------------------------------------------------

def _build_taxonomies(findings: list[Finding]) -> list[dict[str, Any]]:
    """Build SARIF taxonomy definitions for CWE and OWASP."""
    taxonomies = []

    # CWE taxonomy
    cwe_taxa = _build_cwe_taxonomy(findings)
    if cwe_taxa:
        taxonomies.append({
            "name": "CWE",
            "version": "4.14",
            "organization": "MITRE",
            "shortDescription": {"text": "Common Weakness Enumeration"},
            "informationUri": "https://cwe.mitre.org/",
            "isComprehensive": False,
            "taxa": cwe_taxa,
        })

    # OWASP MCP Top 10 taxonomy
    owasp_taxa = _build_owasp_taxonomy(findings)
    if owasp_taxa:
        taxonomies.append({
            "name": "OWASP",
            "version": "2025",
            "organization": "OWASP Foundation",
            "shortDescription": {"text": "OWASP MCP Top 10"},
            "informationUri": "https://owasp.org/www-project-mcp-top-10/",
            "isComprehensive": False,
            "taxa": owasp_taxa,
        })

    return taxonomies


def _build_cwe_taxonomy(findings: list[Finding]) -> list[dict[str, Any]]:
    """Extract unique CWE entries from findings."""
    seen: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if finding.cwe_id not in seen:
            seen[finding.cwe_id] = {
                "id": finding.cwe_id,
                "guid": _cwe_guid(finding.cwe_id),
                "name": finding.cwe_name,
                "shortDescription": {"text": finding.cwe_name},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{finding.cwe_id.split('-')[1]}.html",
            }
    return list(seen.values())


def _build_owasp_taxonomy(findings: list[Finding]) -> list[dict[str, Any]]:
    """Extract unique OWASP references from findings."""
    seen: dict[str, dict[str, Any]] = {}
    for finding in findings:
        for std in finding.standards:
            if std.id.startswith("OWASP") and std.id not in seen:
                seen[std.id] = {
                    "id": std.id,
                    "name": std.section,
                    "shortDescription": {"text": std.section},
                }
    return list(seen.values())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rule_index(findings: list[Finding], finding_id: str) -> int:
    """Get the rule index for a finding ID (order of first appearance)."""
    seen: list[str] = []
    for f in findings:
        if f.finding_id not in seen:
            seen.append(f.finding_id)
    return seen.index(finding_id) if finding_id in seen else 0


def _cwe_guid(cwe_id: str) -> str:
    """Generate a deterministic GUID-like string for a CWE ID.

    SARIF requires GUIDs for taxonomy references. We use a
    deterministic format based on the CWE number for consistency.
    """
    cwe_num = cwe_id.replace("CWE-", "").zfill(8)
    return f"00000000-0000-0000-0000-{cwe_num.zfill(12)}"
