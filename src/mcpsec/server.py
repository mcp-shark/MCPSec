"""MCPSec — FastMCP Server.

The MCP security scanner exposed as an MCP server itself.
Provides scanning tools that any MCP client (Claude, Cursor, VS Code, etc.)
can invoke to audit other MCP servers.

Run with:
    fastmcp run src/mcpsec/server.py --transport http --host 127.0.0.1 --port 8000
"""


from __future__ import annotations

from mcpsec.reports.markdown import generate_markdown_report, generate_compact_report
from mcpsec.reports.sarif import generate_sarif_report
from mcpsec.scanner.config import ConfigAuditor
from mcpsec.scanner.supply_chain import SupplyChainAuditor
from mcpsec.reports.scorecard import generate_scorecard



from typing import Optional

from fastmcp import FastMCP

from mcpsec.models.findings import (
    AccessLevel,
    Auditor,
    ScanDepth,
    Severity,
)
from mcpsec.scanner import ScannerEngine
from mcpsec.scanner.auth import AuthAuditor
from mcpsec.scanner.authorization import AuthorizationAuditor
from mcpsec.scanner.tools import ToolsAuditor
from mcpsec.scanner.transport import TransportAuditor
from mcpsec.storage import ScanStorage

from mcpsec.llm.classifier import HybridClassifier, create_classifier
from mcpsec.llm.passthrough import (
    PassthroughRequest,
    ClientClassification,
    build_passthrough_request,
    parse_client_classifications,
)
from mcpsec.llm.classifier import ClassificationType, ClassificationVerdict

# ---------------------------------------------------------------------------
# Server instance
# ---------------------------------------------------------------------------

mcp = FastMCP(
    name="MCPSec",
    instructions=(
        "MCPSec is a security scanner for MCP servers. "
        "Use scan_server() for a full audit, or individual scan tools "
        "(scan_auth, scan_transport, scan_authorization, scan_tools) "
        "for targeted checks. Results are stored and can be retrieved "
        "with list_scans(), compared with compare_scans(), or formatted "
        "as reports with generate_report()."
    ),
)

# Shared storage — persists across tool calls within a session
_storage = ScanStorage()


# ---------------------------------------------------------------------------
# Helper — build scanner engine with selected auditors
# ---------------------------------------------------------------------------

def _build_engine(
    target_url: Optional[str] = None,
    target_path: Optional[str] = None,
    access_level: str = "remote",
    depth: str = "standard",
    test_token: Optional[str] = None,
    auditors: Optional[list[type]] = None,
    classifier: Optional[HybridClassifier] = None,
) -> ScannerEngine:
    """Create a ScannerEngine with the specified configuration."""
    engine = ScannerEngine(
        target_url=target_url,
        target_path=target_path,
        access_level=AccessLevel(access_level),
        depth=ScanDepth(depth),
        test_token=test_token,
        classifier=classifier,
    )
    if auditors is None:
        auditors = [AuthAuditor, TransportAuditor, AuthorizationAuditor, ToolsAuditor]
        if AccessLevel(access_level) == AccessLevel.LOCAL:
            auditors.append(ConfigAuditor)
            auditors.append(SupplyChainAuditor)
    for auditor_class in auditors:
        engine.register_auditor(auditor_class)
    return engine



def _format_scan_summary(result) -> dict:
    """Create a concise summary dict from a ScanResult."""
    counts = result.finding_count
    return {
        "scan_id": result.scan_id,
        "target_url": result.target_url,
        "target_path": result.target_path,
        "access_level": result.access_level.value,
        "depth": result.depth.value,
        "spec_version": result.spec_version,
        "scanner_version": result.scanner_version,
        "scan_timestamp": result.scan_timestamp.isoformat(),
        "scan_duration_seconds": result.scan_duration_seconds,
        "total_findings": len(result.findings),
        "critical": counts[Severity.CRITICAL],
        "high": counts[Severity.HIGH],
        "medium": counts[Severity.MEDIUM],
        "low": counts[Severity.LOW],
        "informational": counts[Severity.INFORMATIONAL],
        "max_cvss": result.max_cvss,
        "passed_ci_gate": result.passed_ci_gate,
        "findings": [
            {
                "finding_id": f.finding_id,
                "title": f.title,
                "severity": f.severity.value,
                "cvss_score": f.cvss_score,
                "confidence": f.confidence.value,
                "detection_mode": f.detection_mode.value,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
            }
            for f in sorted(result.findings, key=lambda x: x.cvss_score, reverse=True)
        ],
    }


# ---------------------------------------------------------------------------
# Scanning tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def scan_auth(
    url: str,
    access_level: str = "remote",
    depth: str = "standard",
    test_token: Optional[str] = None,
) -> dict:
    """Audit OAuth 2.1 compliance of an MCP server.

    Checks Protected Resource Metadata, Authorization Server Metadata,
    PKCE support, HTTPS enforcement, WWW-Authenticate headers, and
    registration mechanisms against the MCP authorization spec.

    Args:
        url: Target MCP server URL
        access_level: Scanner access — 'remote', 'authenticated', or 'local'
        depth: Scan thoroughness — 'quick', 'standard', or 'thorough'
        test_token: Bearer token for active scanning (audience binding, scope checks)

    Returns:
        Auth-specific findings with remediation recommendations.
    """
    engine = _build_engine(
        target_url=url,
        access_level=access_level,
        depth=depth,
        test_token=test_token,
        auditors=[AuthAuditor],
    )
    result = await engine.run()
    _storage.save_scan(result)
    return _format_scan_summary(result)


@mcp.tool()
async def scan_transport(
    url: str,
    access_level: str = "remote",
    depth: str = "standard",
    test_token: Optional[str] = None,
) -> dict:
    """Check transport and session security of an MCP server.

    Detects deprecated SSE transport, SSRF-vulnerable metadata URLs,
    session entropy issues, and session binding enforcement.

    Args:
        url: Target MCP server URL
        access_level: Scanner access — 'remote' or 'authenticated'
        depth: Scan thoroughness — 'quick', 'standard', or 'thorough'
        test_token: Bearer token for session security tests

    Returns:
        Transport-specific findings with remediation recommendations.
    """
    engine = _build_engine(
        target_url=url,
        access_level=access_level,
        depth=depth,
        test_token=test_token,
        auditors=[TransportAuditor],
    )
    result = await engine.run()
    _storage.save_scan(result)
    return _format_scan_summary(result)


@mcp.tool()
async def scan_authorization(
    url: str,
    access_level: str = "remote",
    depth: str = "standard",
    test_token: Optional[str] = None,
) -> dict:
    """Audit the authorization model of an MCP server.

    Checks for per-tool scope requirements, wildcard/broad scopes,
    and admin tools without authorization. Uses MCP protocol introspection
    to analyze tool metadata and OAuth scope definitions.

    Args:
        url: Target MCP server URL
        access_level: Scanner access — 'remote', 'authenticated', or 'local'
        depth: Scan thoroughness — 'quick', 'standard', or 'thorough'
        test_token: Bearer token for active authorization testing

    Returns:
        Authorization-specific findings with FastMCP remediation patterns.
    """
    engine = _build_engine(
        target_url=url,
        access_level=access_level,
        depth=depth,
        test_token=test_token,
        auditors=[AuthorizationAuditor],
    )
    result = await engine.run()
    _storage.save_scan(result)
    return _format_scan_summary(result)


@mcp.tool()
async def scan_tools(
    url: str,
    access_level: str = "remote",
    depth: str = "standard",
) -> dict:
    """Analyze MCP server tools for security issues.

    Connects to the server as an MCP client, retrieves tool metadata
    via tools/list, and checks for description poisoning, dangerous
    tool names, and missing input schema validation.

    Args:
        url: Target MCP server URL
        access_level: Scanner access — 'remote' or 'local'
        depth: Scan thoroughness — 'quick', 'standard', or 'thorough'

    Returns:
        Tool-specific findings including poisoning detection results.
    """
    engine = _build_engine(
        target_url=url,
        access_level=access_level,
        depth=depth,
        auditors=[ToolsAuditor],
    )
    result = await engine.run()
    _storage.save_scan(result)
    return _format_scan_summary(result)


# ---------------------------------------------------------------------------
# Config & Supply Chain tools (M2 stubs)
# ---------------------------------------------------------------------------

@mcp.tool()
async def scan_config(
    path: Optional[str] = None,
    approved_servers: Optional[list[str]] = None,
) -> dict:
    """Audit local MCP configuration files for security issues.

    Scans mcp.json, claude_desktop_config.json, and VS Code settings
    for hardcoded credentials, shell injection in startup args,
    symlink attacks, and shadow MCP servers.

    Args:
        path: Path to config file or directory to scan. If None, scans all known locations.
        approved_servers: List of approved server names/URLs for shadow detection.

    Returns:
        Config-specific findings.
    """
    engine = ScannerEngine(
        target_path=path,
        access_level=AccessLevel.LOCAL,
        depth=ScanDepth.STANDARD,
    )

    auditor = ConfigAuditor(
        target_path=path,
        access_level=AccessLevel.LOCAL,
        depth=ScanDepth.STANDARD,
    )
    if approved_servers:
        auditor.set_approved_servers(set(approved_servers))

    engine.register_auditor(ConfigAuditor)
    result = await engine.run()
    _storage.save_scan(result)
    return _format_scan_summary(result)


@mcp.tool()
async def scan_dependencies(path: str) -> dict:
    """Check MCP server dependencies for vulnerabilities.

    Scans package.json, pyproject.toml, and requirements.txt against
    CVE databases. Detects typosquatting packages and unpinned versions.

    Args:
        path: Path to project directory or dependency file.

    Returns:
        Supply chain findings.
    """
    engine = ScannerEngine(
        target_path=path,
        access_level=AccessLevel.LOCAL,
        depth=ScanDepth.STANDARD,
    )
    engine.register_auditor(SupplyChainAuditor)
    result = await engine.run()
    _storage.save_scan(result)
    return _format_scan_summary(result)


@mcp.tool()
async def scan_local() -> dict:
    """Enumerate and audit all locally configured MCP servers.

    Discovers MCP servers from Claude Desktop, VS Code, Cursor, and
    other client configs. Runs appropriate scans on each discovered server.

    Returns:
        Combined findings across all discovered local MCP servers.
    """
    # TODO M2: Implement local discovery (consider leveraging fastmcp discover)
    return {
        "status": "not_implemented",
        "message": "Local scanning will be available in M2. Use scan_server() with a localhost URL.",
    }


# ---------------------------------------------------------------------------
# Report & History tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def generate_report(
    scan_id: str,
    format: str = "markdown",
    compact: bool = False,
) -> dict:
    """Generate a compliance report for a completed scan.

    Args:
        scan_id: ID of a previous scan (from scan_server, scan_auth, etc.)
        format: Output format — 'markdown', 'json', 'html', or 'sarif'
        compact: If True, generate compact report (for PR comments / CI logs)

    Returns:
        Formatted compliance report with score, findings, and recommendations.
    """
    try:
        result = _storage.get_scan(scan_id)
    except Exception as e:
        return {"error": str(e)}

    if format == "json":
        return _format_scan_summary(result)

    if format == "sarif":
        report = generate_sarif_report(result)
        return {
            "scan_id": scan_id,
            "format": "sarif",
            "report": report,
        }

    if format == "html":
        from mcpsec.reports.html import generate_html_report
        scorecard = await generate_scorecard(result)
        report = generate_html_report(result, scorecard=scorecard)
        return {
            "scan_id": scan_id,
            "format": "html",
            "report": report,
        }

    # Markdown (default)
    scorecard = await generate_scorecard(result)
    if compact:
        report = generate_compact_report(result)
    else:
        report = generate_markdown_report(result, scorecard=scorecard)

    return {
        "scan_id": scan_id,
        "format": format,
        "report": report,
    }


@mcp.tool()
async def get_recommendations(scan_id: str) -> dict:
    """Get prioritized fix recommendations for a scan's findings.

    Returns recommendations ordered by priority (severity × effort),
    with FastMCP code examples where applicable.

    Args:
        scan_id: ID of a previous scan.

    Returns:
        Ordered list of recommendations with code examples.
    """
    try:
        result = _storage.get_scan(scan_id)
    except Exception as e:
        return {"error": str(e)}

    recommendations = []
    for finding in sorted(
        result.findings,
        key=lambda f: (f.remediation_priority or 999, -f.cvss_score),
    ):
        rec = {
            "priority": finding.remediation_priority,
            "finding_id": finding.finding_id,
            "title": finding.title,
            "severity": finding.severity.value,
            "cvss_score": finding.cvss_score,
            "effort": finding.remediation_effort.value,
            "recommendation": finding.recommendation,
        }
        if finding.code_example:
            rec["code_example"] = finding.code_example
        if finding.standards:
            rec["standards"] = [
                f"{s.id}: {s.section}" for s in finding.standards
            ]
        recommendations.append(rec)

    return {
        "scan_id": scan_id,
        "total_recommendations": len(recommendations),
        "recommendations": recommendations,
    }


@mcp.tool()
async def list_scans(
    target_url: Optional[str] = None,
    limit: int = 20,
) -> dict:
    """List previous scan results.

    Args:
        target_url: Filter by target URL (optional).
        limit: Maximum number of results (default 20).

    Returns:
        List of scan summaries with severity counts.
    """
    scans = _storage.list_scans(target_url=target_url, limit=limit)
    return {
        "total": len(scans),
        "scans": [s.to_dict() for s in scans],
    }


@mcp.tool()
async def compare_scans(
    scan_id_a: str,
    scan_id_b: str,
) -> dict:
    """Compare two scans to track security improvement or regression.

    scan_id_a is the baseline (older scan), scan_id_b is the current (newer).

    Args:
        scan_id_a: Baseline scan ID (older).
        scan_id_b: Current scan ID (newer).

    Returns:
        Comparison showing resolved, new, and persistent findings.
    """
    try:
        comparison = _storage.compare_scans(scan_id_a, scan_id_b)
        return comparison.to_dict()
    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
async def classify_tools(
    scan_id: str,
    classifications: list[dict],
) -> dict:
    """Submit LLM classifications for tools that need semantic analysis.

    In MCP server mode, scan_tools() returns unclassified items that the
    client LLM should analyze. After the client LLM reasons over them,
    submit the results here to merge into the scan findings.

    Args:
        scan_id: Scan ID from the original scan_tools() call.
        classifications: List of dicts with keys: tool_name, verdict
            (flagged/clean/uncertain), reasoning, confidence (0.0-1.0),
            flagged_patterns (list of strings).

    Returns:
        Updated scan summary with merged LLM findings.
    """
    try:
        result = _storage.get_scan(scan_id)
    except Exception as e:
        return {"error": str(e)}

    parsed = [ClientClassification(**c) for c in classifications]
    llm_results = parse_client_classifications(
        parsed, ClassificationType.TOOL_POISONING
    )

    new_findings = []
    for r in llm_results:
        if r.verdict == ClassificationVerdict.FLAGGED and r.confidence_score >= 0.6:
            from mcpsec.models.findings import (
                Finding, Confidence, DetectionMode, RemediationEffort,
                StandardReference, RequirementLevel,
            )
            new_findings.append(Finding(
                finding_id="MCP-TOOL-001",
                title=f"Tool Description Poisoning Detected (LLM)",
                auditor=Auditor.TOOLS,
                severity=Severity.CRITICAL,
                cvss_score=9.2,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                cwe_id="CWE-77",
                cwe_name="Improper Neutralization of Special Elements Used in a Command",
                detection_mode=DetectionMode.INTROSPECTION,
                confidence=Confidence.MEDIUM,
                detection_method="Client LLM classification via classify_tools().",
                remote_scan_applicable=True,
                standards=[
                    StandardReference(
                        id="OWASP-MCP03",
                        ref="OWASP MCP Top 10 v0.1",
                        section="MCP03 — Tool Poisoning",
                        requirement_level=RequirementLevel.NOT_APPLICABLE,
                    ),
                ],
                evidence=f"Tool '{r.item_id}' flagged by client LLM.\n"
                         f"Reasoning: {r.reasoning}\n"
                         f"Confidence: {r.confidence_score:.0%}\n"
                         f"Patterns: {', '.join(r.flagged_patterns) or 'semantic analysis'}",
                risk="Tool passed rule-based checks but flagged by LLM semantic analysis.",
                recommendation="Review the tool description manually. Remove any hidden directives.",
                remediation_effort=RemediationEffort.LOW,
                remediation_priority=1,
            ))

    if new_findings:
        result.findings.extend(new_findings)
        _storage.save_scan(result)

    return _format_scan_summary(result)


@mcp.tool()
async def get_unclassified_tools(
    url: str,
) -> dict:
    """Get tools that need LLM classification from a previous scan.

    Returns pre-built classification prompts that the client LLM
    can reason over, then submit back via classify_tools().

    Args:
        url: Target MCP server URL to introspect.

    Returns:
        Passthrough request with system prompt, items, and instructions.
    """
    # Run a tools-only scan to get rule-based results
    engine = _build_engine(target_url=url, auditors=[ToolsAuditor])
    result = await engine.run()
    _storage.save_scan(result)

    # Get the tools list for passthrough
    import httpx
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            mcp_url = url.rstrip("/") + "/mcp"
            init_resp = await client.post(mcp_url, json={
                "jsonrpc": "2.0", "method": "initialize",
                "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                           "clientInfo": {"name": "mcpsec", "version": "0.1.0"}},
                "id": 1,
            }, headers={"Content-Type": "application/json"})
            tools_resp = await client.post(mcp_url, json={
                "jsonrpc": "2.0", "method": "tools/list", "id": 2,
            }, headers={"Content-Type": "application/json"})
            tools = tools_resp.json().get("result", {}).get("tools", [])
        except Exception:
            return {"error": "Could not retrieve tools list"}

    rule_flagged = {f.finding_id for f in result.findings if f.auditor == Auditor.TOOLS}
    rule_flagged_names = set()
    for f in result.findings:
        if "Tool '" in f.evidence:
            name = f.evidence.split("Tool '")[1].split("'")[0] if "Tool '" in f.evidence else ""
            if name:
                rule_flagged_names.add(name)

    passthrough = build_passthrough_request(
        scan_id=result.scan_id,
        tools=tools,
        rule_flagged_names=rule_flagged_names,
        classification_type=ClassificationType.TOOL_POISONING,
    )

    return passthrough.model_dump()

@mcp.tool()
async def scan_server(
    url: str,
    access_level: str = "remote",
    depth: str = "standard",
    test_token: Optional[str] = None,
) -> dict:
    """Run a full comprehensive security scan of a remote MCP server.

    Executes all auditors (auth, transport, authorization, tools) and
    stores the result for later retrieval and reporting.

    Args:
        url: Target MCP server URL (e.g. https://my-mcp-server.com)
        access_level: Scanner access — 'remote', 'authenticated', or 'local'
        depth: Scan thoroughness — 'quick', 'standard', or 'thorough'
        test_token: Bearer token for active scanning (required for 'authenticated')

    Returns:
        Scan summary with all findings, severity counts, and compliance status.
    """
    engine = _build_engine(
        target_url=url,
        access_level=access_level,
        depth=depth,
        test_token=test_token,
    )
    result = await engine.run()
    _storage.save_scan(result)

    summary = _format_scan_summary(result)

    # Generate scorecard
    scorecard = await generate_scorecard(result)
    summary["scorecard"] = scorecard.model_dump(mode="json")

    return summary

