"""MCPSec — Command-line interface.

Provides CLI access to the scanner without requiring an MCP client.

Usage:
    mcpsec scan <url>                           # full remote scan
    mcpsec scan <url> --access authenticated --test-token $TOKEN
    mcpsec auth <url>                           # auth-only scan
    mcpsec transport <url>                      # transport-only scan
    mcpsec authorization <url>                  # authorization-only scan
    mcpsec tools <url>                          # tools-only scan
    mcpsec report <scan_id>                     # generate report
    mcpsec list                                 # list past scans
    mcpsec compare <scan_id_a> <scan_id_b>      # compare two scans
    mcpsec ci <url> --fail-on <cvss>            # CI/CD mode (exit code)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Optional

from mcpsec.models.findings import AccessLevel, ScanDepth, Severity
from mcpsec.scanner import ScannerEngine
from mcpsec.scanner.auth import AuthAuditor
from mcpsec.scanner.authorization import AuthorizationAuditor
from mcpsec.scanner.tools import ToolsAuditor
from mcpsec.scanner.transport import TransportAuditor
from mcpsec.storage import ScanStorage
from mcpsec.scanner.config import ConfigAuditor
from mcpsec.scanner.supply_chain import SupplyChainAuditor

from mcpsec.llm.classifier import create_classifier



# ---------------------------------------------------------------------------
# Auditor registry
# ---------------------------------------------------------------------------

_AUDITOR_MAP = {
    "auth": [AuthAuditor],
    "transport": [TransportAuditor],
    "authorization": [AuthorizationAuditor],
    "tools": [ToolsAuditor],
    "config": [ConfigAuditor],
    "dependencies": [SupplyChainAuditor],
    "all": [AuthAuditor, TransportAuditor, AuthorizationAuditor, ToolsAuditor],
    "all_local": [AuthAuditor, TransportAuditor, AuthorizationAuditor, ToolsAuditor, ConfigAuditor, SupplyChainAuditor],
}


# ---------------------------------------------------------------------------
# CLI output helpers
# ---------------------------------------------------------------------------

_SEVERITY_ICONS = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFORMATIONAL: "ℹ️ ",
}


def _print_banner() -> None:
    print(
        "\n"
        "  ╔══════════════════════════════════════╗\n"
        "  ║   MCPSec — MCP Security Scanner      ║\n"
        "  ║   v0.1.0                              ║\n"
        "  ╚══════════════════════════════════════╝\n"
    )


def _print_summary(result) -> None:
    """Print a colored scan summary to stdout."""
    counts = result.finding_count
    total = len(result.findings)
    gate = "✅ PASSED" if result.passed_ci_gate else "❌ FAILED"

    print(f"\n  Target:     {result.target_url or result.target_path}")
    print(f"  Scan ID:    {result.scan_id}")
    print(f"  Duration:   {result.scan_duration_seconds}s")
    print(f"  Spec:       {result.spec_version}")
    print(f"  Access:     {result.access_level.value}")
    print(f"  Depth:      {result.depth.value}")
    print(f"\n  ── Results ──────────────────────────")
    print(f"  🔴 Critical:      {counts[Severity.CRITICAL]}")
    print(f"  🟠 High:          {counts[Severity.HIGH]}")
    print(f"  🟡 Medium:        {counts[Severity.MEDIUM]}")
    print(f"  🔵 Low:           {counts[Severity.LOW]}")
    print(f"  ℹ️  Informational: {counts[Severity.INFORMATIONAL]}")
    print(f"  ─────────────────────────────────────")
    print(f"  Total:            {total}")
    print(f"  Max CVSS:         {result.max_cvss}")
    print(f"  CI Gate:          {gate}")
    print()


def _print_findings(result) -> None:
    """Print individual findings to stdout."""
    if not result.findings:
        print("  No findings. ✅")
        return

    for finding in sorted(result.findings, key=lambda f: f.cvss_score, reverse=True):
        icon = _SEVERITY_ICONS[finding.severity]
        print(f"  {icon} {finding.finding_id} — {finding.title}")
        print(f"     CVSS: {finding.cvss_score} | {finding.confidence.value} | {finding.detection_mode.value}")
        print(f"     {finding.evidence[:120]}{'...' if len(finding.evidence) > 120 else ''}")
        print(f"     → {finding.recommendation[:120]}{'...' if len(finding.recommendation) > 120 else ''}")
        print()


# ---------------------------------------------------------------------------
# Scan runner
# ---------------------------------------------------------------------------

async def _run_scan(
    url: str,
    auditors: list[type],
    access_level: AccessLevel,
    depth: ScanDepth,
    test_token: Optional[str] = None,
    output_json: bool = False,
    use_llm: bool = False,
    model: Optional[str] = None,
) -> int:
    """Execute a scan and return exit code (0 = pass, 1 = findings)."""
    classifier = None
    if use_llm:
        classifier = create_classifier(model=model)
        if not classifier.is_available:
            print("  ⚠️  --llm enabled but no API key found. Set ANTHROPIC_API_KEY, OPENAI_API_KEY, etc.")
            print("  Falling back to rule-based only.\n")
            classifier = None

    engine = ScannerEngine(
        target_url=url,
        access_level=access_level,
        depth=depth,
        test_token=test_token,
        classifier=classifier,
    )
    for auditor_class in auditors:
        engine.register_auditor(auditor_class)

    result = await engine.run()

    # Store result
    storage = ScanStorage()
    try:
        storage.save_scan(result)
    finally:
        storage.close()

    if output_json:
        output = result.model_dump(mode="json")
        print(json.dumps(output, indent=2))
    else:
        _print_summary(result)
        _print_findings(result)

    return 0 if result.passed_ci_gate else 1


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

async def _cmd_scan(args: argparse.Namespace) -> int:
    """Handle scan / auth / transport / authorization / tools / config commands."""
    if args.auditor == "config":
        from mcpsec.scanner.config import ConfigAuditor as CA
        engine = ScannerEngine(
            target_path=getattr(args, "path", None),
            access_level=AccessLevel.LOCAL,
            depth=ScanDepth.STANDARD,
        )
        engine.register_auditor(CA)
        result = await engine.run()
        storage = ScanStorage()
        try:
            storage.save_scan(result)
        finally:
            storage.close()
        if args.json:
            print(json.dumps(result.model_dump(mode="json"), indent=2))
        else:
            _print_summary(result)
            _print_findings(result)
        return 0 if result.passed_ci_gate else 1
    
    if args.auditor == "dependencies":
        engine = ScannerEngine(
            target_path=args.path,
            access_level=AccessLevel.LOCAL,
            depth=ScanDepth.STANDARD,
        )
        engine.register_auditor(SupplyChainAuditor)
        result = await engine.run()
        storage = ScanStorage()
        try:
            storage.save_scan(result)
        finally:
            storage.close()
        if args.json:
            print(json.dumps(result.model_dump(mode="json"), indent=2))
        else:
            _print_summary(result)
            _print_findings(result)
        return 0 if result.passed_ci_gate else 1


    auditors = _AUDITOR_MAP.get(args.auditor, _AUDITOR_MAP["all"])
    if AccessLevel(args.access) == AccessLevel.LOCAL:
        auditors = _AUDITOR_MAP["all_local"]
    return await _run_scan(
        url=args.url,
        auditors=auditors,
        access_level=AccessLevel(args.access),
        depth=ScanDepth(args.depth),
        test_token=args.test_token,
        output_json=args.json,
        use_llm=getattr(args, "llm", False),
        model=getattr(args, "model", None),
    )



async def _cmd_ci(args: argparse.Namespace) -> int:
    """Handle CI/CD mode — exit code based on CVSS threshold."""
    classifier = None
    if getattr(args, "llm", False):
        classifier = create_classifier(model=getattr(args, "model", None))
        if not classifier.is_available:
            classifier = None

    engine = ScannerEngine(
        target_url=args.url,
        access_level=AccessLevel(args.access),
        depth=ScanDepth(args.depth),
        test_token=args.test_token,
        classifier=classifier,
    )
    for auditor_class in _AUDITOR_MAP["all"]:
        engine.register_auditor(auditor_class)

    result = await engine.run()

    # Store result
    storage = ScanStorage()
    try:
        storage.save_scan(result)
    finally:
        storage.close()

    if args.json:
        output = result.model_dump(mode="json")
        print(json.dumps(output, indent=2))
    else:
        _print_summary(result)
        _print_findings(result)

    # CI gate: fail if any finding meets or exceeds threshold
    threshold = args.fail_on
    above = result.findings_above_cvss(threshold)

    if above:
        print(f"\n  ❌ CI FAILED — {len(above)} finding(s) at or above CVSS {threshold}")
        return 1
    else:
        print(f"\n  ✅ CI PASSED — no findings at or above CVSS {threshold}")
        return 0


async def _cmd_report(args: argparse.Namespace) -> int:
    """Handle report generation."""
    from mcpsec.server import generate_report
    fmt = "json" if args.json else args.format
    result = await generate_report(
        scan_id=args.scan_id,
        format=fmt,
        compact=getattr(args, "compact", False),
    )
    if "error" in result:
        print(f"  Error: {result['error']}", file=sys.stderr)
        return 1
    if fmt == "json":
        print(json.dumps(result, indent=2))
    elif fmt == "html":
        # Write HTML to file and notify user
        output_file = f"mcpsec_report_{args.scan_id}.html"
        with open(output_file, "w") as f:
            f.write(result.get("report", ""))
        print(f"  HTML report saved to: {output_file}")
    else:
        print(result.get("report", ""))
    return 0


async def _cmd_list(args: argparse.Namespace) -> int:
    """Handle list scans."""
    storage = ScanStorage()
    try:
        scans = storage.list_scans(target_url=args.target, limit=args.limit)
    finally:
        storage.close()

    if not scans:
        print("  No scans found.")
        return 0

    if args.json:
        print(json.dumps([s.to_dict() for s in scans], indent=2))
    else:
        print(f"\n  {'Scan ID':<40} {'Target':<35} {'Findings':>8} {'Max CVSS':>9} {'Gate':>6}")
        print(f"  {'─' * 40} {'─' * 35} {'─' * 8} {'─' * 9} {'─' * 6}")
        for s in scans:
            gate = "✅" if s.passed_ci_gate else "❌"
            target = (s.target_url or s.target_path or "")[:35]
            print(f"  {s.scan_id:<40} {target:<35} {s.finding_count:>8} {s.max_cvss:>9.1f} {gate:>6}")
    print()
    return 0


async def _cmd_compare(args: argparse.Namespace) -> int:
    """Handle scan comparison."""
    storage = ScanStorage()
    try:
        comparison = storage.compare_scans(args.scan_a, args.scan_b)
    except Exception as e:
        print(f"  Error: {e}", file=sys.stderr)
        return 1
    finally:
        storage.close()

    if args.json:
        print(json.dumps(comparison.to_dict(), indent=2))
    else:
        print(f"\n  ── Scan Comparison ──────────────────")
        print(f"  Baseline: {comparison.baseline_scan_id}")
        print(f"  Current:  {comparison.current_scan_id}")
        print(f"  ─────────────────────────────────────")
        print(f"  Resolved (fixed):    {len(comparison.resolved_findings)}")
        print(f"  New (introduced):    {len(comparison.new_findings)}")
        print(f"  Persistent:          {len(comparison.persistent_findings)}")
        print(f"  Severity changes:    {len(comparison.severity_changes)}")
        print(f"  ─────────────────────────────────────")
        print(f"  Baseline findings:   {comparison.baseline_finding_count}")
        print(f"  Current findings:    {comparison.current_finding_count}")
        print(f"  Baseline max CVSS:   {comparison.baseline_max_cvss}")
        print(f"  Current max CVSS:    {comparison.current_max_cvss}")
        trend = "📈 Improved" if comparison.improved else "📉 Regressed"
        print(f"  Trend:               {trend}")

        if comparison.resolved_findings:
            print(f"\n  ✅ Resolved: {', '.join(comparison.resolved_findings)}")
        if comparison.new_findings:
            print(f"\n  🆕 New:      {', '.join(comparison.new_findings)}")
        if comparison.severity_changes:
            print(f"\n  🔄 Changed:")
            for sc in comparison.severity_changes:
                print(f"     {sc.finding_id}: {sc.old_severity.value} → {sc.new_severity.value}")

    print()
    return 0

def _cmd_serve(args: argparse.Namespace) -> None:
    """Handle serve command — run MCPSec as an MCP server."""
    from mcpsec.server import mcp as mcp_server

    transport = args.transport
    host = args.host
    port = args.port

    print(f"  Starting MCPSec MCP server...")
    print(f"  Transport: {transport}")
    if transport != "stdio":
        print(f"  Endpoint:  http://{host}:{port}/mcp")
    print(f"  Press Ctrl+C to stop.\n")

    if transport == "stdio":
        mcp_server.run(transport="stdio")
    else:
        mcp_server.run(transport="streamable-http", host=host, port=port)

# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="mcpsec",
        description="MCPSec — MCP Security Scanner",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- Shared scan arguments ---
    def _add_scan_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("url", help="Target MCP server URL")
        p.add_argument(
            "--access", choices=["remote", "authenticated", "local"],
            default="remote", help="Scanner access level (default: remote)"
        )
        p.add_argument(
            "--depth", choices=["quick", "standard", "thorough"],
            default="standard", help="Scan depth (default: standard)"
        )
        p.add_argument("--test-token", help="Bearer token for active scanning")
        p.add_argument("--json", action="store_true", help="Output as JSON")
        p.add_argument("--llm", action="store_true", help="Enable LLM second-pass classification (BYOK)")
        p.add_argument("--model", help="LLM model override (e.g. gpt-4o, claude-sonnet-4-20250514)")

    # scan — full scan
    p_scan = subparsers.add_parser("scan", help="Full security scan")
    _add_scan_args(p_scan)
    p_scan.set_defaults(auditor="all")

    # auth — auth-only scan
    p_auth = subparsers.add_parser("auth", help="OAuth 2.1 compliance audit")
    _add_scan_args(p_auth)
    p_auth.set_defaults(auditor="auth")

    # transport — transport-only scan
    p_transport = subparsers.add_parser("transport", help="Transport security check")
    _add_scan_args(p_transport)
    p_transport.set_defaults(auditor="transport")

    # authorization — authorization-only scan
    p_authz = subparsers.add_parser("authorization", help="Authorization model audit")
    _add_scan_args(p_authz)
    p_authz.set_defaults(auditor="authorization")

    # tools — tools-only scan
    p_tools = subparsers.add_parser("tools", help="Tool security analysis")
    _add_scan_args(p_tools)
    p_tools.set_defaults(auditor="tools")

    # ci — CI/CD mode
    p_ci = subparsers.add_parser("ci", help="CI/CD mode (exit code based on CVSS)")
    _add_scan_args(p_ci)
    p_ci.add_argument(
        "--fail-on", type=float, default=7.0,
        help="CVSS threshold to fail (default: 7.0)"
    )

    # report
    p_report = subparsers.add_parser("report", help="Generate compliance report")
    p_report.add_argument("scan_id", help="Scan ID to report on")
    
    p_report.add_argument(
        "--format", choices=["markdown", "json", "html", "sarif"],
        default="markdown", help="Report format (default: markdown)"
    )

    p_report.add_argument("--json", action="store_true", help="Shortcut for --format json")

    # list
    p_list = subparsers.add_parser("list", help="List previous scans")
    p_list.add_argument("--target", help="Filter by target URL")
    p_list.add_argument("--limit", type=int, default=20, help="Max results (default: 20)")
    p_list.add_argument("--json", action="store_true", help="Output as JSON")

    # compare
    p_compare = subparsers.add_parser("compare", help="Compare two scans")
    p_compare.add_argument("scan_a", help="Baseline scan ID (older)")
    p_compare.add_argument("scan_b", help="Current scan ID (newer)")
    p_compare.add_argument("--json", action="store_true", help="Output as JSON")

    # config — config-only scan
    p_config = subparsers.add_parser("config", help="Configuration file audit")
    p_config.add_argument("path", nargs="?", default=None, help="Path to config file or directory")
    p_config.add_argument("--approved-servers", nargs="*", help="Approved server names for shadow detection")
    p_config.add_argument("--json", action="store_true", help="Output as JSON")
    p_config.set_defaults(auditor="config")

    # dependencies — supply chain scan
    p_deps = subparsers.add_parser("dependencies", help="Dependency vulnerability check")
    p_deps.add_argument("path", help="Path to project directory or dependency file")
    p_deps.add_argument("--json", action="store_true", help="Output as JSON")
    p_deps.set_defaults(auditor="dependencies")

    # serve — run as MCP server
    p_serve = subparsers.add_parser("serve", help="Run MCPSec as an MCP server")
    p_serve.add_argument("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
    p_serve.add_argument("--port", type=int, default=8000, help="Port to bind (default: 8000)")
    p_serve.add_argument(
        "--transport", choices=["stdio", "http"],
        default="stdio", help="Transport type (default: stdio for Claude Desktop/Cursor)"
    )


    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        _print_banner()
        parser.print_help()
        sys.exit(0)

    _print_banner()

    # Route to command handler
    if args.command in ("scan", "auth", "transport", "authorization", "tools", "config", "dependencies"):
        exit_code = asyncio.run(_cmd_scan(args))
    elif args.command == "ci":
        exit_code = asyncio.run(_cmd_ci(args))
    elif args.command == "report":
        exit_code = asyncio.run(_cmd_report(args))
    elif args.command == "list":
        exit_code = asyncio.run(_cmd_list(args))
    elif args.command == "compare":
        exit_code = asyncio.run(_cmd_compare(args))
    elif args.command == "serve":
        _cmd_serve(args)
        exit_code = 0

    else:
        parser.print_help()
        exit_code = 0

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
