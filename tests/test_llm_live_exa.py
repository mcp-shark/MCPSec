"""MCPSec — Live LLM + Exa MCP server integration tests.

Tests MCPSec auditors against Exa's real hosted MCP server at
https://mcp.exa.ai/mcp — validates scanner behavior against a
production MCP deployment.

Requires:
    - Network access to mcp.exa.ai
    - ANTHROPIC_API_KEY for LLM classification tests

Run with:
    pytest tests/test_llm_live_exa.py -v
    pytest -m exa -v  (runs only Exa tests)
"""

from __future__ import annotations

import pytest
import httpx

from mcpsec.scanner.auth import AuthAuditor
from mcpsec.scanner.transport import TransportAuditor
from mcpsec.scanner.tools import ToolsAuditor
from mcpsec.scanner.authorization import AuthorizationAuditor
from mcpsec.llm.classifier import (
    ClassificationType,
    ClassificationVerdict,
    HybridClassifier,
    LiteLLMProvider,
)
from mcpsec.models.findings import AccessLevel, Severity


# ---------------------------------------------------------------------------
# Markers and skip conditions
# ---------------------------------------------------------------------------

pytestmark = pytest.mark.exa

EXA_URL = "https://mcp.exa.ai"
EXA_MCP_URL = f"{EXA_URL}/mcp"
TIMEOUT = httpx.Timeout(30.0, connect=10.0)


def _can_reach_exa() -> bool:
    """Check if Exa is reachable before running tests."""
    try:
        r = httpx.get(EXA_URL, timeout=5.0, follow_redirects=True)
        return r.status_code < 500
    except Exception:
        return False


if not _can_reach_exa():
    pytest.skip("Cannot reach mcp.exa.ai", allow_module_level=True)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding_ids(findings) -> set[str]:
    return {f.finding_id for f in findings}


def _has_llm() -> bool:
    return LiteLLMProvider().is_available()


# ==================================================================
# Auth auditor against Exa
# ==================================================================

class TestExaAuth:
    """Auth checks against Exa's production MCP server."""

    @pytest.mark.asyncio
    async def test_https_no_finding(self):
        """Exa uses HTTPS — AUTH-004 should NOT fire."""
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
            auditor = AuthAuditor(target_url=EXA_URL, http_client=client)
            findings = await auditor.audit()
        assert "MCP-AUTH-004" not in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_protected_resource_metadata(self):
        """Exa likely lacks /.well-known/oauth-protected-resource → AUTH-001."""
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
            auditor = AuthAuditor(target_url=EXA_URL, http_client=client)
            findings = await auditor.audit()
        ids = _finding_ids(findings)
        # Record what we find — Exa may or may not have this
        if "MCP-AUTH-001" in ids:
            f = next(f for f in findings if f.finding_id == "MCP-AUTH-001")
            assert f.severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_as_metadata(self):
        """Check if Exa has AS metadata — expect AUTH-006 if missing."""
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
            auditor = AuthAuditor(target_url=EXA_URL, http_client=client)
            findings = await auditor.audit()
        ids = _finding_ids(findings)
        if "MCP-AUTH-006" in ids:
            f = next(f for f in findings if f.finding_id == "MCP-AUTH-006")
            assert f.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_findings_are_valid(self):
        """All findings have required fields populated."""
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
            auditor = AuthAuditor(target_url=EXA_URL, http_client=client)
            findings = await auditor.audit()
        for f in findings:
            assert f.finding_id.startswith("MCP-AUTH-")
            assert f.evidence
            assert f.recommendation
            assert len(f.standards) > 0


# ==================================================================
# Transport auditor against Exa
# ==================================================================

class TestExaTransport:
    """Transport checks against Exa's production server."""

    @pytest.mark.asyncio
    async def test_no_sse_on_modern_server(self):
        """Exa likely uses Streamable HTTP, not deprecated SSE."""
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
            auditor = TransportAuditor(target_url=EXA_URL, http_client=client)
            findings = await auditor.audit()
        # Don't assert absence — just validate if present
        for f in findings:
            assert f.finding_id.startswith("MCP-TRANS-")

    @pytest.mark.asyncio
    async def test_no_ssrf_in_metadata(self):
        """Exa's metadata URLs (if any) should not point to private IPs."""
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
            auditor = TransportAuditor(target_url=EXA_URL, http_client=client)
            findings = await auditor.audit()
        assert "MCP-TRANS-002" not in _finding_ids(findings)


# ==================================================================
# Tools auditor — rule-based against Exa
# ==================================================================

class TestExaToolsRuleBased:
    """Tool introspection against Exa's real tools."""

    @pytest.mark.asyncio
    async def test_can_retrieve_tools(self):
        """Verify we can introspect Exa's tools/list."""
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
            auditor = ToolsAuditor(target_url=EXA_URL, http_client=client)
            tools = await auditor._get_tools_list()
        assert tools is not None
        assert len(tools) >= 2  # at least web_search_exa + get_code_context_exa

    @pytest.mark.asyncio
    async def test_tool_names_present(self):
        """Exa exposes known tool names."""
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
            auditor = ToolsAuditor(target_url=EXA_URL, http_client=client)
            tools = await auditor._get_tools_list()
        names = {t.get("name") for t in tools}
        assert "web_search_exa" in names

    @pytest.mark.asyncio
    async def test_no_poisoning_findings(self):
        """Exa's descriptions should be clean — no rule-based poisoning."""
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
            auditor = ToolsAuditor(target_url=EXA_URL, http_client=client)
            findings = await auditor.audit()
        assert "MCP-TOOL-001" not in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_no_dangerous_names(self):
        """Exa tool names should not match dangerous patterns."""
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
            auditor = ToolsAuditor(target_url=EXA_URL, http_client=client)
            findings = await auditor.audit()
        assert "MCP-TOOL-005" not in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_schema_findings(self):
        """Check if Exa has unconstrained sensitive params (TOOL-004)."""
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
            auditor = ToolsAuditor(target_url=EXA_URL, http_client=client)
            findings = await auditor.audit()
        # Report what we find — Exa may or may not have constraints
        tool_004 = [f for f in findings if f.finding_id == "MCP-TOOL-004"]
        if tool_004:
            assert tool_004[0].severity == Severity.HIGH


# ==================================================================
# Tools auditor — LLM classification against Exa
# ==================================================================

class TestExaToolsLLM:
    """LLM semantic analysis of Exa's real tool descriptions."""

    @pytest.fixture(autouse=True)
    def skip_without_llm(self):
        if not _has_llm():
            pytest.skip("No LLM API key available")

    @pytest.mark.asyncio
    async def test_llm_classifies_exa_tools_clean(self):
        """LLM should classify Exa's legitimate tools as clean."""
        classifier = HybridClassifier(provider=LiteLLMProvider())
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
            auditor = ToolsAuditor(
                target_url=EXA_URL,
                http_client=client,
                classifier=classifier,
            )
            findings = await auditor.audit()

        llm_poisoning = [
            f for f in findings
            if f.finding_id == "MCP-TOOL-001" and "LLM" in f.title
        ]
        assert len(llm_poisoning) == 0, (
            f"LLM false-positived on Exa tools: "
            f"{[f.evidence[:100] for f in llm_poisoning]}"
        )

    @pytest.mark.asyncio
    async def test_llm_no_dangerous_names(self):
        """LLM should not flag Exa's tool names as dangerous."""
        classifier = HybridClassifier(provider=LiteLLMProvider())
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
            auditor = ToolsAuditor(
                target_url=EXA_URL,
                http_client=client,
                classifier=classifier,
            )
            findings = await auditor.audit()

        llm_names = [
            f for f in findings
            if f.finding_id == "MCP-TOOL-005" and "LLM" in f.title
        ]
        assert len(llm_names) == 0

    @pytest.mark.asyncio
    async def test_direct_classification_web_search(self):
        """Directly classify Exa's web_search_exa tool description."""
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
            auditor = ToolsAuditor(target_url=EXA_URL, http_client=client)
            tools = await auditor._get_tools_list()

        web_search = next(
            (t for t in tools if t.get("name") == "web_search_exa"), None
        )
        assert web_search is not None

        classifier = HybridClassifier(provider=LiteLLMProvider())
        batch = await classifier.classify_tools(
            tools=[web_search],
            rule_flagged_names=set(),
            classification_type=ClassificationType.TOOL_POISONING,
        )
        assert len(batch.results) == 1
        assert batch.results[0].verdict == ClassificationVerdict.CLEAN
        assert batch.total_tokens > 0


# ==================================================================
# Full scan summary
# ==================================================================

class TestExaFullScan:
    """Run all applicable auditors and summarize."""

    @pytest.mark.asyncio
    async def test_full_remote_scan(self):
        """Smoke test — full remote scan completes without errors."""
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
            all_findings = []
            for auditor_cls in [AuthAuditor, TransportAuditor, ToolsAuditor]:
                auditor = auditor_cls(
                    target_url=EXA_URL,
                    http_client=client,
                    access_level=AccessLevel.REMOTE,
                )
                findings = await auditor.audit()
                all_findings.extend(findings)

        # Just verify we got findings and they're well-formed
        assert len(all_findings) > 0
        for f in all_findings:
            assert f.finding_id.startswith("MCP-")
            assert f.severity in list(Severity)
            assert f.evidence
            assert len(f.standards) > 0

    @pytest.mark.asyncio
    async def test_print_scan_summary(self, capsys):
        """Print a summary of findings for manual review."""
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=True) as client:
            all_findings = []
            for auditor_cls in [AuthAuditor, TransportAuditor, ToolsAuditor]:
                auditor = auditor_cls(
                    target_url=EXA_URL,
                    http_client=client,
                    access_level=AccessLevel.REMOTE,
                )
                findings = await auditor.audit()
                all_findings.extend(findings)

        print(f"\n{'='*60}")
        print(f"MCPSec scan of {EXA_URL}")
        print(f"Total findings: {len(all_findings)}")
        print(f"{'='*60}")
        for f in sorted(all_findings, key=lambda x: x.cvss_score, reverse=True):
            print(f"  [{f.severity.value.upper():8s}] {f.finding_id}: {f.title} (CVSS {f.cvss_score})")
        print(f"{'='*60}")
