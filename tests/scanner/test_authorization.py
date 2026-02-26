"""MCPSec — Authorization auditor integration tests.

Tests AuthorizationAuditor against compliant and non-compliant test servers.

Introspection checks (M1):
    AUTHZ-002  No per-tool scope requirements
    AUTHZ-003  Wildcard or overly broad scope definitions

Active checks (M2):
    AUTHZ-001  Admin/privileged tool without authorization check
    AUTHZ-004  Privilege escalation via scope manipulation
"""

from __future__ import annotations

import pytest
import httpx

from mcpsec.scanner.authorization import (
    AuthorizationAuditor,
    _BROAD_SCOPE_PATTERNS,
    _PRIVILEGED_TOOL_PATTERNS,
    _WILDCARD_SCOPE_PATTERNS,
)
from mcpsec.models.findings import AccessLevel, Confidence, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding_ids(findings) -> set[str]:
    return {f.finding_id for f in findings}


async def _run_authz_audit(
    url: str,
    access_level: AccessLevel = AccessLevel.REMOTE,
    test_token: str | None = None,
) -> list:
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(10.0, connect=5.0), follow_redirects=True
    ) as client:
        auditor = AuthorizationAuditor(
            target_url=url,
            http_client=client,
            access_level=access_level,
            test_token=test_token,
        )
        return await auditor.audit()


# ==================================================================
# Introspection checks — compliant server
# ==================================================================

class TestAuthzIntrospectionCompliant:
    """Compliant server has scopes + privileged tools.

    AUTHZ-002 fires at MEDIUM confidence because per-tool scope binding
    cannot be verified via introspection alone (scopes exist but we can't
    confirm they're enforced per-tool without active probing).

    AUTHZ-003 fires because 'admin' matches the broad scope pattern.
    """

    @pytest.mark.asyncio
    async def test_authz_002_medium_confidence(self, compliant_url):
        findings = await _run_authz_audit(compliant_url)
        authz_002 = [f for f in findings if f.finding_id == "MCP-AUTHZ-002"]
        assert len(authz_002) == 1
        assert authz_002[0].confidence == Confidence.MEDIUM

    @pytest.mark.asyncio
    async def test_authz_003_broad_admin_scope(self, compliant_url):
        """'admin' in scopes_supported matches broad scope pattern."""
        findings = await _run_authz_audit(compliant_url)
        assert "MCP-AUTHZ-003" in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_introspection_finding_count(self, compliant_url):
        findings = await _run_authz_audit(compliant_url)
        assert len(findings) == 2  # AUTHZ-002 + AUTHZ-003


# ==================================================================
# Introspection checks — non-compliant server
# ==================================================================

class TestAuthzIntrospectionNonCompliant:
    """Non-compliant server also has scopes (from AS metadata fallback).

    Produces the same introspection findings as compliant — the difference
    only appears in active checks where scope enforcement is tested.
    """

    @pytest.mark.asyncio
    async def test_authz_002_flagged(self, non_compliant_url):
        findings = await _run_authz_audit(non_compliant_url)
        assert "MCP-AUTHZ-002" in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_authz_003_flagged(self, non_compliant_url):
        findings = await _run_authz_audit(non_compliant_url)
        assert "MCP-AUTHZ-003" in _finding_ids(findings)


# ==================================================================
# Active checks — compliant server (scope enforcement works)
# ==================================================================

class TestAuthzActiveCompliant:
    """Compliant server enforces per-tool scopes.

    Read-only token is rejected by admin_delete (403) and write_data (403).
    No active findings should fire.
    """

    @pytest.mark.asyncio
    async def test_authz_001_not_triggered(self, compliant_url, compliant_read_token):
        """admin_delete rejects read-only token with 403."""
        findings = await _run_authz_audit(
            compliant_url,
            access_level=AccessLevel.AUTHENTICATED,
            test_token=compliant_read_token,
        )
        assert "MCP-AUTHZ-001" not in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_authz_004_not_triggered(self, compliant_url, compliant_read_token):
        """write_data and admin_delete both reject read-only token."""
        findings = await _run_authz_audit(
            compliant_url,
            access_level=AccessLevel.AUTHENTICATED,
            test_token=compliant_read_token,
        )
        assert "MCP-AUTHZ-004" not in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_introspection_findings_still_present(
        self, compliant_url, compliant_read_token
    ):
        """Authenticated mode still runs introspection checks."""
        findings = await _run_authz_audit(
            compliant_url,
            access_level=AccessLevel.AUTHENTICATED,
            test_token=compliant_read_token,
        )
        assert "MCP-AUTHZ-002" in _finding_ids(findings)
        assert "MCP-AUTHZ-003" in _finding_ids(findings)


# ==================================================================
# Active checks — non-compliant server (no scope enforcement)
# ==================================================================

class TestAuthzActiveNonCompliant:
    """Non-compliant server has NO per-tool scope enforcement.

    Read-only token can invoke admin_delete and write_data → both
    AUTHZ-001 and AUTHZ-004 fire.
    """

    @pytest.mark.asyncio
    async def test_authz_001_admin_unprotected(
        self, non_compliant_url, non_compliant_read_token
    ):
        """admin_delete accepts read-only token → AUTHZ-001."""
        findings = await _run_authz_audit(
            non_compliant_url,
            access_level=AccessLevel.AUTHENTICATED,
            test_token=non_compliant_read_token,
        )
        assert "MCP-AUTHZ-001" in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_authz_001_severity_critical(
        self, non_compliant_url, non_compliant_read_token
    ):
        findings = await _run_authz_audit(
            non_compliant_url,
            access_level=AccessLevel.AUTHENTICATED,
            test_token=non_compliant_read_token,
        )
        f = next(f for f in findings if f.finding_id == "MCP-AUTHZ-001")
        assert f.severity == Severity.CRITICAL
        assert f.cvss_score >= 9.0

    @pytest.mark.asyncio
    async def test_authz_004_scope_escalation(
        self, non_compliant_url, non_compliant_read_token
    ):
        """Read token invokes write_data + admin_delete → AUTHZ-004."""
        findings = await _run_authz_audit(
            non_compliant_url,
            access_level=AccessLevel.AUTHENTICATED,
            test_token=non_compliant_read_token,
        )
        assert "MCP-AUTHZ-004" in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_authz_004_evidence_mentions_tools(
        self, non_compliant_url, non_compliant_read_token
    ):
        findings = await _run_authz_audit(
            non_compliant_url,
            access_level=AccessLevel.AUTHENTICATED,
            test_token=non_compliant_read_token,
        )
        f = next(f for f in findings if f.finding_id == "MCP-AUTHZ-004")
        assert "write_data" in f.evidence
        assert "admin_delete" in f.evidence

    @pytest.mark.asyncio
    async def test_all_active_findings_present(
        self, non_compliant_url, non_compliant_read_token
    ):
        """Non-compliant server triggers all four authorization findings."""
        findings = await _run_authz_audit(
            non_compliant_url,
            access_level=AccessLevel.AUTHENTICATED,
            test_token=non_compliant_read_token,
        )
        ids = _finding_ids(findings)
        assert "MCP-AUTHZ-001" in ids
        assert "MCP-AUTHZ-002" in ids
        assert "MCP-AUTHZ-003" in ids
        assert "MCP-AUTHZ-004" in ids


# ==================================================================
# Wildcard/broad scope detection — unit tests
# ==================================================================

class TestWildcardScopeDetection:
    """Unit tests for _check_wildcard_scopes."""

    @pytest.fixture
    def auditor(self):
        return AuthorizationAuditor(target_url="http://127.0.0.1:9999")

    def test_wildcard_star(self, auditor):
        auditor._clear_findings()
        auditor._check_wildcard_scopes(["*", "read"])
        assert any(f.finding_id == "MCP-AUTHZ-003" for f in auditor._findings)

    def test_wildcard_admin_star(self, auditor):
        auditor._clear_findings()
        auditor._check_wildcard_scopes(["admin:*", "read"])
        assert any(f.finding_id == "MCP-AUTHZ-003" for f in auditor._findings)

    def test_broad_full_access(self, auditor):
        auditor._clear_findings()
        auditor._check_wildcard_scopes(["full_access", "read"])
        assert any(f.finding_id == "MCP-AUTHZ-003" for f in auditor._findings)

    def test_broad_readwrite(self, auditor):
        auditor._clear_findings()
        auditor._check_wildcard_scopes(["read_write"])
        assert any(f.finding_id == "MCP-AUTHZ-003" for f in auditor._findings)

    def test_granular_scopes_clean(self, auditor):
        auditor._clear_findings()
        auditor._check_wildcard_scopes(["files:read", "files:write", "users:read"])
        assert not any(f.finding_id == "MCP-AUTHZ-003" for f in auditor._findings)

    def test_empty_scopes_clean(self, auditor):
        auditor._clear_findings()
        auditor._check_wildcard_scopes([])
        assert len(auditor._findings) == 0


# ==================================================================
# Privileged tool detection — unit tests
# ==================================================================

class TestPrivilegedToolDetection:
    """Unit tests for privileged tool pattern matching."""

    @pytest.fixture
    def auditor(self):
        return AuthorizationAuditor(target_url="http://127.0.0.1:9999")

    def test_admin_tool_flagged(self, auditor):
        tools = [{"name": "admin_delete", "description": "Delete records"}]
        auditor._clear_findings()
        auditor._check_per_tool_scopes(tools, None)
        assert any(f.finding_id == "MCP-AUTHZ-002" for f in auditor._findings)

    def test_admin_in_description_flagged(self, auditor):
        tools = [{"name": "cleanup", "description": "Admin tool to remove stale data"}]
        auditor._clear_findings()
        auditor._check_per_tool_scopes(tools, None)
        assert any(f.finding_id == "MCP-AUTHZ-002" for f in auditor._findings)

    def test_safe_tools_no_finding(self, auditor):
        tools = [
            {"name": "get_weather", "description": "Get weather forecast"},
            {"name": "list_items", "description": "List catalog items"},
        ]
        auditor._clear_findings()
        auditor._check_per_tool_scopes(tools, None)
        assert not any(f.finding_id == "MCP-AUTHZ-002" for f in auditor._findings)

    def test_privileged_with_scopes_medium_confidence(self, auditor):
        tools = [{"name": "admin_delete", "description": "Delete"}]
        auditor._clear_findings()
        auditor._check_per_tool_scopes(tools, ["read", "write", "admin"])
        authz_002 = [f for f in auditor._findings if f.finding_id == "MCP-AUTHZ-002"]
        assert len(authz_002) == 1
        assert authz_002[0].confidence == Confidence.MEDIUM

    def test_privileged_without_scopes_high_confidence(self, auditor):
        tools = [{"name": "admin_delete", "description": "Delete"}]
        auditor._clear_findings()
        auditor._check_per_tool_scopes(tools, None)
        authz_002 = [f for f in auditor._findings if f.finding_id == "MCP-AUTHZ-002"]
        assert len(authz_002) == 1
        assert authz_002[0].confidence == Confidence.HIGH


# ==================================================================
# Regex pattern coverage
# ==================================================================

class TestRegexPatterns:
    """Verify regex patterns catch expected tool names."""

    @pytest.mark.parametrize("name", [
        "admin_panel", "delete_user", "remove_record", "drop_table",
        "destroy_session", "execute_query", "exec_cmd", "eval_code",
        "sudo_action", "shell_command", "deploy_service", "purge_cache",
        "reset_password", "grant_access", "revoke_token", "impersonate_user",
    ])
    def test_privileged_patterns_match(self, name):
        assert _PRIVILEGED_TOOL_PATTERNS.search(name) is not None

    @pytest.mark.parametrize("name", [
        "get_weather", "list_items", "read_file", "search_docs",
        "format_text", "calculate_sum",
    ])
    def test_safe_names_no_match(self, name):
        assert _PRIVILEGED_TOOL_PATTERNS.search(name) is None

    @pytest.mark.parametrize("scope", ["*", "all", "admin:*", "full_access", "superuser", "root"])
    def test_wildcard_scope_patterns(self, scope):
        assert _WILDCARD_SCOPE_PATTERNS.match(scope) is not None

    @pytest.mark.parametrize("scope", ["admin", "full", "read_write", "manage", "all_access"])
    def test_broad_scope_patterns(self, scope):
        assert _BROAD_SCOPE_PATTERNS.match(scope) is not None

    @pytest.mark.parametrize("scope", ["files:read", "users:write", "tools:execute"])
    def test_granular_scope_no_match(self, scope):
        assert _WILDCARD_SCOPE_PATTERNS.match(scope) is None
        assert _BROAD_SCOPE_PATTERNS.match(scope) is None


# ==================================================================
# Edge cases
# ==================================================================

class TestAuthzEdgeCases:

    @pytest.mark.asyncio
    async def test_no_target_url(self):
        auditor = AuthorizationAuditor(target_url=None)
        assert await auditor.audit() == []

    @pytest.mark.asyncio
    async def test_active_skipped_without_token(self, non_compliant_url):
        """Active checks need test_token — should not fire without one."""
        findings = await _run_authz_audit(
            non_compliant_url,
            access_level=AccessLevel.AUTHENTICATED,
            test_token=None,
        )
        assert "MCP-AUTHZ-001" not in _finding_ids(findings)
        assert "MCP-AUTHZ-004" not in _finding_ids(findings)
