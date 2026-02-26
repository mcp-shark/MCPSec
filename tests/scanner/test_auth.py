"""MCPSec — Auth auditor integration tests.

Tests AuthAuditor against compliant and non-compliant test servers.

Endpoint checks (M1):
    AUTH-001  Protected Resource Metadata missing
    AUTH-004  Remote server over HTTP (no TLS)
    AUTH-005  PKCE not supported
    AUTH-006  Authorization Server Metadata missing
    AUTH-008  Bearer token in URI query string
    AUTH-012  No registration mechanism

Active checks (M2):
    AUTH-003  Audience binding not enforced
"""

from __future__ import annotations

import pytest
import httpx

from mcpsec.scanner.auth import AuthAuditor
from mcpsec.models.findings import AccessLevel, Confidence, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding_ids(findings) -> set[str]:
    return {f.finding_id for f in findings}


async def _run_auth_audit(
    url: str,
    access_level: AccessLevel = AccessLevel.REMOTE,
    test_token: str | None = None,
) -> list:
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(10.0, connect=5.0), follow_redirects=True
    ) as client:
        auditor = AuthAuditor(
            target_url=url,
            http_client=client,
            access_level=access_level,
            test_token=test_token,
        )
        return await auditor.audit()


# ==================================================================
# Endpoint checks — compliant server (expect zero findings)
# ==================================================================

class TestAuthEndpointCompliant:
    """Compliant server satisfies all endpoint requirements."""

    @pytest.mark.asyncio
    async def test_no_endpoint_findings(self, compliant_url):
        findings = await _run_auth_audit(compliant_url)
        assert len(findings) == 0, f"Unexpected: {_finding_ids(findings)}"

    @pytest.mark.asyncio
    async def test_auth_001_not_triggered(self, compliant_url):
        """Valid /.well-known/oauth-protected-resource with authorization_servers."""
        findings = await _run_auth_audit(compliant_url)
        assert "MCP-AUTH-001" not in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_auth_004_localhost_exempt(self, compliant_url):
        """Localhost is exempt from HTTPS requirement per spec."""
        findings = await _run_auth_audit(compliant_url)
        assert "MCP-AUTH-004" not in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_auth_005_pkce_s256_present(self, compliant_url):
        """AS metadata includes code_challenge_methods_supported: ['S256']."""
        findings = await _run_auth_audit(compliant_url)
        assert "MCP-AUTH-005" not in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_auth_006_as_metadata_present(self, compliant_url):
        """Valid /.well-known/oauth-authorization-server endpoint."""
        findings = await _run_auth_audit(compliant_url)
        assert "MCP-AUTH-006" not in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_auth_012_registration_present(self, compliant_url):
        """AS metadata has registration_endpoint + CIMD support."""
        findings = await _run_auth_audit(compliant_url)
        assert "MCP-AUTH-012" not in _finding_ids(findings)


# ==================================================================
# Endpoint checks — non-compliant server
# ==================================================================

class TestAuthEndpointNonCompliant:
    """Non-compliant server triggers AUTH-005 (no PKCE) and AUTH-012 (no registration)."""

    @pytest.mark.asyncio
    async def test_auth_005_no_pkce(self, non_compliant_url):
        """AS metadata missing code_challenge_methods_supported entirely."""
        findings = await _run_auth_audit(non_compliant_url)
        assert "MCP-AUTH-005" in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_auth_005_severity_critical(self, non_compliant_url):
        findings = await _run_auth_audit(non_compliant_url)
        f = next(f for f in findings if f.finding_id == "MCP-AUTH-005")
        assert f.severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_auth_005_cwe(self, non_compliant_url):
        findings = await _run_auth_audit(non_compliant_url)
        f = next(f for f in findings if f.finding_id == "MCP-AUTH-005")
        assert f.cwe_id == "CWE-345"

    @pytest.mark.asyncio
    async def test_auth_012_no_registration(self, non_compliant_url):
        """AS metadata missing registration_endpoint and CIMD."""
        findings = await _run_auth_audit(non_compliant_url)
        assert "MCP-AUTH-012" in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_auth_001_metadata_still_valid(self, non_compliant_url):
        """Non-compliant server HAS protected resource metadata (just weak)."""
        findings = await _run_auth_audit(non_compliant_url)
        assert "MCP-AUTH-001" not in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_auth_004_localhost_still_exempt(self, non_compliant_url):
        findings = await _run_auth_audit(non_compliant_url)
        assert "MCP-AUTH-004" not in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_auth_006_as_metadata_valid(self, non_compliant_url):
        """Non-compliant server has valid AS metadata (just missing fields)."""
        findings = await _run_auth_audit(non_compliant_url)
        assert "MCP-AUTH-006" not in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_expected_finding_count(self, non_compliant_url):
        """Exactly AUTH-005 and AUTH-012 at endpoint level."""
        findings = await _run_auth_audit(non_compliant_url)
        ids = _finding_ids(findings)
        assert ids == {"MCP-AUTH-005", "MCP-AUTH-012"}


# ==================================================================
# AUTH-004 — HTTPS structural check (no server needed)
# ==================================================================

class TestAuthHttpsCheck:
    """AUTH-004 fires for non-localhost HTTP URLs."""

    @pytest.mark.asyncio
    async def test_http_non_localhost_triggers(self):
        findings = await _run_auth_audit("http://mcp.example.com")
        assert "MCP-AUTH-004" in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_http_non_localhost_severity(self):
        findings = await _run_auth_audit("http://mcp.example.com")
        f = next(f for f in findings if f.finding_id == "MCP-AUTH-004")
        assert f.severity == Severity.CRITICAL

    @pytest.mark.asyncio
    async def test_https_non_localhost_clean(self):
        findings = await _run_auth_audit("https://mcp.example.com")
        assert "MCP-AUTH-004" not in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_localhost_127_exempt(self):
        findings = await _run_auth_audit("http://127.0.0.1:9999")
        assert "MCP-AUTH-004" not in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_localhost_name_exempt(self):
        findings = await _run_auth_audit("http://localhost:9999")
        assert "MCP-AUTH-004" not in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_ipv6_loopback_exempt(self):
        findings = await _run_auth_audit("http://[::1]:9999")
        assert "MCP-AUTH-004" not in _finding_ids(findings)


# ==================================================================
# AUTH-008 — Token in query string (structural check)
# ==================================================================

class TestAuthTokenInQueryString:
    """AUTH-008 detects bearer tokens in URL query parameters."""

    @pytest.mark.asyncio
    async def test_access_token_param(self):
        findings = await _run_auth_audit("http://127.0.0.1:9999?access_token=secret")
        assert "MCP-AUTH-008" in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_token_param(self):
        findings = await _run_auth_audit("http://127.0.0.1:9999?token=abc")
        assert "MCP-AUTH-008" in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_bearer_token_param(self):
        findings = await _run_auth_audit("http://127.0.0.1:9999?bearer_token=xyz")
        assert "MCP-AUTH-008" in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_auth_token_param(self):
        findings = await _run_auth_audit("http://127.0.0.1:9999?auth_token=t")
        assert "MCP-AUTH-008" in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_clean_url(self, compliant_url):
        findings = await _run_auth_audit(compliant_url)
        assert "MCP-AUTH-008" not in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_unrelated_query_param(self):
        findings = await _run_auth_audit("http://127.0.0.1:9999?page=2")
        assert "MCP-AUTH-008" not in _finding_ids(findings)


# ==================================================================
# Active checks — AUTH-003 (audience binding)
# ==================================================================

class TestAuthAudienceBinding:
    """AUTH-003 active check.

    The auditor tampers the JWT payload to change the aud claim, which
    invalidates the HMAC signature. Both test servers verify signatures,
    so the tampered token is rejected by both. AUTH-003 fires only when
    the server accepts a token with wrong audience AND valid signature
    (e.g. opaque tokens, forwarded tokens, or separate signing keys).
    """

    @pytest.mark.asyncio
    async def test_compliant_no_finding(self, compliant_url, compliant_token):
        """Compliant server validates aud — tampered token rejected."""
        findings = await _run_auth_audit(
            compliant_url,
            access_level=AccessLevel.AUTHENTICATED,
            test_token=compliant_token,
        )
        assert "MCP-AUTH-003" not in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_non_compliant_tampered_still_rejected(
        self, non_compliant_url, non_compliant_token
    ):
        """Non-compliant skips aud check, but HMAC signature still verified.

        The tampered payload breaks the signature before the aud check
        matters — AUTH-003 cannot fire with HMAC-signed test tokens.
        """
        findings = await _run_auth_audit(
            non_compliant_url,
            access_level=AccessLevel.AUTHENTICATED,
            test_token=non_compliant_token,
        )
        assert "MCP-AUTH-003" not in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_endpoint_findings_still_present_in_authenticated_mode(
        self, non_compliant_url, non_compliant_token
    ):
        """Authenticated mode includes endpoint checks too."""
        findings = await _run_auth_audit(
            non_compliant_url,
            access_level=AccessLevel.AUTHENTICATED,
            test_token=non_compliant_token,
        )
        assert "MCP-AUTH-005" in _finding_ids(findings)
        assert "MCP-AUTH-012" in _finding_ids(findings)


# ==================================================================
# Edge cases
# ==================================================================

class TestAuthEdgeCases:
    """Auditor edge cases."""

    @pytest.mark.asyncio
    async def test_no_target_url_returns_empty(self):
        auditor = AuthAuditor(target_url=None)
        findings = await auditor.audit()
        assert findings == []

    @pytest.mark.asyncio
    async def test_empty_target_url_returns_empty(self):
        auditor = AuthAuditor(target_url="")
        findings = await auditor.audit()
        assert findings == []

    @pytest.mark.asyncio
    async def test_active_checks_skipped_at_remote_level(
        self, compliant_url, compliant_token
    ):
        """REMOTE access level does not run active checks even if token provided."""
        findings = await _run_auth_audit(
            compliant_url,
            access_level=AccessLevel.REMOTE,
            test_token=compliant_token,
        )
        # Should only have endpoint findings (none for compliant)
        assert len(findings) == 0
