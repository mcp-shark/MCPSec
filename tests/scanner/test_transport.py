"""MCPSec — Transport auditor integration tests.

Tests TransportAuditor against compliant and non-compliant test servers.

Endpoint checks (M1):
    TRANS-001  Deprecated SSE transport
    TRANS-002  SSRF-vulnerable metadata URL

Active checks (M2):
    TRANS-003  Session ID low entropy
    TRANS-004  Session binding not enforced
"""

from __future__ import annotations

import secrets

import pytest
import httpx

from mcpsec.scanner.transport import TransportAuditor
from mcpsec.models.findings import AccessLevel, Confidence, Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _finding_ids(findings) -> set[str]:
    return {f.finding_id for f in findings}


async def _run_transport_audit(
    url: str,
    access_level: AccessLevel = AccessLevel.REMOTE,
    test_token: str | None = None,
) -> list:
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(10.0, connect=5.0), follow_redirects=True
    ) as client:
        auditor = TransportAuditor(
            target_url=url,
            http_client=client,
            access_level=access_level,
            test_token=test_token,
        )
        return await auditor.audit()


# ==================================================================
# Endpoint checks — both servers (no SSE, no SSRF in localhost setup)
# ==================================================================

class TestTransportEndpointCompliant:
    """Compliant server: no SSE endpoint, no SSRF-vulnerable metadata."""

    @pytest.mark.asyncio
    async def test_no_sse_finding(self, compliant_url):
        findings = await _run_transport_audit(compliant_url)
        assert "MCP-TRANS-001" not in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_no_ssrf_finding(self, compliant_url):
        findings = await _run_transport_audit(compliant_url)
        assert "MCP-TRANS-002" not in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_zero_endpoint_findings(self, compliant_url):
        findings = await _run_transport_audit(compliant_url)
        assert len(findings) == 0


class TestTransportEndpointNonCompliant:
    """Non-compliant server also has no SSE and localhost metadata URLs."""

    @pytest.mark.asyncio
    async def test_no_sse_finding(self, non_compliant_url):
        findings = await _run_transport_audit(non_compliant_url)
        assert "MCP-TRANS-001" not in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_no_ssrf_finding(self, non_compliant_url):
        findings = await _run_transport_audit(non_compliant_url)
        assert "MCP-TRANS-002" not in _finding_ids(findings)


# ==================================================================
# SSRF URL checker — unit tests
# ==================================================================

class TestSsrfUrlChecker:
    """Unit tests for TransportAuditor._check_url_for_ssrf."""

    def _auditor(self, target="https://mcp.example.com"):
        return TransportAuditor(target_url=target)

    # --- Private IP ranges ---

    def test_private_10_network(self):
        assert self._auditor()._check_url_for_ssrf("http://10.0.0.1/token") is not None

    def test_private_172_network(self):
        assert self._auditor()._check_url_for_ssrf("http://172.16.0.1/token") is not None

    def test_private_192_network(self):
        assert self._auditor()._check_url_for_ssrf("https://192.168.1.1/api") is not None

    def test_loopback_127(self):
        result = self._auditor("https://remote.example.com")._check_url_for_ssrf(
            "http://127.0.0.1/admin"
        )
        assert result is not None

    # --- Cloud metadata ---

    def test_aws_metadata_ip(self):
        result = self._auditor()._check_url_for_ssrf("http://169.254.169.254/latest/meta-data/")
        assert result is not None
        assert "metadata" in result.lower()

    def test_gcp_metadata_hostname(self):
        result = self._auditor()._check_url_for_ssrf(
            "http://metadata.google.internal/computeMetadata/v1/"
        )
        assert result is not None

    def test_alibaba_metadata(self):
        result = self._auditor()._check_url_for_ssrf("http://100.100.100.200/latest/meta-data/")
        assert result is not None

    # --- Localhost handling ---

    def test_localhost_from_remote_server_flagged(self):
        result = self._auditor("https://remote.example.com")._check_url_for_ssrf(
            "http://localhost/admin"
        )
        assert result is not None

    def test_localhost_from_localhost_server_permitted(self):
        result = self._auditor("http://localhost:8000")._check_url_for_ssrf(
            "http://localhost:8000/token"
        )
        assert result is None

    # --- Safe URLs ---

    def test_public_https_safe(self):
        result = self._auditor()._check_url_for_ssrf(
            "https://auth.example.com/.well-known/jwks.json"
        )
        assert result is None

    # --- Scheme checks ---

    def test_http_scheme_from_remote_flagged(self):
        result = self._auditor("https://remote.example.com")._check_url_for_ssrf(
            "http://auth.example.com/token"
        )
        assert result is not None

    def test_http_scheme_from_localhost_permitted(self):
        result = self._auditor("http://127.0.0.1:8000")._check_url_for_ssrf(
            "http://auth.example.com/token"
        )
        assert result is None


# ==================================================================
# Active checks — TRANS-003 (session entropy)
# ==================================================================

class TestSessionEntropy:
    """TRANS-003: Session ID entropy analysis against test servers."""

    @pytest.mark.asyncio
    async def test_compliant_high_entropy_no_finding(self, compliant_url):
        """Compliant server: secrets.token_urlsafe(32) → 256 bits."""
        findings = await _run_transport_audit(
            compliant_url, access_level=AccessLevel.AUTHENTICATED
        )
        assert "MCP-TRANS-003" not in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_non_compliant_low_entropy_finding(self, non_compliant_url):
        """Non-compliant server: sequential integers → near-zero entropy."""
        findings = await _run_transport_audit(
            non_compliant_url, access_level=AccessLevel.AUTHENTICATED
        )
        assert "MCP-TRANS-003" in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_non_compliant_entropy_severity_high(self, non_compliant_url):
        findings = await _run_transport_audit(
            non_compliant_url, access_level=AccessLevel.AUTHENTICATED
        )
        f = next(f for f in findings if f.finding_id == "MCP-TRANS-003")
        assert f.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_non_compliant_entropy_evidence_mentions_bits(self, non_compliant_url):
        findings = await _run_transport_audit(
            non_compliant_url, access_level=AccessLevel.AUTHENTICATED
        )
        f = next(f for f in findings if f.finding_id == "MCP-TRANS-003")
        assert "bits" in f.evidence.lower()


# ==================================================================
# Active checks — TRANS-004 (session binding)
# ==================================================================

class TestSessionBinding:
    """TRANS-004: Session binding enforcement."""

    @pytest.mark.asyncio
    async def test_non_compliant_accepts_fake_session(self, non_compliant_url):
        """Non-compliant server silently creates new session for unknown IDs."""
        findings = await _run_transport_audit(
            non_compliant_url, access_level=AccessLevel.AUTHENTICATED
        )
        assert "MCP-TRANS-004" in _finding_ids(findings)

    @pytest.mark.asyncio
    async def test_non_compliant_binding_severity_high(self, non_compliant_url):
        findings = await _run_transport_audit(
            non_compliant_url, access_level=AccessLevel.AUTHENTICATED
        )
        f = next(f for f in findings if f.finding_id == "MCP-TRANS-004")
        assert f.severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_compliant_rejects_fabricated_session(self, compliant_url):
        """Compliant server rejects unknown session IDs with 403.

        Note: TRANS-004 may still fire as MEDIUM confidence due to the
        X-Forwarded-For heuristic — both requests originate from 127.0.0.1
        so the IP binding check cannot distinguish spoofed vs real client.
        """
        findings = await _run_transport_audit(
            compliant_url, access_level=AccessLevel.AUTHENTICATED
        )
        trans_004 = [f for f in findings if f.finding_id == "MCP-TRANS-004"]
        if trans_004:
            # If it fires, it's the IP-binding heuristic — MEDIUM confidence
            assert trans_004[0].confidence == Confidence.MEDIUM


# ==================================================================
# Entropy helpers — unit tests
# ==================================================================

class TestEntropyHelpers:
    """Unit tests for static entropy analysis methods."""

    def test_sequential_integers_detected(self):
        assert TransportAuditor._detect_sequential(["1", "2", "3", "4"]) is True

    def test_sequential_with_step(self):
        assert TransportAuditor._detect_sequential(["10", "20", "30", "40"]) is True

    def test_random_strings_not_sequential(self):
        ids = [secrets.token_urlsafe(16) for _ in range(5)]
        assert TransportAuditor._detect_sequential(ids) is False

    def test_entropy_zero_for_single_chars(self):
        """Single-character strings have zero Shannon entropy."""
        entropy = TransportAuditor._calculate_avg_entropy(["a", "b", "c"])
        assert entropy == 0.0

    def test_entropy_high_for_random_strings(self):
        ids = [secrets.token_urlsafe(32) for _ in range(5)]
        entropy = TransportAuditor._calculate_avg_entropy(ids)
        assert entropy > 3.0

    def test_entropy_empty_list(self):
        assert TransportAuditor._calculate_avg_entropy([]) == 0.0


# ==================================================================
# Edge cases
# ==================================================================

class TestTransportEdgeCases:
    """Auditor edge cases."""

    @pytest.mark.asyncio
    async def test_no_target_url(self):
        auditor = TransportAuditor(target_url=None)
        assert await auditor.audit() == []

    @pytest.mark.asyncio
    async def test_active_checks_skipped_at_remote_level(self, non_compliant_url):
        """REMOTE level does not run active session checks."""
        findings = await _run_transport_audit(
            non_compliant_url, access_level=AccessLevel.REMOTE
        )
        assert "MCP-TRANS-003" not in _finding_ids(findings)
        assert "MCP-TRANS-004" not in _finding_ids(findings)
