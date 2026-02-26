"""MCPSec — Model unit tests.

Tests Pydantic models for correct validation, serialization,
and computed property behavior. These are the foundation —
every scanner, report, and storage operation depends on them.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from mcpsec.models.findings import (
    AccessLevel,
    Auditor,
    Confidence,
    DetectionMode,
    Finding,
    RemediationEffort,
    RemoteHeuristic,
    RequirementLevel,
    ScanDepth,
    ScanResult,
    Severity,
    StandardReference,
)


# ---------------------------------------------------------------------------
# Fixtures — reusable valid model instances
# ---------------------------------------------------------------------------

@pytest.fixture
def valid_standard_ref() -> StandardReference:
    """Minimal valid StandardReference."""
    return StandardReference(
        id="MCP-SPEC-AUTH",
        ref="modelcontextprotocol.io/specification/draft/basic/authorization",
        section="Protected Resource Metadata Discovery",
        requirement_level=RequirementLevel.MUST,
    )


@pytest.fixture
def valid_finding(valid_standard_ref) -> Finding:
    """Minimal valid Finding with all required fields."""
    return Finding(
        finding_id="MCP-AUTH-001",
        title="Protected Resource Metadata Missing",
        auditor=Auditor.AUTH,
        severity=Severity.CRITICAL,
        cvss_score=8.6,
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        cwe_id="CWE-287",
        cwe_name="Improper Authentication",
        detection_mode=DetectionMode.ENDPOINT,
        confidence=Confidence.DEFINITIVE,
        detection_method="HTTP GET to /.well-known/oauth-protected-resource",
        remote_scan_applicable=True,
        standards=[valid_standard_ref],
        evidence="GET /.well-known/oauth-protected-resource — HTTP 404",
        risk="MCP auth discovery chain is broken.",
        recommendation="Serve RFC 9728 compliant metadata.",
        remediation_effort=RemediationEffort.HIGH,
    )


@pytest.fixture
def valid_scan_result(valid_finding) -> ScanResult:
    """Minimal valid ScanResult with one finding."""
    return ScanResult(
        scan_id="scan_20260226_120000_abc123",
        target_url="https://mcp.example.com",
        access_level=AccessLevel.REMOTE,
        depth=ScanDepth.STANDARD,
        spec_version="draft-2025-11-25",
        scanner_version="0.1.0",
        scan_duration_seconds=1.5,
        findings=[valid_finding],
    )


# ==================================================================
# Finding ID validation
# ==================================================================

class TestFindingIdFormat:
    """Finding IDs follow MCP-{AUDITOR}-{NNN} pattern.

    This is a stable identifier used in CI gating, scan comparison,
    and trend tracking. Invalid IDs would break all downstream consumers.
    """

    def test_valid_auth_id(self, valid_finding):
        assert valid_finding.finding_id == "MCP-AUTH-001"

    def test_valid_transport_id(self, valid_standard_ref):
        f = valid_finding_with_id("MCP-TRANS-001", valid_standard_ref)
        assert f.finding_id == "MCP-TRANS-001"

    def test_valid_tool_id(self, valid_standard_ref):
        f = valid_finding_with_id("MCP-TOOL-005", valid_standard_ref)
        assert f.finding_id == "MCP-TOOL-005"

    def test_valid_config_id(self, valid_standard_ref):
        f = valid_finding_with_id("MCP-CONFIG-001", valid_standard_ref)
        assert f.finding_id == "MCP-CONFIG-001"

    def test_valid_supply_chain_id(self, valid_standard_ref):
        f = valid_finding_with_id("MCP-SC-004", valid_standard_ref)
        assert f.finding_id == "MCP-SC-004"

    def test_valid_authz_id(self, valid_standard_ref):
        f = valid_finding_with_id("MCP-AUTHZ-002", valid_standard_ref)
        assert f.finding_id == "MCP-AUTHZ-002"

    def test_rejects_invalid_prefix(self, valid_standard_ref):
        with pytest.raises(ValidationError):
            valid_finding_with_id("INVALID-AUTH-001", valid_standard_ref)

    def test_rejects_unknown_auditor(self, valid_standard_ref):
        with pytest.raises(ValidationError):
            valid_finding_with_id("MCP-UNKNOWN-001", valid_standard_ref)

    def test_rejects_missing_number(self, valid_standard_ref):
        with pytest.raises(ValidationError):
            valid_finding_with_id("MCP-AUTH", valid_standard_ref)

    def test_rejects_non_numeric_suffix(self, valid_standard_ref):
        with pytest.raises(ValidationError):
            valid_finding_with_id("MCP-AUTH-ABC", valid_standard_ref)


# ==================================================================
# CVSS score validation
# ==================================================================

class TestCvssValidation:
    """CVSS scores drive CI gating and severity display.

    Out-of-range scores would break threshold comparisons.
    """

    def test_valid_score(self, valid_finding):
        assert valid_finding.cvss_score == 8.6

    def test_zero_score(self, valid_standard_ref):
        f = valid_finding_with_cvss(0.0, valid_standard_ref)
        assert f.cvss_score == 0.0

    def test_max_score(self, valid_standard_ref):
        f = valid_finding_with_cvss(10.0, valid_standard_ref)
        assert f.cvss_score == 10.0

    def test_rejects_negative_score(self, valid_standard_ref):
        with pytest.raises(ValidationError):
            valid_finding_with_cvss(-1.0, valid_standard_ref)

    def test_rejects_over_ten(self, valid_standard_ref):
        with pytest.raises(ValidationError):
            valid_finding_with_cvss(10.1, valid_standard_ref)


# ==================================================================
# CWE ID validation
# ==================================================================

class TestCweValidation:
    """CWE IDs cross-reference with NVD and MITRE."""

    def test_valid_cwe(self, valid_finding):
        assert valid_finding.cwe_id == "CWE-287"

    def test_rejects_invalid_cwe_format(self, valid_standard_ref):
        with pytest.raises(ValidationError):
            valid_finding_with_cwe("287", valid_standard_ref)

    def test_rejects_cwe_no_number(self, valid_standard_ref):
        with pytest.raises(ValidationError):
            valid_finding_with_cwe("CWE-", valid_standard_ref)


# ==================================================================
# Standards — at least one required
# ==================================================================

class TestStandardsValidation:
    """Every finding must map to at least one standard."""

    def test_valid_single_standard(self, valid_finding):
        assert len(valid_finding.standards) == 1

    def test_rejects_empty_standards(self):
        with pytest.raises(ValidationError):
            Finding(
                finding_id="MCP-AUTH-001",
                title="Test",
                auditor=Auditor.AUTH,
                severity=Severity.CRITICAL,
                cvss_score=8.0,
                cwe_id="CWE-287",
                cwe_name="Test",
                detection_mode=DetectionMode.ENDPOINT,
                confidence=Confidence.DEFINITIVE,
                detection_method="Test",
                remote_scan_applicable=True,
                standards=[],  # ❌ empty
                evidence="Test",
                risk="Test",
                recommendation="Test",
                remediation_effort=RemediationEffort.LOW,
            )


# ==================================================================
# ScanResult computed properties
# ==================================================================

class TestScanResultProperties:
    """Computed properties drive reports, CI gating, and filtering.

    These are the most-used accessors in the codebase — they must be correct.
    """

    def test_finding_count_by_severity(self, valid_scan_result):
        counts = valid_scan_result.finding_count
        assert counts[Severity.CRITICAL] == 1
        assert counts[Severity.HIGH] == 0
        assert counts[Severity.MEDIUM] == 0

    def test_critical_count(self, valid_scan_result):
        assert valid_scan_result.critical_count == 1

    def test_max_cvss(self, valid_scan_result):
        assert valid_scan_result.max_cvss == 8.6

    def test_max_cvss_empty(self):
        result = _empty_scan_result()
        assert result.max_cvss == 0.0

    def test_ci_gate_fails_on_critical(self, valid_scan_result):
        assert valid_scan_result.passed_ci_gate is False

    def test_ci_gate_passes_when_clean(self):
        result = _empty_scan_result()
        assert result.passed_ci_gate is True

    def test_findings_by_auditor(self, valid_scan_result):
        auth_findings = valid_scan_result.findings_by_auditor(Auditor.AUTH)
        assert len(auth_findings) == 1
        transport_findings = valid_scan_result.findings_by_auditor(Auditor.TRANSPORT)
        assert len(transport_findings) == 0

    def test_findings_by_mode(self, valid_scan_result):
        endpoint = valid_scan_result.findings_by_mode(DetectionMode.ENDPOINT)
        assert len(endpoint) == 1
        active = valid_scan_result.findings_by_mode(DetectionMode.ACTIVE)
        assert len(active) == 0

    def test_findings_above_cvss(self, valid_scan_result):
        above_7 = valid_scan_result.findings_above_cvss(7.0)
        assert len(above_7) == 1
        above_9 = valid_scan_result.findings_above_cvss(9.0)
        assert len(above_9) == 0


# ==================================================================
# Serialization round-trip
# ==================================================================

class TestSerialization:
    """Models must survive JSON round-trips for storage and MCP transport.

    ScanResult → JSON → ScanResult must produce identical data.
    Finding → JSON → Finding must preserve all fields.
    """

    def test_finding_round_trip(self, valid_finding):
        json_str = valid_finding.model_dump_json()
        restored = Finding.model_validate_json(json_str)
        assert restored.finding_id == valid_finding.finding_id
        assert restored.cvss_score == valid_finding.cvss_score
        assert restored.severity == valid_finding.severity
        assert restored.auditor == valid_finding.auditor
        assert len(restored.standards) == len(valid_finding.standards)

    def test_scan_result_round_trip(self, valid_scan_result):
        json_str = valid_scan_result.model_dump_json()
        restored = ScanResult.model_validate_json(json_str)
        assert restored.scan_id == valid_scan_result.scan_id
        assert len(restored.findings) == len(valid_scan_result.findings)
        assert restored.findings[0].finding_id == valid_scan_result.findings[0].finding_id

    def test_finding_dict_mode(self, valid_finding):
        d = valid_finding.model_dump(mode="json")
        assert isinstance(d, dict)
        assert d["finding_id"] == "MCP-AUTH-001"
        assert d["severity"] == "critical"

    def test_remote_heuristic_serialization(self, valid_standard_ref):
        finding = valid_finding_with_id("MCP-AUTH-002", valid_standard_ref)
        finding_with_heuristic = finding.model_copy(update={
            "remote_heuristic": RemoteHeuristic(
                available=True,
                confidence=Confidence.LOW,
                description="Response body contains upstream API errors.",
            )
        })
        json_str = finding_with_heuristic.model_dump_json()
        restored = Finding.model_validate_json(json_str)
        assert restored.remote_heuristic is not None
        assert restored.remote_heuristic.available is True
        assert restored.remote_heuristic.confidence == Confidence.LOW


# ==================================================================
# Enum serialization
# ==================================================================

class TestEnumSerialization:
    """str+Enum pattern must serialize to string values, not enum names.

    This matters for JSON output, SARIF reports, and MCP tool responses.
    """

    def test_severity_serializes_to_value(self):
        assert Severity.CRITICAL.value == "critical"
        assert str(Severity.CRITICAL) == "Severity.CRITICAL"

    def test_detection_mode_serializes(self):
        assert DetectionMode.INTROSPECTION.value == "introspection"

    def test_confidence_serializes(self):
        assert Confidence.DEFINITIVE.value == "definitive"

    def test_access_level_serializes(self):
        assert AccessLevel.AUTHENTICATED.value == "authenticated"


# ==================================================================
# Helpers — construct findings with specific overrides
# ==================================================================

def _base_finding_kwargs(standard_ref: StandardReference) -> dict:
    """Base kwargs for a valid Finding."""
    return dict(
        title="Test Finding",
        auditor=Auditor.AUTH,
        severity=Severity.CRITICAL,
        cvss_score=8.0,
        cwe_id="CWE-287",
        cwe_name="Improper Authentication",
        detection_mode=DetectionMode.ENDPOINT,
        confidence=Confidence.DEFINITIVE,
        detection_method="Test method",
        remote_scan_applicable=True,
        standards=[standard_ref],
        evidence="Test evidence",
        risk="Test risk",
        recommendation="Test recommendation",
        remediation_effort=RemediationEffort.LOW,
    )


def valid_finding_with_id(finding_id: str, standard_ref: StandardReference) -> Finding:
    return Finding(finding_id=finding_id, **_base_finding_kwargs(standard_ref))


def valid_finding_with_cvss(cvss: float, standard_ref: StandardReference) -> Finding:
    kwargs = _base_finding_kwargs(standard_ref)
    kwargs["cvss_score"] = cvss
    return Finding(finding_id="MCP-AUTH-001", **kwargs)


def valid_finding_with_cwe(cwe_id: str, standard_ref: StandardReference) -> Finding:
    kwargs = _base_finding_kwargs(standard_ref)
    kwargs["cwe_id"] = cwe_id
    return Finding(finding_id="MCP-AUTH-001", **kwargs)


def _empty_scan_result() -> ScanResult:
    return ScanResult(
        scan_id="scan_test_empty",
        target_url="https://example.com",
        access_level=AccessLevel.REMOTE,
        depth=ScanDepth.STANDARD,
        spec_version="draft-2025-11-25",
        scanner_version="0.1.0",
        scan_duration_seconds=0.1,
        findings=[],
    )
