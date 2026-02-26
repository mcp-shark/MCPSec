"""MCPSec — Storage unit tests.

Tests SQLite scan persistence, retrieval, filtering, and comparison.
Uses in-memory SQLite (:memory:) for speed and isolation.

Test structure:
    - Write/Read round-trip: save a scan, load it, verify identical
    - Listing and filtering: multiple scans, filter by target
    - Comparison: resolved, new, persistent findings across two scans
    - Edge cases: missing scans, duplicate saves, empty results
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from mcpsec.exceptions import ScanNotFoundError
from mcpsec.models.findings import (
    AccessLevel,
    Auditor,
    Confidence,
    DetectionMode,
    Finding,
    RemediationEffort,
    RequirementLevel,
    ScanDepth,
    ScanResult,
    Severity,
    StandardReference,
)
from mcpsec.storage import ScanStorage


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def storage():
    """In-memory storage for test isolation."""
    s = ScanStorage(":memory:")
    yield s
    s.close()


@pytest.fixture
def standard_ref() -> StandardReference:
    return StandardReference(
        id="MCP-SPEC-AUTH",
        ref="modelcontextprotocol.io/specification/draft/basic/authorization",
        section="Test Section",
        requirement_level=RequirementLevel.MUST,
    )


def _make_finding(
    finding_id: str,
    severity: Severity,
    cvss: float,
    auditor: Auditor,
    standard_ref: StandardReference,
) -> Finding:
    """Helper to create a Finding with minimal boilerplate."""
    return Finding(
        finding_id=finding_id,
        title=f"Test {finding_id}",
        auditor=auditor,
        severity=severity,
        cvss_score=cvss,
        cwe_id="CWE-287",
        cwe_name="Improper Authentication",
        detection_mode=DetectionMode.ENDPOINT,
        confidence=Confidence.DEFINITIVE,
        detection_method="Test",
        remote_scan_applicable=True,
        standards=[standard_ref],
        evidence="Test evidence",
        risk="Test risk",
        recommendation="Test recommendation",
        remediation_effort=RemediationEffort.LOW,
    )


def _make_scan(
    scan_id: str,
    target_url: str,
    findings: list[Finding],
    duration: float = 1.0,
) -> ScanResult:
    """Helper to create a ScanResult with minimal boilerplate."""
    return ScanResult(
        scan_id=scan_id,
        target_url=target_url,
        access_level=AccessLevel.REMOTE,
        depth=ScanDepth.STANDARD,
        spec_version="draft-2025-11-25",
        scanner_version="0.1.0",
        scan_duration_seconds=duration,
        findings=findings,
    )


# ==================================================================
# Write / Read round-trip
# ==================================================================

class TestSaveAndLoad:
    """Scan results must survive a SQLite round-trip without data loss.

    This is the most critical storage test — if save→load is lossy,
    reports, comparisons, and CI gating all break.
    """

    def test_save_and_load_with_findings(self, storage, standard_ref):
        finding = _make_finding("MCP-AUTH-001", Severity.CRITICAL, 8.6, Auditor.AUTH, standard_ref)
        scan = _make_scan("scan_001", "https://example.com", [finding])

        storage.save_scan(scan)
        loaded = storage.get_scan("scan_001")

        assert loaded.scan_id == "scan_001"
        assert loaded.target_url == "https://example.com"
        assert loaded.access_level == AccessLevel.REMOTE
        assert loaded.spec_version == "draft-2025-11-25"
        assert loaded.scan_duration_seconds == 1.0
        assert len(loaded.findings) == 1
        assert loaded.findings[0].finding_id == "MCP-AUTH-001"
        assert loaded.findings[0].cvss_score == 8.6
        assert loaded.findings[0].severity == Severity.CRITICAL

    def test_save_and_load_empty_scan(self, storage):
        scan = _make_scan("scan_empty", "https://clean.example.com", [])

        storage.save_scan(scan)
        loaded = storage.get_scan("scan_empty")

        assert loaded.scan_id == "scan_empty"
        assert len(loaded.findings) == 0

    def test_save_and_load_multiple_findings(self, storage, standard_ref):
        findings = [
            _make_finding("MCP-AUTH-001", Severity.CRITICAL, 8.6, Auditor.AUTH, standard_ref),
            _make_finding("MCP-TRANS-001", Severity.HIGH, 4.3, Auditor.TRANSPORT, standard_ref),
            _make_finding("MCP-TOOL-004", Severity.HIGH, 6.8, Auditor.TOOLS, standard_ref),
        ]
        scan = _make_scan("scan_multi", "https://example.com", findings)

        storage.save_scan(scan)
        loaded = storage.get_scan("scan_multi")

        assert len(loaded.findings) == 3
        ids = {f.finding_id for f in loaded.findings}
        assert ids == {"MCP-AUTH-001", "MCP-TRANS-001", "MCP-TOOL-004"}

    def test_resave_overwrites(self, storage, standard_ref):
        """Re-saving a scan with the same ID replaces the old one."""
        finding_v1 = _make_finding("MCP-AUTH-001", Severity.CRITICAL, 8.6, Auditor.AUTH, standard_ref)
        scan_v1 = _make_scan("scan_resave", "https://example.com", [finding_v1])
        storage.save_scan(scan_v1)

        finding_v2 = _make_finding("MCP-AUTH-006", Severity.HIGH, 7.2, Auditor.AUTH, standard_ref)
        scan_v2 = _make_scan("scan_resave", "https://example.com", [finding_v2])
        storage.save_scan(scan_v2)

        loaded = storage.get_scan("scan_resave")
        assert len(loaded.findings) == 1
        assert loaded.findings[0].finding_id == "MCP-AUTH-006"

    def test_returns_scan_id(self, storage):
        scan = _make_scan("scan_return", "https://example.com", [])
        returned_id = storage.save_scan(scan)
        assert returned_id == "scan_return"


# ==================================================================
# Missing scan handling
# ==================================================================

class TestScanNotFound:
    """Storage must raise ScanNotFoundError for missing scan IDs.

    This error propagates to CLI and MCP tool responses — must be reliable.
    """

    def test_get_nonexistent_scan(self, storage):
        with pytest.raises(ScanNotFoundError):
            storage.get_scan("nonexistent")

    def test_delete_nonexistent_scan(self, storage):
        with pytest.raises(ScanNotFoundError):
            storage.delete_scan("nonexistent")

    def test_get_findings_nonexistent_scan(self, storage):
        with pytest.raises(ScanNotFoundError):
            storage.get_findings_for_scan("nonexistent")


# ==================================================================
# Delete
# ==================================================================

class TestDeleteScan:
    """Deletion must remove both the scan and its findings."""

    def test_delete_removes_scan(self, storage, standard_ref):
        finding = _make_finding("MCP-AUTH-001", Severity.CRITICAL, 8.6, Auditor.AUTH, standard_ref)
        scan = _make_scan("scan_del", "https://example.com", [finding])
        storage.save_scan(scan)

        storage.delete_scan("scan_del")

        with pytest.raises(ScanNotFoundError):
            storage.get_scan("scan_del")


# ==================================================================
# List scans
# ==================================================================

class TestListScans:
    """list_scans() powers the CLI list command and MCP list_scans tool."""

    def test_list_empty(self, storage):
        scans = storage.list_scans()
        assert len(scans) == 0

    def test_list_returns_summaries(self, storage, standard_ref):
        finding = _make_finding("MCP-AUTH-001", Severity.CRITICAL, 8.6, Auditor.AUTH, standard_ref)
        scan = _make_scan("scan_list_1", "https://server-a.com", [finding])
        storage.save_scan(scan)

        scans = storage.list_scans()
        assert len(scans) == 1
        assert scans[0].scan_id == "scan_list_1"
        assert scans[0].critical_count == 1
        assert scans[0].max_cvss == 8.6

    def test_list_filter_by_target(self, storage, standard_ref):
        finding = _make_finding("MCP-AUTH-001", Severity.CRITICAL, 8.6, Auditor.AUTH, standard_ref)
        scan_a = _make_scan("scan_a", "https://server-a.com", [finding])
        scan_b = _make_scan("scan_b", "https://server-b.com", [])
        storage.save_scan(scan_a)
        storage.save_scan(scan_b)

        filtered = storage.list_scans(target_url="https://server-a.com")
        assert len(filtered) == 1
        assert filtered[0].scan_id == "scan_a"

    def test_list_respects_limit(self, storage):
        for i in range(10):
            scan = _make_scan(f"scan_{i:03d}", "https://example.com", [])
            storage.save_scan(scan)

        limited = storage.list_scans(limit=3)
        assert len(limited) == 3

    def test_list_ordered_by_timestamp_desc(self, storage):
        for i in range(5):
            scan = _make_scan(f"scan_{i:03d}", "https://example.com", [])
            storage.save_scan(scan)

        scans = storage.list_scans()
        timestamps = [s.scan_timestamp for s in scans]
        assert timestamps == sorted(timestamps, reverse=True)


# ==================================================================
# Get findings with filters
# ==================================================================

class TestGetFindings:
    """Filtered finding retrieval powers targeted report generation."""

    def test_get_all_findings(self, storage, standard_ref):
        findings = [
            _make_finding("MCP-AUTH-001", Severity.CRITICAL, 8.6, Auditor.AUTH, standard_ref),
            _make_finding("MCP-TRANS-001", Severity.HIGH, 4.3, Auditor.TRANSPORT, standard_ref),
        ]
        scan = _make_scan("scan_findings", "https://example.com", findings)
        storage.save_scan(scan)

        loaded = storage.get_findings_for_scan("scan_findings")
        assert len(loaded) == 2

    def test_filter_by_severity(self, storage, standard_ref):
        findings = [
            _make_finding("MCP-AUTH-001", Severity.CRITICAL, 8.6, Auditor.AUTH, standard_ref),
            _make_finding("MCP-TRANS-001", Severity.HIGH, 4.3, Auditor.TRANSPORT, standard_ref),
        ]
        scan = _make_scan("scan_sev", "https://example.com", findings)
        storage.save_scan(scan)

        critical = storage.get_findings_for_scan("scan_sev", severity=Severity.CRITICAL)
        assert len(critical) == 1
        assert critical[0].finding_id == "MCP-AUTH-001"

    def test_filter_by_auditor(self, storage, standard_ref):
        findings = [
            _make_finding("MCP-AUTH-001", Severity.CRITICAL, 8.6, Auditor.AUTH, standard_ref),
            _make_finding("MCP-TRANS-001", Severity.HIGH, 4.3, Auditor.TRANSPORT, standard_ref),
        ]
        scan = _make_scan("scan_aud", "https://example.com", findings)
        storage.save_scan(scan)

        transport = storage.get_findings_for_scan("scan_aud", auditor="transport")
        assert len(transport) == 1
        assert transport[0].finding_id == "MCP-TRANS-001"

    def test_findings_ordered_by_cvss_desc(self, storage, standard_ref):
        findings = [
            _make_finding("MCP-TRANS-001", Severity.HIGH, 4.3, Auditor.TRANSPORT, standard_ref),
            _make_finding("MCP-AUTH-001", Severity.CRITICAL, 8.6, Auditor.AUTH, standard_ref),
        ]
        scan = _make_scan("scan_order", "https://example.com", findings)
        storage.save_scan(scan)

        loaded = storage.get_findings_for_scan("scan_order")
        assert loaded[0].cvss_score >= loaded[1].cvss_score


# ==================================================================
# Scan comparison
# ==================================================================

class TestCompareSans:
    """compare_scans() tracks security improvement over time.

    Three categories:
        - Resolved: in baseline but NOT in current (fixed)
        - New: NOT in baseline but in current (introduced)
        - Persistent: in both (still open)
    """

    def test_resolved_findings(self, storage, standard_ref):
        """Finding in baseline but not current = resolved."""
        f1 = _make_finding("MCP-AUTH-001", Severity.CRITICAL, 8.6, Auditor.AUTH, standard_ref)
        f2 = _make_finding("MCP-AUTH-006", Severity.HIGH, 7.2, Auditor.AUTH, standard_ref)

        baseline = _make_scan("scan_old", "https://example.com", [f1, f2])
        current = _make_scan("scan_new", "https://example.com", [f2])

        storage.save_scan(baseline)
        storage.save_scan(current)

        comparison = storage.compare_scans("scan_old", "scan_new")
        assert "MCP-AUTH-001" in comparison.resolved_findings
        assert len(comparison.resolved_findings) == 1
        assert comparison.improved is True

    def test_new_findings(self, storage, standard_ref):
        """Finding in current but not baseline = new."""
        f1 = _make_finding("MCP-AUTH-001", Severity.CRITICAL, 8.6, Auditor.AUTH, standard_ref)
        f2 = _make_finding("MCP-TRANS-001", Severity.HIGH, 4.3, Auditor.TRANSPORT, standard_ref)

        baseline = _make_scan("scan_old", "https://example.com", [f1])
        current = _make_scan("scan_new", "https://example.com", [f1, f2])

        storage.save_scan(baseline)
        storage.save_scan(current)

        comparison = storage.compare_scans("scan_old", "scan_new")
        assert "MCP-TRANS-001" in comparison.new_findings
        assert len(comparison.new_findings) == 1
        assert comparison.improved is False

    def test_persistent_findings(self, storage, standard_ref):
        """Finding in both = persistent."""
        f1 = _make_finding("MCP-AUTH-001", Severity.CRITICAL, 8.6, Auditor.AUTH, standard_ref)

        baseline = _make_scan("scan_old", "https://example.com", [f1])
        current = _make_scan("scan_new", "https://example.com", [f1])

        storage.save_scan(baseline)
        storage.save_scan(current)

        comparison = storage.compare_scans("scan_old", "scan_new")
        assert "MCP-AUTH-001" in comparison.persistent_findings
        assert len(comparison.resolved_findings) == 0
        assert len(comparison.new_findings) == 0

    def test_severity_changes(self, storage, standard_ref):
        """Same finding with different severity between scans."""
        f_old = _make_finding("MCP-AUTH-001", Severity.CRITICAL, 8.6, Auditor.AUTH, standard_ref)
        f_new = _make_finding("MCP-AUTH-001", Severity.HIGH, 7.0, Auditor.AUTH, standard_ref)

        baseline = _make_scan("scan_old", "https://example.com", [f_old])
        current = _make_scan("scan_new", "https://example.com", [f_new])

        storage.save_scan(baseline)
        storage.save_scan(current)

        comparison = storage.compare_scans("scan_old", "scan_new")
        assert len(comparison.severity_changes) == 1
        assert comparison.severity_changes[0].finding_id == "MCP-AUTH-001"
        assert comparison.severity_changes[0].old_severity == Severity.CRITICAL
        assert comparison.severity_changes[0].new_severity == Severity.HIGH

    def test_compare_nonexistent_baseline(self, storage, standard_ref):
        scan = _make_scan("scan_exists", "https://example.com", [])
        storage.save_scan(scan)

        with pytest.raises(ScanNotFoundError):
            storage.compare_scans("nonexistent", "scan_exists")

    def test_compare_nonexistent_current(self, storage, standard_ref):
        scan = _make_scan("scan_exists", "https://example.com", [])
        storage.save_scan(scan)

        with pytest.raises(ScanNotFoundError):
            storage.compare_scans("scan_exists", "nonexistent")

    def test_comparison_cvss_tracking(self, storage, standard_ref):
        f1 = _make_finding("MCP-AUTH-001", Severity.CRITICAL, 8.6, Auditor.AUTH, standard_ref)
        f2 = _make_finding("MCP-TRANS-001", Severity.HIGH, 4.3, Auditor.TRANSPORT, standard_ref)

        baseline = _make_scan("scan_old", "https://example.com", [f1])
        current = _make_scan("scan_new", "https://example.com", [f2])

        storage.save_scan(baseline)
        storage.save_scan(current)

        comparison = storage.compare_scans("scan_old", "scan_new")
        assert comparison.baseline_max_cvss == 8.6
        assert comparison.current_max_cvss == 4.3
        assert comparison.baseline_finding_count == 1
        assert comparison.current_finding_count == 1

    def test_comparison_to_dict(self, storage, standard_ref):
        """Serialization for JSON/report output."""
        f1 = _make_finding("MCP-AUTH-001", Severity.CRITICAL, 8.6, Auditor.AUTH, standard_ref)

        baseline = _make_scan("scan_old", "https://example.com", [f1])
        current = _make_scan("scan_new", "https://example.com", [])

        storage.save_scan(baseline)
        storage.save_scan(current)

        comparison = storage.compare_scans("scan_old", "scan_new")
        d = comparison.to_dict()

        assert isinstance(d, dict)
        assert d["baseline_scan_id"] == "scan_old"
        assert d["current_scan_id"] == "scan_new"
        assert "MCP-AUTH-001" in d["resolved_findings"]


# ==================================================================
# Context manager
# ==================================================================

class TestContextManager:
    """Storage supports context manager for clean resource handling."""

    def test_context_manager(self):
        with ScanStorage(":memory:") as storage:
            scan = _make_scan("scan_ctx", "https://example.com", [])
            storage.save_scan(scan)
            loaded = storage.get_scan("scan_ctx")
            assert loaded.scan_id == "scan_ctx"
