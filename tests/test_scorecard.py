"""MCPSec — Scorecard unit tests.

Tests the compliance scorecard generation:
    - Overall scoring and grades
    - MCP Spec / OWASP / FastMCP framework-specific scores
    - OWASP MCP Top 10 category coverage
    - Per-auditor breakdown
    - LLM narrative via MockProvider
    - Integration with markdown report
"""

from __future__ import annotations

import pytest

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
from mcpsec.reports.scorecard import (
    AuditorScore,
    OwaspCategory,
    ScoreCard,
    generate_scorecard,
    _compute_score,
    _compute_grade,
    _compute_owasp_coverage,
    _compute_auditor_breakdown,
    _filter_by_standard_prefix,
)
from mcpsec.llm.classifier import HybridClassifier, MockProvider


# ---------------------------------------------------------------------------
# Helpers — build findings with specific standards
# ---------------------------------------------------------------------------

def _make_finding(
    finding_id: str = "MCP-AUTH-001",
    severity: Severity = Severity.HIGH,
    cvss: float = 7.0,
    auditor: Auditor = Auditor.AUTH,
    standard_ids: list[str] | None = None,
) -> Finding:
    standards = []
    for sid in (standard_ids or ["MCP-SPEC-AUTH"]):
        standards.append(StandardReference(
            id=sid,
            ref="test-ref",
            section="Test section",
            requirement_level=RequirementLevel.MUST,
        ))
    return Finding(
        finding_id=finding_id,
        title="Test Finding",
        auditor=auditor,
        severity=severity,
        cvss_score=cvss,
        cwe_id="CWE-287",
        cwe_name="Test CWE",
        detection_mode=DetectionMode.ENDPOINT,
        confidence=Confidence.DEFINITIVE,
        detection_method="Test",
        remote_scan_applicable=True,
        standards=standards,
        evidence="Test evidence",
        risk="Test risk",
        recommendation="Test recommendation",
        remediation_effort=RemediationEffort.LOW,
    )


def _make_scan_result(findings: list[Finding] | None = None) -> ScanResult:
    return ScanResult(
        scan_id="scan_test",
        target_url="https://example.com",
        access_level=AccessLevel.REMOTE,
        depth=ScanDepth.STANDARD,
        spec_version="draft-2025-11-25",
        scanner_version="0.1.0",
        scan_duration_seconds=1.0,
        findings=findings or [],
    )


# ==================================================================
# _compute_score
# ==================================================================

class TestComputeScore:

    def test_no_findings_perfect(self):
        assert _compute_score([]) == 100

    def test_single_critical(self):
        findings = [_make_finding(severity=Severity.CRITICAL)]
        assert _compute_score(findings) == 85

    def test_single_high(self):
        findings = [_make_finding(severity=Severity.HIGH)]
        assert _compute_score(findings) == 90

    def test_single_medium(self):
        findings = [_make_finding(severity=Severity.MEDIUM)]
        assert _compute_score(findings) == 95

    def test_single_low(self):
        findings = [_make_finding(severity=Severity.LOW)]
        assert _compute_score(findings) == 98

    def test_informational_no_deduction(self):
        findings = [_make_finding(severity=Severity.INFORMATIONAL)]
        assert _compute_score(findings) == 100

    def test_multiple_findings(self):
        findings = [
            _make_finding(severity=Severity.CRITICAL),
            _make_finding(finding_id="MCP-AUTH-002", severity=Severity.HIGH),
            _make_finding(finding_id="MCP-AUTH-003", severity=Severity.MEDIUM),
        ]
        # 100 - 15 - 10 - 5 = 70
        assert _compute_score(findings) == 70

    def test_floor_at_zero(self):
        findings = [
            _make_finding(finding_id=f"MCP-AUTH-{i:03d}", severity=Severity.CRITICAL)
            for i in range(10)
        ]
        # 100 - 150 = clamped to 0
        assert _compute_score(findings) == 0


# ==================================================================
# _compute_grade
# ==================================================================

class TestComputeGrade:

    def test_grade_a(self):
        grade, icon = _compute_grade(95)
        assert grade == "A"
        assert icon == "🟢"

    def test_grade_a_boundary(self):
        grade, _ = _compute_grade(90)
        assert grade == "A"

    def test_grade_b(self):
        grade, icon = _compute_grade(80)
        assert grade == "B"
        assert icon == "🟡"

    def test_grade_c(self):
        grade, icon = _compute_grade(65)
        assert grade == "C"
        assert icon == "🟠"

    def test_grade_d(self):
        grade, _ = _compute_grade(45)
        assert grade == "D"

    def test_grade_f(self):
        grade, icon = _compute_grade(30)
        assert grade == "F"
        assert icon == "🔴"

    def test_grade_f_zero(self):
        grade, _ = _compute_grade(0)
        assert grade == "F"

    def test_grade_a_perfect(self):
        grade, _ = _compute_grade(100)
        assert grade == "A"


# ==================================================================
# _filter_by_standard_prefix
# ==================================================================

class TestFilterByStandardPrefix:

    def test_mcp_spec_filter(self):
        findings = [
            _make_finding(standard_ids=["MCP-SPEC-AUTH"]),
            _make_finding(finding_id="MCP-TOOL-001", standard_ids=["OWASP-MCP03"]),
        ]
        filtered = _filter_by_standard_prefix(findings, "MCP-SPEC")
        assert len(filtered) == 1

    def test_fmcp_filter(self):
        findings = [
            _make_finding(standard_ids=["FMCP-SCOPES"]),
            _make_finding(finding_id="MCP-AUTH-002", standard_ids=["MCP-SPEC-AUTH"]),
        ]
        filtered = _filter_by_standard_prefix(findings, "FMCP")
        assert len(filtered) == 1

    def test_owasp_filter(self):
        findings = [
            _make_finding(standard_ids=["OWASP-MCP01"]),
            _make_finding(finding_id="MCP-AUTH-002", standard_ids=["OWASP-MCP07"]),
            _make_finding(finding_id="MCP-AUTH-003", standard_ids=["MCP-SPEC-AUTH"]),
        ]
        filtered = _filter_by_standard_prefix(findings, "OWASP")
        assert len(filtered) == 2

    def test_no_matches(self):
        findings = [_make_finding(standard_ids=["MCP-SPEC-AUTH"])]
        filtered = _filter_by_standard_prefix(findings, "FMCP")
        assert len(filtered) == 0

    def test_multiple_standards_on_one_finding(self):
        findings = [_make_finding(standard_ids=["MCP-SPEC-AUTH", "OWASP-MCP07"])]
        assert len(_filter_by_standard_prefix(findings, "MCP-SPEC")) == 1
        assert len(_filter_by_standard_prefix(findings, "OWASP")) == 1


# ==================================================================
# _compute_owasp_coverage
# ==================================================================

class TestOwaspCoverage:

    def test_no_findings_all_clear(self):
        coverage, categories = _compute_owasp_coverage([])
        assert coverage == 10
        assert all(c.clear for c in categories)

    def test_one_category_hit(self):
        findings = [_make_finding(standard_ids=["OWASP-MCP07"])]
        coverage, categories = _compute_owasp_coverage(findings)
        assert coverage == 9
        mcp07 = next(c for c in categories if c.id == "MCP07")
        assert not mcp07.clear
        assert "MCP-AUTH-001" in mcp07.finding_ids

    def test_multiple_categories_hit(self):
        findings = [
            _make_finding(standard_ids=["OWASP-MCP01"]),
            _make_finding(finding_id="MCP-TOOL-001", standard_ids=["OWASP-MCP03"]),
            _make_finding(finding_id="MCP-AUTH-006", standard_ids=["OWASP-MCP07"]),
        ]
        coverage, categories = _compute_owasp_coverage(findings)
        assert coverage == 7

    def test_multiple_findings_same_category(self):
        findings = [
            _make_finding(standard_ids=["OWASP-MCP07"]),
            _make_finding(finding_id="MCP-AUTH-002", standard_ids=["OWASP-MCP07"]),
        ]
        coverage, categories = _compute_owasp_coverage(findings)
        assert coverage == 9  # Still just one category affected
        mcp07 = next(c for c in categories if c.id == "MCP07")
        assert len(mcp07.finding_ids) == 2

    def test_non_owasp_standards_ignored(self):
        findings = [_make_finding(standard_ids=["MCP-SPEC-AUTH"])]
        coverage, _ = _compute_owasp_coverage(findings)
        assert coverage == 10

    def test_all_ten_categories(self):
        _, categories = _compute_owasp_coverage([])
        assert len(categories) == 10
        ids = {c.id for c in categories}
        assert ids == {f"MCP{i:02d}" for i in range(1, 11)}


# ==================================================================
# _compute_auditor_breakdown
# ==================================================================

class TestAuditorBreakdown:

    def test_empty_findings(self):
        breakdown = _compute_auditor_breakdown([])
        assert breakdown == []

    def test_single_auditor(self):
        findings = [
            _make_finding(severity=Severity.HIGH, cvss=7.5),
            _make_finding(finding_id="MCP-AUTH-002", severity=Severity.MEDIUM, cvss=5.0),
        ]
        breakdown = _compute_auditor_breakdown(findings)
        assert len(breakdown) == 1
        assert breakdown[0].auditor == "auth"
        assert breakdown[0].finding_count == 2
        assert breakdown[0].max_cvss == 7.5
        assert breakdown[0].score == 85  # 100 - 10 - 5

    def test_multiple_auditors(self):
        findings = [
            _make_finding(auditor=Auditor.AUTH, severity=Severity.CRITICAL),
            _make_finding(finding_id="MCP-TRANS-001", auditor=Auditor.TRANSPORT, severity=Severity.HIGH),
            _make_finding(finding_id="MCP-TOOL-001", auditor=Auditor.TOOLS, severity=Severity.MEDIUM),
        ]
        breakdown = _compute_auditor_breakdown(findings)
        assert len(breakdown) == 3
        auditor_names = {a.auditor for a in breakdown}
        assert auditor_names == {"auth", "transport", "tools"}

    def test_sorted_by_auditor_name(self):
        findings = [
            _make_finding(finding_id="MCP-TOOL-001", auditor=Auditor.TOOLS),
            _make_finding(auditor=Auditor.AUTH),
        ]
        breakdown = _compute_auditor_breakdown(findings)
        assert breakdown[0].auditor == "auth"
        assert breakdown[1].auditor == "tools"


# ==================================================================
# generate_scorecard — no LLM
# ==================================================================

class TestGenerateScorecard:

    @pytest.mark.asyncio
    async def test_empty_scan_perfect_score(self):
        result = _make_scan_result([])
        sc = await generate_scorecard(result)
        assert sc.overall_score == 100
        assert sc.grade == "A"
        assert sc.owasp_mcp_coverage == 10
        assert sc.analysis is None

    @pytest.mark.asyncio
    async def test_critical_finding_drops_score(self):
        result = _make_scan_result([
            _make_finding(severity=Severity.CRITICAL),
        ])
        sc = await generate_scorecard(result)
        assert sc.overall_score == 85
        assert sc.grade == "B"

    @pytest.mark.asyncio
    async def test_mcp_spec_score_isolated(self):
        result = _make_scan_result([
            _make_finding(severity=Severity.HIGH, standard_ids=["MCP-SPEC-AUTH"]),
            _make_finding(finding_id="MCP-TOOL-001", severity=Severity.HIGH, standard_ids=["OWASP-MCP03"]),
        ])
        sc = await generate_scorecard(result)
        assert sc.mcp_spec_score == 90  # Only one MCP-SPEC finding
        assert sc.overall_score == 80   # Both findings count

    @pytest.mark.asyncio
    async def test_fastmcp_score_isolated(self):
        result = _make_scan_result([
            _make_finding(severity=Severity.HIGH, standard_ids=["FMCP-SCOPES"]),
            _make_finding(finding_id="MCP-AUTH-006", severity=Severity.HIGH, standard_ids=["MCP-SPEC-AUTH"]),
        ])
        sc = await generate_scorecard(result)
        assert sc.fastmcp_baseline_score == 90  # Only one FMCP finding

    @pytest.mark.asyncio
    async def test_owasp_coverage_in_scorecard(self):
        result = _make_scan_result([
            _make_finding(standard_ids=["OWASP-MCP01"]),
            _make_finding(finding_id="MCP-TOOL-001", standard_ids=["OWASP-MCP03"]),
        ])
        sc = await generate_scorecard(result)
        assert sc.owasp_mcp_coverage == 8

    @pytest.mark.asyncio
    async def test_auditor_breakdown_present(self):
        result = _make_scan_result([
            _make_finding(auditor=Auditor.AUTH),
            _make_finding(finding_id="MCP-TRANS-001", auditor=Auditor.TRANSPORT),
        ])
        sc = await generate_scorecard(result)
        assert len(sc.auditor_breakdown) == 2

    @pytest.mark.asyncio
    async def test_owasp_categories_present(self):
        result = _make_scan_result([])
        sc = await generate_scorecard(result)
        assert len(sc.owasp_categories) == 10

    @pytest.mark.asyncio
    async def test_grade_icon_present(self):
        result = _make_scan_result([])
        sc = await generate_scorecard(result)
        assert sc.grade_icon == "🟢"

    @pytest.mark.asyncio
    async def test_serialization_round_trip(self):
        result = _make_scan_result([_make_finding()])
        sc = await generate_scorecard(result)
        json_str = sc.model_dump_json()
        restored = ScoreCard.model_validate_json(json_str)
        assert restored.overall_score == sc.overall_score
        assert restored.grade == sc.grade
        assert len(restored.owasp_categories) == 10


# ==================================================================
# generate_scorecard — with MockProvider LLM
# ==================================================================

class TestScorecardWithLLM:

    @pytest.mark.asyncio
    async def test_analysis_populated(self):
        result = _make_scan_result([
            _make_finding(severity=Severity.CRITICAL),
        ])
        classifier = HybridClassifier(provider=MockProvider("clean"))
        sc = await generate_scorecard(result, classifier=classifier)
        assert sc.analysis is not None
        assert len(sc.analysis) > 0

    @pytest.mark.asyncio
    async def test_no_classifier_no_analysis(self):
        result = _make_scan_result([_make_finding()])
        sc = await generate_scorecard(result, classifier=None)
        assert sc.analysis is None

    @pytest.mark.asyncio
    async def test_scores_same_with_or_without_llm(self):
        result = _make_scan_result([
            _make_finding(severity=Severity.CRITICAL),
            _make_finding(finding_id="MCP-AUTH-002", severity=Severity.HIGH),
        ])
        sc_no_llm = await generate_scorecard(result)
        classifier = HybridClassifier(provider=MockProvider("clean"))
        sc_with_llm = await generate_scorecard(result, classifier=classifier)
        assert sc_no_llm.overall_score == sc_with_llm.overall_score
        assert sc_no_llm.grade == sc_with_llm.grade
        assert sc_no_llm.mcp_spec_score == sc_with_llm.mcp_spec_score


# ==================================================================
# ScoreCard model validation
# ==================================================================

class TestScoreCardModel:

    def test_score_bounds(self):
        with pytest.raises(Exception):
            ScoreCard(
                overall_score=101, grade="A", grade_icon="🟢",
                mcp_spec_score=100, owasp_mcp_coverage=10,
                fastmcp_baseline_score=100,
            )

    def test_owasp_coverage_bounds(self):
        with pytest.raises(Exception):
            ScoreCard(
                overall_score=100, grade="A", grade_icon="🟢",
                mcp_spec_score=100, owasp_mcp_coverage=11,
                fastmcp_baseline_score=100,
            )

    def test_valid_scorecard(self):
        sc = ScoreCard(
            overall_score=75, grade="B", grade_icon="🟡",
            mcp_spec_score=80, owasp_mcp_coverage=7,
            fastmcp_baseline_score=90,
        )
        assert sc.overall_score == 75
        assert sc.analysis is None


# ==================================================================
# Integration with markdown report
# ==================================================================

class TestScorecardMarkdownIntegration:

    @pytest.mark.asyncio
    async def test_markdown_includes_scorecard(self):
        from mcpsec.reports.markdown import generate_markdown_report
        result = _make_scan_result([
            _make_finding(severity=Severity.CRITICAL, standard_ids=["MCP-SPEC-AUTH", "OWASP-MCP07"]),
        ])
        sc = await generate_scorecard(result)
        report = generate_markdown_report(result, scorecard=sc)
        assert "Compliance Score" in report
        assert "MCP Spec Compliance" in report
        assert "OWASP MCP Top 10" in report
        assert "FastMCP Baseline" in report
        assert "Grade:" in report

    @pytest.mark.asyncio
    async def test_markdown_without_scorecard(self):
        from mcpsec.reports.markdown import generate_markdown_report
        result = _make_scan_result([_make_finding()])
        report = generate_markdown_report(result)
        assert "Compliance Score" in report
        assert "Grade:" in report

    @pytest.mark.asyncio
    async def test_markdown_with_llm_analysis(self):
        from mcpsec.reports.markdown import generate_markdown_report
        result = _make_scan_result([_make_finding()])
        classifier = HybridClassifier(provider=MockProvider("clean"))
        sc = await generate_scorecard(result, classifier=classifier)
        report = generate_markdown_report(result, scorecard=sc)
        assert "Risk Analysis" in report
