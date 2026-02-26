"""MCPSec — Core finding and scan result models.

Canonical data structures for security findings, scan results,
and compliance reporting. All models use Pydantic for validation,
serialization, and schema generation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    """CVSS-aligned severity rating."""
    CRITICAL      = "critical"       # CVSS 9.0–10.0
    HIGH          = "high"           # CVSS 7.0–8.9
    MEDIUM        = "medium"         # CVSS 4.0–6.9
    LOW           = "low"            # CVSS 1.0–3.9
    INFORMATIONAL = "informational"  # CVSS 0.0


class DetectionMode(str, Enum):
    """How the scanner detects this finding."""
    ENDPOINT      = "endpoint"       # HTTP probing only — zero credentials
    INTROSPECTION = "introspection"  # MCP client connection (tools/list)
    ACTIVE        = "active"         # Requires test tokens / auth interaction
    STATIC        = "static"         # Requires filesystem / source code access


class Confidence(str, Enum):
    """How certain the scanner is about this finding."""
    DEFINITIVE = "definitive"  # Spec check passed/failed — binary
    HIGH       = "high"        # Strong heuristic or pattern match
    MEDIUM     = "medium"      # LLM classifier or indirect signal
    LOW        = "low"         # Inferred from weak indicators


class RemediationEffort(str, Enum):
    """Estimated effort to fix the finding."""
    LOW    = "low"     # Config change or one-liner
    MEDIUM = "medium"  # Code change in existing architecture
    HIGH   = "high"    # Architecture change required


class Auditor(str, Enum):
    """Which scanner module produced the finding."""
    AUTH          = "auth"
    TRANSPORT     = "transport"
    AUTHORIZATION = "authorization"
    TOOLS         = "tools"
    CONFIG        = "config"
    SUPPLY_CHAIN  = "supply_chain"


class RequirementLevel(str, Enum):
    """RFC 2119 requirement level from the referenced standard."""
    MUST          = "MUST"
    MUST_NOT      = "MUST NOT"
    SHOULD        = "SHOULD"
    SHOULD_NOT    = "SHOULD NOT"
    MAY           = "MAY"
    RECOMMENDED   = "RECOMMENDED"
    NOT_APPLICABLE = "N/A"


class AccessLevel(str, Enum):
    """What access the scanner has to the target."""
    REMOTE        = "remote"         # Endpoint + introspection only
    AUTHENTICATED = "authenticated"  # + active token probing
    LOCAL         = "local"          # + static analysis (full access)


class ScanDepth(str, Enum):
    """How thorough the scan is at the given access level."""
    QUICK    = "quick"     # Well-known endpoints only (~5 sec)
    STANDARD = "standard"  # Full checks for access level (~15 sec)
    THOROUGH = "thorough"  # All checks, including slow ones (~30 sec)


# ---------------------------------------------------------------------------
# Sub-models
# ---------------------------------------------------------------------------

class StandardReference(BaseModel):
    """A reference to a specific standard or specification section."""
    id: str = Field(
        ...,
        description="Standard identifier (e.g. 'MCP-SPEC-AUTH', 'OWASP-MCP07', 'RFC9728')"
    )
    ref: str = Field(
        ...,
        description="URL or document reference"
    )
    section: str = Field(
        ...,
        description="Specific section or requirement title"
    )
    requirement_level: RequirementLevel = Field(
        default=RequirementLevel.NOT_APPLICABLE,
        description="RFC 2119 requirement level (MUST, SHOULD, etc.)"
    )


class RemoteHeuristic(BaseModel):
    """When a finding can't be definitively detected remotely,
    describe the heuristic fallback available."""
    available: bool = Field(
        ...,
        description="Whether a remote heuristic exists for this finding"
    )
    confidence: Confidence = Field(
        default=Confidence.LOW,
        description="Confidence level of the heuristic"
    )
    description: str = Field(
        default="",
        description="How the heuristic works and its limitations"
    )


# ---------------------------------------------------------------------------
# Core models
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """A single security finding from a scan.

    This is the atomic unit of MCPSec output. Every finding maps to at least
    one standard, has a detection mode, and includes actionable remediation.
    """

    # --- Identity ---
    finding_id: str = Field(
        ...,
        pattern=r"^MCP-(AUTH|TRANS|AUTHZ|TOOL|CONFIG|SC)-\d{3}$",
        description="Stable finding ID (e.g. 'MCP-AUTH-001'). Never reassigned."
    )
    title: str = Field(
        ...,
        description="Short human-readable title"
    )

    # --- Classification ---
    auditor: Auditor
    severity: Severity
    cvss_score: float = Field(
        ...,
        ge=0.0,
        le=10.0,
        description="CVSS 3.1 base score"
    )
    cvss_vector: Optional[str] = Field(
        default=None,
        description="Full CVSS 3.1 vector string"
    )
    cwe_id: str = Field(
        ...,
        pattern=r"^CWE-\d+$",
        description="CWE identifier (e.g. 'CWE-287')"
    )
    cwe_name: str = Field(
        ...,
        description="CWE title (e.g. 'Improper Authentication')"
    )

    # --- Detection ---
    detection_mode: DetectionMode
    confidence: Confidence
    detection_method: str = Field(
        ...,
        description="How the scanner detects this finding"
    )
    remote_scan_applicable: bool = Field(
        ...,
        description="Whether this finding can be detected via remote scan"
    )
    remote_heuristic: Optional[RemoteHeuristic] = Field(
        default=None,
        description="Heuristic fallback for remote detection when direct detection requires local access"
    )

    # --- Standards ---
    standards: list[StandardReference] = Field(
        ...,
        min_length=1,
        description="Standards this finding maps to (at least one)"
    )

    # --- Evidence & Risk ---
    evidence: str = Field(
        ...,
        description="What was observed (populated at scan time)"
    )
    risk: str = Field(
        ...,
        description="Why this matters — threat and impact"
    )

    # --- Remediation ---
    recommendation: str = Field(
        ...,
        description="Step-by-step fix guidance"
    )
    code_example: Optional[str] = Field(
        default=None,
        description="FastMCP reference code for the fix"
    )
    remediation_effort: RemediationEffort
    remediation_priority: Optional[int] = Field(
        default=None,
        ge=1,
        description="Fix order (1 = fix first). Computed from severity + effort."
    )


class ScanResult(BaseModel):
    """Complete result of a single MCPSec scan run.

    Contains all findings, scan metadata, and enough context
    to generate compliance reports and compare scans over time.
    """

    # --- Scan identity ---
    scan_id: str = Field(
        ...,
        description="Unique scan identifier (e.g. 'scan_20260224_001')"
    )

    # --- Target ---
    target_url: Optional[str] = Field(
        default=None,
        description="Remote MCP server URL (for remote scans)"
    )
    target_path: Optional[str] = Field(
        default=None,
        description="Local server path (for static scans)"
    )

    # --- Scan config ---
    access_level: AccessLevel
    depth: ScanDepth
    spec_version: str = Field(
        ...,
        description="MCP spec version evaluated against (e.g. 'draft-2025-11-25')"
    )
    scanner_version: str = Field(
        ...,
        description="MCPSec version that produced this scan"
    )

    # --- Timing ---
    scan_timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    scan_duration_seconds: float = Field(
        ...,
        ge=0.0,
        description="Wall-clock scan duration"
    )

    # --- Results ---
    findings: list[Finding] = Field(
        default_factory=list,
        description="All findings from this scan"
    )

    # --- Computed properties ---
    @property
    def finding_count(self) -> dict[Severity, int]:
        """Count findings by severity."""
        counts = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        return counts

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def max_cvss(self) -> float:
        """Highest CVSS score across all findings."""
        if not self.findings:
            return 0.0
        return max(f.cvss_score for f in self.findings)

    @property
    def passed_ci_gate(self) -> bool:
        """Default CI gate: fail on any Critical or High."""
        return all(
            f.severity not in (Severity.CRITICAL, Severity.HIGH)
            for f in self.findings
        )

    def findings_by_auditor(self, auditor: Auditor) -> list[Finding]:
        """Filter findings by auditor."""
        return [f for f in self.findings if f.auditor == auditor]

    def findings_by_mode(self, mode: DetectionMode) -> list[Finding]:
        """Filter findings by detection mode."""
        return [f for f in self.findings if f.detection_mode == mode]

    def findings_above_cvss(self, threshold: float) -> list[Finding]:
        """Get findings at or above a CVSS threshold (for CI gating)."""
        return [f for f in self.findings if f.cvss_score >= threshold]
