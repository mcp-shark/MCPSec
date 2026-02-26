"""MCPSec — SQLite scan history storage.

Persists scan results for history, comparison, and trend tracking.
Uses a denormalized approach: full ScanResult JSON stored alongside
extracted columns for efficient querying without deserialization.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from mcpsec.exceptions import ScanNotFoundError, StorageError
from mcpsec.models.findings import (
    Finding,
    ScanResult,
    Severity,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_DB_PATH = Path.home() / ".mcpsec" / "scans.db"

SCHEMA_VERSION = 1

_CREATE_TABLES = """
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    scan_id             TEXT PRIMARY KEY,
    target_url          TEXT,
    target_path         TEXT,
    access_level        TEXT NOT NULL,
    depth               TEXT NOT NULL,
    spec_version        TEXT NOT NULL,
    scanner_version     TEXT NOT NULL,
    scan_timestamp      TEXT NOT NULL,
    scan_duration_seconds REAL NOT NULL,
    finding_count       INTEGER NOT NULL DEFAULT 0,
    critical_count      INTEGER NOT NULL DEFAULT 0,
    high_count          INTEGER NOT NULL DEFAULT 0,
    medium_count        INTEGER NOT NULL DEFAULT 0,
    low_count           INTEGER NOT NULL DEFAULT 0,
    info_count          INTEGER NOT NULL DEFAULT 0,
    max_cvss            REAL NOT NULL DEFAULT 0.0,
    passed_ci_gate      INTEGER NOT NULL DEFAULT 1,
    raw_json            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id             TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    finding_id          TEXT NOT NULL,
    title               TEXT NOT NULL,
    auditor             TEXT NOT NULL,
    severity            TEXT NOT NULL,
    cvss_score          REAL NOT NULL,
    cwe_id              TEXT NOT NULL,
    detection_mode      TEXT NOT NULL,
    confidence          TEXT NOT NULL,
    remote_scan_applicable INTEGER NOT NULL,
    evidence            TEXT NOT NULL,
    risk                TEXT NOT NULL,
    recommendation      TEXT NOT NULL,
    remediation_effort  TEXT NOT NULL,
    raw_json            TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_auditor ON findings(auditor);
CREATE INDEX IF NOT EXISTS idx_findings_finding_id ON findings(finding_id);
CREATE INDEX IF NOT EXISTS idx_scans_target_url ON scans(target_url);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(scan_timestamp);
"""


# ---------------------------------------------------------------------------
# Storage class
# ---------------------------------------------------------------------------

class ScanStorage:
    """SQLite-backed storage for MCPSec scan results.

    Usage:
        storage = ScanStorage()              # default ~/.mcpsec/scans.db
        storage = ScanStorage("./scans.db")  # custom path
        storage = ScanStorage(":memory:")     # in-memory (testing)
    """

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH):
        self._db_path = Path(db_path) if db_path != ":memory:" else db_path
        self._conn: Optional[sqlite3.Connection] = None
        self._ensure_db()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _ensure_db(self) -> None:
        """Create database directory and initialize schema."""
        if self._db_path != ":memory:":
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(self._db_path),
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self) -> None:
        """Create tables if they don't exist, handle migrations."""
        cursor = self._conn.cursor()
        cursor.executescript(_CREATE_TABLES)

        # Check / set schema version
        row = cursor.execute(
            "SELECT version FROM schema_version LIMIT 1"
        ).fetchone()
        if row is None:
            cursor.execute(
                "INSERT INTO schema_version (version) VALUES (?)",
                (SCHEMA_VERSION,),
            )
        self._conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> ScanStorage:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def save_scan(self, result: ScanResult) -> str:
        """Persist a ScanResult and all its findings.

        Args:
            result: Complete scan result to store.

        Returns:
            The scan_id of the saved scan.

        Raises:
            StorageError: If the scan could not be saved.
        """
        try:
            cursor = self._conn.cursor()
            counts = result.finding_count

            cursor.execute(
                """
                INSERT OR REPLACE INTO scans (
                    scan_id, target_url, target_path,
                    access_level, depth, spec_version, scanner_version,
                    scan_timestamp, scan_duration_seconds,
                    finding_count, critical_count, high_count,
                    medium_count, low_count, info_count,
                    max_cvss, passed_ci_gate, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.scan_id,
                    result.target_url,
                    result.target_path,
                    result.access_level.value,
                    result.depth.value,
                    result.spec_version,
                    result.scanner_version,
                    result.scan_timestamp.isoformat(),
                    result.scan_duration_seconds,
                    len(result.findings),
                    counts[Severity.CRITICAL],
                    counts[Severity.HIGH],
                    counts[Severity.MEDIUM],
                    counts[Severity.LOW],
                    counts[Severity.INFORMATIONAL],
                    result.max_cvss,
                    int(result.passed_ci_gate),
                    result.model_dump_json(),
                ),
            )

            # Clear old findings for this scan (for re-scans / updates)
            cursor.execute(
                "DELETE FROM findings WHERE scan_id = ?", (result.scan_id,)
            )

            # Insert individual findings
            for finding in result.findings:
                cursor.execute(
                    """
                    INSERT INTO findings (
                        scan_id, finding_id, title, auditor, severity,
                        cvss_score, cwe_id, detection_mode, confidence,
                        remote_scan_applicable, evidence, risk,
                        recommendation, remediation_effort, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        result.scan_id,
                        finding.finding_id,
                        finding.title,
                        finding.auditor.value,
                        finding.severity.value,
                        finding.cvss_score,
                        finding.cwe_id,
                        finding.detection_mode.value,
                        finding.confidence.value,
                        int(finding.remote_scan_applicable),
                        finding.evidence,
                        finding.risk,
                        finding.recommendation,
                        finding.remediation_effort.value,
                        finding.model_dump_json(),
                    ),
                )

            self._conn.commit()
            return result.scan_id

        except sqlite3.Error as e:
            self._conn.rollback()
            raise StorageError(f"Failed to save scan {result.scan_id}: {e}") from e

    def delete_scan(self, scan_id: str) -> None:
        """Delete a scan and all its findings.

        Raises:
            ScanNotFoundError: If scan_id doesn't exist.
        """
        self._assert_scan_exists(scan_id)
        try:
            self._conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            self._conn.commit()
        except sqlite3.Error as e:
            self._conn.rollback()
            raise StorageError(f"Failed to delete scan {scan_id}: {e}") from e

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def get_scan(self, scan_id: str) -> ScanResult:
        """Load a full ScanResult by scan_id.

        Raises:
            ScanNotFoundError: If scan_id doesn't exist.
        """
        row = self._conn.execute(
            "SELECT raw_json FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()

        if row is None:
            raise ScanNotFoundError(f"Scan not found: {scan_id}")

        return ScanResult.model_validate_json(row["raw_json"])

    def list_scans(
        self,
        target_url: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ScanSummary]:
        """List scan summaries, optionally filtered by target.

        Returns lightweight summaries — not full findings.
        """
        query = """
            SELECT scan_id, target_url, target_path,
                   access_level, depth, spec_version, scanner_version,
                   scan_timestamp, scan_duration_seconds,
                   finding_count, critical_count, high_count,
                   medium_count, low_count, info_count,
                   max_cvss, passed_ci_gate
            FROM scans
        """
        params: list = []

        if target_url:
            query += " WHERE target_url = ?"
            params.append(target_url)

        query += " ORDER BY scan_timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        rows = self._conn.execute(query, params).fetchall()
        return [ScanSummary.from_row(dict(row)) for row in rows]

    def get_findings_for_scan(
        self,
        scan_id: str,
        severity: Optional[Severity] = None,
        auditor: Optional[str] = None,
    ) -> list[Finding]:
        """Load findings for a scan with optional filters.

        Raises:
            ScanNotFoundError: If scan_id doesn't exist.
        """
        self._assert_scan_exists(scan_id)

        query = "SELECT raw_json FROM findings WHERE scan_id = ?"
        params: list = [scan_id]

        if severity:
            query += " AND severity = ?"
            params.append(severity.value)

        if auditor:
            query += " AND auditor = ?"
            params.append(auditor)

        query += " ORDER BY cvss_score DESC"

        rows = self._conn.execute(query, params).fetchall()
        return [Finding.model_validate_json(row["raw_json"]) for row in rows]

    # ------------------------------------------------------------------
    # Comparison
    # ------------------------------------------------------------------

    def compare_scans(self, scan_id_a: str, scan_id_b: str) -> ScanComparison:
        """Compare two scans to track improvement or regression.

        scan_id_a is treated as the baseline (older scan).
        scan_id_b is treated as the current (newer scan).

        Raises:
            ScanNotFoundError: If either scan_id doesn't exist.
        """
        scan_a = self.get_scan(scan_id_a)
        scan_b = self.get_scan(scan_id_b)

        findings_a = {f.finding_id for f in scan_a.findings}
        findings_b = {f.finding_id for f in scan_b.findings}

        resolved = findings_a - findings_b
        new = findings_b - findings_a
        persistent = findings_a & findings_b

        # Check for severity changes in persistent findings
        severity_changes = []
        a_by_id = {f.finding_id: f for f in scan_a.findings}
        b_by_id = {f.finding_id: f for f in scan_b.findings}

        for fid in persistent:
            if a_by_id[fid].severity != b_by_id[fid].severity:
                severity_changes.append(
                    SeverityChange(
                        finding_id=fid,
                        old_severity=a_by_id[fid].severity,
                        new_severity=b_by_id[fid].severity,
                    )
                )

        return ScanComparison(
            baseline_scan_id=scan_id_a,
            current_scan_id=scan_id_b,
            baseline_timestamp=scan_a.scan_timestamp,
            current_timestamp=scan_b.scan_timestamp,
            resolved_findings=sorted(resolved),
            new_findings=sorted(new),
            persistent_findings=sorted(persistent),
            severity_changes=severity_changes,
            baseline_max_cvss=scan_a.max_cvss,
            current_max_cvss=scan_b.max_cvss,
            baseline_finding_count=len(scan_a.findings),
            current_finding_count=len(scan_b.findings),
            improved=len(scan_b.findings) < len(scan_a.findings),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _assert_scan_exists(self, scan_id: str) -> None:
        """Raise ScanNotFoundError if scan doesn't exist."""
        row = self._conn.execute(
            "SELECT 1 FROM scans WHERE scan_id = ?", (scan_id,)
        ).fetchone()
        if row is None:
            raise ScanNotFoundError(f"Scan not found: {scan_id}")


# ---------------------------------------------------------------------------
# Lightweight models for storage operations
# ---------------------------------------------------------------------------

class ScanSummary:
    """Lightweight scan summary for list views (no full findings)."""

    __slots__ = (
        "scan_id", "target_url", "target_path",
        "access_level", "depth", "spec_version", "scanner_version",
        "scan_timestamp", "scan_duration_seconds",
        "finding_count", "critical_count", "high_count",
        "medium_count", "low_count", "info_count",
        "max_cvss", "passed_ci_gate",
    )

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    @classmethod
    def from_row(cls, row: dict) -> ScanSummary:
        """Create from a SQLite row dict."""
        return cls(
            scan_id=row["scan_id"],
            target_url=row["target_url"],
            target_path=row["target_path"],
            access_level=row["access_level"],
            depth=row["depth"],
            spec_version=row["spec_version"],
            scanner_version=row["scanner_version"],
            scan_timestamp=datetime.fromisoformat(row["scan_timestamp"]),
            scan_duration_seconds=row["scan_duration_seconds"],
            finding_count=row["finding_count"],
            critical_count=row["critical_count"],
            high_count=row["high_count"],
            medium_count=row["medium_count"],
            low_count=row["low_count"],
            info_count=row["info_count"],
            max_cvss=row["max_cvss"],
            passed_ci_gate=bool(row["passed_ci_gate"]),
        )

    def to_dict(self) -> dict:
        """Serialize for JSON output."""
        return {
            attr: (
                getattr(self, attr).isoformat()
                if isinstance(getattr(self, attr), datetime)
                else getattr(self, attr)
            )
            for attr in self.__slots__
        }


class SeverityChange:
    """Tracks a severity change for a finding between two scans."""

    __slots__ = ("finding_id", "old_severity", "new_severity")

    def __init__(self, finding_id: str, old_severity: Severity, new_severity: Severity):
        self.finding_id = finding_id
        self.old_severity = old_severity
        self.new_severity = new_severity


class ScanComparison:
    """Result of comparing two scans."""

    __slots__ = (
        "baseline_scan_id", "current_scan_id",
        "baseline_timestamp", "current_timestamp",
        "resolved_findings", "new_findings", "persistent_findings",
        "severity_changes",
        "baseline_max_cvss", "current_max_cvss",
        "baseline_finding_count", "current_finding_count",
        "improved",
    )

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    def to_dict(self) -> dict:
        """Serialize for JSON/report output."""
        return {
            "baseline_scan_id": self.baseline_scan_id,
            "current_scan_id": self.current_scan_id,
            "baseline_timestamp": self.baseline_timestamp.isoformat(),
            "current_timestamp": self.current_timestamp.isoformat(),
            "resolved_findings": self.resolved_findings,
            "new_findings": self.new_findings,
            "persistent_findings": self.persistent_findings,
            "severity_changes": [
                {
                    "finding_id": sc.finding_id,
                    "old_severity": sc.old_severity.value,
                    "new_severity": sc.new_severity.value,
                }
                for sc in self.severity_changes
            ],
            "baseline_max_cvss": self.baseline_max_cvss,
            "current_max_cvss": self.current_max_cvss,
            "baseline_finding_count": self.baseline_finding_count,
            "current_finding_count": self.current_finding_count,
            "improved": self.improved,
        }
