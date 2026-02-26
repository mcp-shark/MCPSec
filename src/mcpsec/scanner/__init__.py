"""MCPSec — Scanner engine and base auditor.

All auditor modules (auth, transport, authorization, tools, config,
supply_chain) inherit from BaseAuditor and implement the `audit()` method.
"""

from __future__ import annotations

import time
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional

import httpx

from mcpsec.exceptions import AuditorError, ScanError, TargetConnectionError
from mcpsec.models.findings import (
    AccessLevel,
    Auditor,
    DetectionMode,
    Finding,
    ScanDepth,
    ScanResult,
    Severity,
)


# ---------------------------------------------------------------------------
# Scanner version — single source of truth
# ---------------------------------------------------------------------------

SCANNER_VERSION = "0.1.0"
SPEC_VERSION = "draft-2025-11-25"


# ---------------------------------------------------------------------------
# Base Auditor
# ---------------------------------------------------------------------------

class BaseAuditor(ABC):
    """Abstract base class for all MCPSec auditors.

    Subclasses must implement:
        - `auditor_type` (property): which Auditor enum value this is
        - `audit()`: run all checks and return findings
    """

    def __init__(
        self,
        target_url: Optional[str] = None,
        target_path: Optional[str] = None,
        http_client: Optional[httpx.AsyncClient] = None,
        access_level: AccessLevel = AccessLevel.REMOTE,
        depth: ScanDepth = ScanDepth.STANDARD,
        test_token: Optional[str] = None,
    ):
        self.target_url = target_url
        self.target_path = target_path
        self.access_level = access_level
        self.depth = depth
        self.test_token = test_token
        self._http_client = http_client
        self._findings: list[Finding] = []

    @property
    @abstractmethod
    def auditor_type(self) -> Auditor:
        """Return the Auditor enum value for this auditor."""

    @abstractmethod
    async def audit(self) -> list[Finding]:
        """Run all checks and return findings.

        Implementations should:
        1. Check `self.access_level` and `self.depth` to decide which checks to run
        2. Use `self._add_finding()` or collect findings directly
        3. Catch per-check exceptions so one failing check doesn't abort the auditor
        4. Return the complete list of findings
        """

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    async def get_http_client(self) -> httpx.AsyncClient:
        """Get or create the shared HTTP client."""
        if self._http_client is None:
            self._http_client = httpx.AsyncClient(
                timeout=httpx.Timeout(10.0, connect=5.0),
                follow_redirects=True,
                verify=True,
            )
        return self._http_client

    async def http_get(self, url: str, **kwargs) -> httpx.Response:
        """Perform an HTTP GET with error handling."""
        client = await self.get_http_client()
        try:
            return await client.get(url, **kwargs)
        except httpx.ConnectError as e:
            raise TargetConnectionError(f"Cannot connect to {url}: {e}") from e
        except httpx.TimeoutException as e:
            raise TargetConnectionError(f"Timeout connecting to {url}: {e}") from e

    async def http_head(self, url: str, **kwargs) -> httpx.Response:
        """Perform an HTTP HEAD with error handling."""
        client = await self.get_http_client()
        try:
            return await client.head(url, **kwargs)
        except httpx.ConnectError as e:
            raise TargetConnectionError(f"Cannot connect to {url}: {e}") from e
        except httpx.TimeoutException as e:
            raise TargetConnectionError(f"Timeout connecting to {url}: {e}") from e

    # ------------------------------------------------------------------
    # Finding helpers
    # ------------------------------------------------------------------

    def _add_finding(self, finding: Finding) -> None:
        """Append a finding to this auditor's results."""
        self._findings.append(finding)

    def _clear_findings(self) -> None:
        """Reset findings (useful for re-running)."""
        self._findings.clear()

    def _should_run_check(self, mode: DetectionMode) -> bool:
        """Determine if a check should run given the current access level.

        Access levels unlock detection modes cumulatively:
            remote        → endpoint, introspection
            authenticated → endpoint, introspection, active
            local         → endpoint, introspection, active, static
        """
        allowed = {
            AccessLevel.REMOTE: {DetectionMode.ENDPOINT, DetectionMode.INTROSPECTION},
            AccessLevel.AUTHENTICATED: {
                DetectionMode.ENDPOINT,
                DetectionMode.INTROSPECTION,
                DetectionMode.ACTIVE,
            },
            AccessLevel.LOCAL: {
                DetectionMode.ENDPOINT,
                DetectionMode.INTROSPECTION,
                DetectionMode.ACTIVE,
                DetectionMode.STATIC,
            },
        }
        return mode in allowed[self.access_level]


# ---------------------------------------------------------------------------
# Scanner Engine — orchestrates all auditors
# ---------------------------------------------------------------------------

class ScannerEngine:
    """Orchestrates multiple auditors into a single scan.

    Usage:
        engine = ScannerEngine(target_url="https://mcp-server.com")
        engine.register_auditor(AuthAuditor)
        engine.register_auditor(TransportAuditor)
        result = await engine.run()
    """

    def __init__(
        self,
        target_url: Optional[str] = None,
        target_path: Optional[str] = None,
        access_level: AccessLevel = AccessLevel.REMOTE,
        depth: ScanDepth = ScanDepth.STANDARD,
        test_token: Optional[str] = None,
        classifier: Optional[object] = None,
    ):
        self.target_url = target_url
        self.target_path = target_path
        self.access_level = access_level
        self.depth = depth
        self.test_token = test_token
        self._auditor_classes: list[type[BaseAuditor]] = []
        self._http_client: Optional[httpx.AsyncClient] = None
        self._classifier = classifier

    def register_auditor(self, auditor_class: type[BaseAuditor]) -> None:
        """Register an auditor class to run during scans."""
        self._auditor_classes.append(auditor_class)

    async def run(self) -> ScanResult:
        """Execute all registered auditors and return combined results."""
        scan_id = f"scan_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        start_time = time.monotonic()

        all_findings: list[Finding] = []
        errors: list[str] = []

        # Share a single HTTP client across all auditors
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(10.0, connect=5.0),
            follow_redirects=True,
            verify=True,
        ) as client:
            self._http_client = client

            for auditor_class in self._auditor_classes:
                kwargs = dict(
                    target_url=self.target_url,
                    target_path=self.target_path,
                    http_client=client,
                    access_level=self.access_level,
                    depth=self.depth,
                    test_token=self.test_token,
                )
                if self._classifier and auditor_class.__name__ == "ToolsAuditor":
                    kwargs["classifier"] = self._classifier
                auditor = auditor_class(**kwargs)

                try:
                    findings = await auditor.audit()
                    all_findings.extend(findings)
                except AuditorError as e:
                    errors.append(str(e))
                except Exception as e:
                    errors.append(
                        f"[{auditor.auditor_type.value}] Unexpected error: {e}"
                    )

        duration = time.monotonic() - start_time

        return ScanResult(
            scan_id=scan_id,
            target_url=self.target_url,
            target_path=self.target_path,
            access_level=self.access_level,
            depth=self.depth,
            spec_version=SPEC_VERSION,
            scanner_version=SCANNER_VERSION,
            scan_duration_seconds=round(duration, 2),
            findings=all_findings,
        )
