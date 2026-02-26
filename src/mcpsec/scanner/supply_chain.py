"""MCPSec — Supply Chain Auditor.

Scans MCP server dependencies for known vulnerabilities, typosquatting,
unpinned versions, and unverified publishers.

M2 scope: Static detection mode (SC-001, SC-002, SC-003, SC-004)
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Optional

from mcpsec.exceptions import FileAccessError
from mcpsec.models.findings import (
    Auditor,
    Confidence,
    DetectionMode,
    Finding,
    RemediationEffort,
    RequirementLevel,
    Severity,
    StandardReference,
)
from mcpsec.scanner import BaseAuditor


# ---------------------------------------------------------------------------
# Well-known MCP packages (for typosquat detection)
# ---------------------------------------------------------------------------

_KNOWN_PYTHON_PACKAGES = {
    "fastmcp", "mcp", "anthropic", "openai", "langchain", "llama-index",
    "httpx", "pydantic", "uvicorn", "starlette", "fastapi", "litellm",
    "claudette", "replicate", "google-generativeai", "transformers",
}

_KNOWN_NODE_PACKAGES = {
    "@modelcontextprotocol/sdk", "@anthropic-ai/sdk", "openai",
    "mcp-framework", "fastmcp", "langchain", "llamaindex",
    "express", "axios", "zod", "typescript",
}

# Max Levenshtein distance for typosquat detection
_TYPOSQUAT_DISTANCE = 2

# ---------------------------------------------------------------------------
# Unpinned version patterns
# ---------------------------------------------------------------------------

_PYTHON_UNPINNED = re.compile(r">=|~=|>|!=|\*")
_NODE_UNPINNED = re.compile(r"[\^~*]|>=|>")


class SupplyChainAuditor(BaseAuditor):
    """Audits MCP server dependencies for supply chain risks.

    Static checks (M2 — requires filesystem access):
        SC-001  Known CVE in dependency
        SC-002  Typosquatting package detected
        SC-003  Unpinned dependencies
        SC-004  Publisher not verified
    """

    @property
    def auditor_type(self) -> Auditor:
        return Auditor.SUPPLY_CHAIN

    async def audit(self) -> list[Finding]:
        """Run all supply chain checks."""
        self._clear_findings()

        if not self._should_run_check(DetectionMode.STATIC):
            return self._findings

        if not self.target_path:
            return self._findings

        project_path = Path(self.target_path)
        if not project_path.exists():
            return self._findings

        # Determine project type and find dependency files
        dep_files = self._discover_dependency_files(project_path)

        for dep_file, dep_type in dep_files:
            deps = self._parse_dependencies(dep_file, dep_type)

            if deps:
                self._check_known_cves(dep_file, dep_type)
                self._check_typosquatting(dep_file, dep_type, deps)
                self._check_unpinned(dep_file, dep_type, deps)
                self._check_publisher(dep_file, dep_type, deps)

        return self._findings

    # ==================================================================
    # Dependency discovery
    # ==================================================================

    def _discover_dependency_files(
        self, project_path: Path
    ) -> list[tuple[Path, str]]:
        """Find dependency files in the project.

        Returns list of (path, type) tuples where type is
        'python-requirements', 'python-pyproject', 'python-setup',
        'node-package', or 'node-lockfile'.
        """
        found: list[tuple[Path, str]] = []

        if project_path.is_file():
            dep_type = self._classify_dep_file(project_path)
            if dep_type:
                found.append((project_path, dep_type))
            return found

        # Search project directory
        patterns: list[tuple[str, str]] = [
            ("requirements*.txt", "python-requirements"),
            ("pyproject.toml", "python-pyproject"),
            ("setup.py", "python-setup"),
            ("setup.cfg", "python-setup"),
            ("package.json", "node-package"),
            ("package-lock.json", "node-lockfile"),
            ("yarn.lock", "node-lockfile"),
            ("pnpm-lock.yaml", "node-lockfile"),
        ]

        for pattern, dep_type in patterns:
            for match in project_path.glob(pattern):
                if match.is_file():
                    found.append((match, dep_type))

        return found

    def _classify_dep_file(self, path: Path) -> Optional[str]:
        """Classify a single file by dependency type."""
        name = path.name.lower()
        if name.startswith("requirements") and name.endswith(".txt"):
            return "python-requirements"
        if name == "pyproject.toml":
            return "python-pyproject"
        if name in ("setup.py", "setup.cfg"):
            return "python-setup"
        if name == "package.json":
            return "node-package"
        if name in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
            return "node-lockfile"
        return None

    # ==================================================================
    # Dependency parsing
    # ==================================================================

    def _parse_dependencies(
        self, dep_file: Path, dep_type: str
    ) -> list[dict[str, str]]:
        """Parse dependencies from a file.

        Returns list of {name, version_spec, raw_line} dicts.
        """
        try:
            content = dep_file.read_text(encoding="utf-8")
        except OSError:
            return []

        if dep_type == "python-requirements":
            return self._parse_requirements_txt(content)
        elif dep_type == "python-pyproject":
            return self._parse_pyproject_toml(content)
        elif dep_type == "node-package":
            return self._parse_package_json(content)

        return []

    def _parse_requirements_txt(self, content: str) -> list[dict[str, str]]:
        """Parse requirements.txt format."""
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue

            # Handle inline comments
            line = line.split("#")[0].strip()

            # Parse name and version spec
            match = re.match(r"^([a-zA-Z0-9_.-]+)\s*(.*)?$", line)
            if match:
                name = match.group(1).lower()
                version_spec = (match.group(2) or "").strip()
                deps.append({
                    "name": name,
                    "version_spec": version_spec,
                    "raw_line": line,
                })

        return deps

    def _parse_pyproject_toml(self, content: str) -> list[dict[str, str]]:
        """Parse pyproject.toml dependencies (basic TOML parsing)."""
        deps = []
        in_deps = False

        for line in content.splitlines():
            stripped = line.strip()

            # Detect dependencies section
            if stripped in ("dependencies = [", "[project]"):
                in_deps = "dependencies" in stripped
                continue

            if in_deps:
                if stripped == "]":
                    in_deps = False
                    continue

                # Parse quoted dependency string
                match = re.match(r'["\']([a-zA-Z0-9_.-]+)\s*(.*?)["\'],?\s*$', stripped)
                if match:
                    name = match.group(1).lower()
                    version_spec = match.group(2).strip()
                    deps.append({
                        "name": name,
                        "version_spec": version_spec,
                        "raw_line": stripped,
                    })

        return deps

    def _parse_package_json(self, content: str) -> list[dict[str, str]]:
        """Parse package.json dependencies."""
        deps = []
        try:
            pkg = json.loads(content)
        except json.JSONDecodeError:
            return deps

        for section in ("dependencies", "devDependencies"):
            section_deps = pkg.get(section, {})
            if isinstance(section_deps, dict):
                for name, version in section_deps.items():
                    deps.append({
                        "name": name.lower(),
                        "version_spec": version,
                        "raw_line": f'"{name}": "{version}"',
                    })

        return deps

    # ==================================================================
    # SC-001: Known CVEs
    # ==================================================================

    def _check_known_cves(self, dep_file: Path, dep_type: str) -> None:
        """SC-001: Check dependencies against CVE databases.

        Uses pip-audit for Python and npm audit for Node.js.
        """
        vulnerabilities: list[dict[str, str]] = []

        if dep_type.startswith("python"):
            vulnerabilities = self._run_pip_audit(dep_file)
        elif dep_type.startswith("node"):
            vulnerabilities = self._run_npm_audit(dep_file)

        if not vulnerabilities:
            return

        evidence_parts = []
        max_cvss = 0.0

        for vuln in vulnerabilities:
            cvss = float(vuln.get("cvss", "0.0"))
            max_cvss = max(max_cvss, cvss)
            evidence_parts.append(
                f"  - {vuln['package']} {vuln.get('installed', '?')}: "
                f"{vuln.get('id', 'unknown')} (CVSS {cvss}) — "
                f"fix: {vuln.get('fix', 'unknown')}"
            )

        # Severity based on highest CVSS in vulnerabilities
        if max_cvss >= 9.0:
            severity = Severity.CRITICAL
        elif max_cvss >= 7.0:
            severity = Severity.HIGH
        elif max_cvss >= 4.0:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        self._add_finding(Finding(
            finding_id="MCP-SC-001",
            title="Known CVE in MCP Server Dependency",
            auditor=Auditor.SUPPLY_CHAIN,
            severity=severity,
            cvss_score=max_cvss,
            cvss_vector=None,
            cwe_id="CWE-1395",
            cwe_name="Dependency on Vulnerable Third-Party Component",
            detection_mode=DetectionMode.STATIC,
            confidence=Confidence.DEFINITIVE,
            detection_method=f"{'pip-audit' if dep_type.startswith('python') else 'npm audit'} "
                            f"against OSV.dev / GitHub Advisory Database.",
            remote_scan_applicable=False,
            standards=[
                StandardReference(
                    id="OWASP-MCP04",
                    ref="OWASP MCP Top 10 v0.1",
                    section="MCP04 — Software Supply Chain Attacks",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="OWASP-ASI04",
                    ref="genai.owasp.org",
                    section="ASI04 — Supply Chain Vulnerabilities",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="OWASP-LLM05",
                    ref="OWASP Top 10 for LLM Applications 2025",
                    section="LLM05 — Supply Chain Vulnerabilities",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
            ],
            evidence=f"File: {dep_file}\n"
                     f"{len(vulnerabilities)} vulnerable package(s):\n"
                     + "\n".join(evidence_parts[:15])
                     + (f"\n  ... and {len(vulnerabilities) - 15} more"
                        if len(vulnerabilities) > 15 else ""),
            risk="Dependencies with known CVEs can be exploited to compromise the "
                 "MCP server. Attackers actively scan for unpatched vulnerabilities "
                 "in deployed services. The MCP server inherits all vulnerabilities "
                 "of its dependency tree.",
            recommendation="Update vulnerable packages to their fixed versions. "
                          "Run dependency audits regularly in CI/CD. Pin dependencies "
                          "to specific versions and review before upgrading.",
            code_example=(
                "# Python — audit and fix\n"
                "pip-audit --fix\n\n"
                "# Node.js — audit and fix\n"
                "npm audit fix\n\n"
                "# CI/CD — fail on vulnerabilities\n"
                "pip-audit --strict  # exits non-zero on findings\n"
                "npm audit --audit-level=high"
            ),
            remediation_effort=RemediationEffort.LOW,
            remediation_priority=1,
        ))

    def _run_pip_audit(self, dep_file: Path) -> list[dict[str, str]]:
        """Run pip-audit and parse JSON output."""
        try:
            cmd = ["pip-audit", "--format", "json", "--require-hashes=false"]
            if dep_file.name.startswith("requirements"):
                cmd.extend(["--requirement", str(dep_file)])
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                cwd=dep_file.parent,
            )
            if result.stdout:
                data = json.loads(result.stdout)
                vulns = []
                for dep in data.get("dependencies", []):
                    for vuln in dep.get("vulns", []):
                        vulns.append({
                            "package": dep.get("name", "unknown"),
                            "installed": dep.get("version", "?"),
                            "id": vuln.get("id", "unknown"),
                            "cvss": str(vuln.get("fix_versions", ["?"])[0] if vuln.get("fix_versions") else "?"),
                            "fix": ", ".join(vuln.get("fix_versions", ["no fix"])),
                        })
                return vulns
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass
        return []

    def _run_npm_audit(self, dep_file: Path) -> list[dict[str, str]]:
        """Run npm audit and parse JSON output."""
        try:
            result = subprocess.run(
                ["npm", "audit", "--json"],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=dep_file.parent,
            )
            if result.stdout:
                data = json.loads(result.stdout)
                vulns = []
                for advisory_id, advisory in data.get("advisories", {}).items():
                    vulns.append({
                        "package": advisory.get("module_name", "unknown"),
                        "installed": advisory.get("findings", [{}])[0].get("version", "?"),
                        "id": str(advisory.get("cves", [advisory_id])[0] if advisory.get("cves") else advisory_id),
                        "cvss": str(advisory.get("cvss", {}).get("score", 0.0)),
                        "fix": advisory.get("patched_versions", "unknown"),
                    })
                # Also handle npm audit v2 format
                for vuln_name, vuln_data in data.get("vulnerabilities", {}).items():
                    vulns.append({
                        "package": vuln_name,
                        "installed": vuln_data.get("range", "?"),
                        "id": vuln_data.get("via", [{}])[0].get("url", "unknown") if isinstance(vuln_data.get("via", [{}])[0], dict) else "unknown",
                        "cvss": str(vuln_data.get("severity", "unknown")),
                        "fix": vuln_data.get("fixAvailable", {}).get("version", "unknown") if isinstance(vuln_data.get("fixAvailable"), dict) else "unknown",
                    })
                return vulns
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError):
            pass
        return []

    # ==================================================================
    # SC-002: Typosquatting
    # ==================================================================

    def _check_typosquatting(
        self,
        dep_file: Path,
        dep_type: str,
        deps: list[dict[str, str]],
    ) -> None:
        """SC-002: Detect packages with names suspiciously similar to popular packages."""
        known = _KNOWN_PYTHON_PACKAGES if dep_type.startswith("python") else _KNOWN_NODE_PACKAGES
        suspects: list[dict[str, Any]] = []

        for dep in deps:
            name = dep["name"]
            if name in known:
                continue

            for known_name in known:
                distance = self._levenshtein_distance(name, known_name)
                if 0 < distance <= _TYPOSQUAT_DISTANCE:
                    suspects.append({
                        "package": name,
                        "similar_to": known_name,
                        "distance": distance,
                    })
                    break

        if not suspects:
            return

        evidence_parts = [
            f"  - '{s['package']}' similar to '{s['similar_to']}' "
            f"(edit distance: {s['distance']})"
            for s in suspects
        ]

        self._add_finding(Finding(
            finding_id="MCP-SC-002",
            title="Typosquatting Package Detected",
            auditor=Auditor.SUPPLY_CHAIN,
            severity=Severity.CRITICAL,
            cvss_score=9.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
            cwe_id="CWE-1104",
            cwe_name="Use of Unmaintained Third Party Components",
            detection_mode=DetectionMode.STATIC,
            confidence=Confidence.HIGH,
            detection_method="Levenshtein distance comparison against known legitimate "
                            f"MCP and AI packages. Threshold: {_TYPOSQUAT_DISTANCE}.",
            remote_scan_applicable=False,
            standards=[
                StandardReference(
                    id="OWASP-MCP04",
                    ref="OWASP MCP Top 10 v0.1",
                    section="MCP04 — Software Supply Chain Attacks",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="OWASP-ASI04",
                    ref="genai.owasp.org",
                    section="ASI04 — Supply Chain Vulnerabilities",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="OWASP-LLM05",
                    ref="OWASP Top 10 for LLM Applications 2025",
                    section="LLM05 — Supply Chain Vulnerabilities",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
            ],
            evidence=f"File: {dep_file}\n"
                     f"{len(suspects)} suspected typosquat(s):\n"
                     + "\n".join(evidence_parts),
            risk="Typosquatting packages impersonate legitimate libraries to execute "
                 "malicious code at install time. A single mistyped package name in "
                 "an MCP server's dependencies can compromise the entire server and "
                 "all connected AI agents.",
            recommendation="Verify each flagged package is the intended dependency. "
                          "Check the publisher, download count, and repository URL on "
                          "PyPI/npm. Replace with the correct package name if typosquatted.",
            remediation_effort=RemediationEffort.LOW,
            remediation_priority=1,
        ))

    # ==================================================================
    # SC-003: Unpinned Dependencies
    # ==================================================================

    def _check_unpinned(
        self,
        dep_file: Path,
        dep_type: str,
        deps: list[dict[str, str]],
    ) -> None:
        """SC-003: Detect unpinned or loosely pinned dependency versions."""
        unpinned: list[dict[str, str]] = []

        for dep in deps:
            version_spec = dep["version_spec"]
            name = dep["name"]

            if not version_spec or version_spec.strip() == "":
                unpinned.append({"name": name, "spec": "(no version)", "reason": "No version constraint"})
                continue

            if dep_type.startswith("python"):
                if _PYTHON_UNPINNED.search(version_spec):
                    unpinned.append({"name": name, "spec": version_spec, "reason": "Range specifier"})
            elif dep_type.startswith("node"):
                if _NODE_UNPINNED.search(version_spec):
                    unpinned.append({"name": name, "spec": version_spec, "reason": "Range specifier"})
                if version_spec == "latest" or version_spec == "*":
                    unpinned.append({"name": name, "spec": version_spec, "reason": "Wildcard/latest"})

        if not unpinned:
            return

        evidence_parts = [
            f"  - {u['name']} {u['spec']} ({u['reason']})"
            for u in unpinned[:20]
        ]
        if len(unpinned) > 20:
            evidence_parts.append(f"  ... and {len(unpinned) - 20} more")

        self._add_finding(Finding(
            finding_id="MCP-SC-003",
            title="Unpinned Dependencies",
            auditor=Auditor.SUPPLY_CHAIN,
            severity=Severity.MEDIUM,
            cvss_score=5.0,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L",
            cwe_id="CWE-1329",
            cwe_name="Reliance on Component That is Not Updateable",
            detection_mode=DetectionMode.STATIC,
            confidence=Confidence.DEFINITIVE,
            detection_method="Parsed version specifiers from dependency files. "
                            "Flagged range specifiers (>=, ~, ^, *) and missing version constraints.",
            remote_scan_applicable=False,
            standards=[
                StandardReference(
                    id="OWASP-MCP04",
                    ref="OWASP MCP Top 10 v0.1",
                    section="MCP04 — Software Supply Chain Attacks",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="OWASP-ASI04",
                    ref="genai.owasp.org",
                    section="ASI04 — Supply Chain Vulnerabilities",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="OWASP-LLM05",
                    ref="OWASP Top 10 for LLM Applications 2025",
                    section="LLM05 — Supply Chain Vulnerabilities",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
            ],
            evidence=f"File: {dep_file}\n"
                     f"{len(unpinned)} unpinned dependency(ies):\n"
                     + "\n".join(evidence_parts),
            risk="Unpinned dependencies can silently update to compromised versions. "
                 "A supply chain attack on any dependency with a range specifier will "
                 "automatically propagate to your MCP server on the next install. "
                 "Builds become non-reproducible.",
            recommendation="Pin all direct dependencies to exact versions. "
                          "Use a lockfile (requirements.txt with ==, package-lock.json, "
                          "poetry.lock) for reproducible builds. Review before upgrading.",
            code_example=(
                "# BAD — unpinned\n"
                "fastmcp>=3.0.0    # ❌ accepts any 3.x\n"
                "httpx~=0.27       # ❌ accepts 0.27.x\n"
                "pydantic          # ❌ no constraint at all\n\n"
                "# GOOD — pinned\n"
                "fastmcp==3.0.2    # ✅ exact version\n"
                "httpx==0.27.2     # ✅ exact version\n"
                "pydantic==2.12.5  # ✅ exact version"
            ),
            remediation_effort=RemediationEffort.LOW,
            remediation_priority=7,
        ))

    # ==================================================================
    # SC-004: Publisher Not Verified
    # ==================================================================

    def _check_publisher(
        self,
        dep_file: Path,
        dep_type: str,
        deps: list[dict[str, str]],
    ) -> None:
        """SC-004: Flag packages without provenance or from unknown publishers.

        This is a heuristic check — flags packages that:
        - Have very short names (< 3 chars) — often squatted
        - Have numeric suffixes — common typosquat pattern
        - Use unusual characters in names
        """
        suspicious: list[dict[str, str]] = []

        for dep in deps:
            name = dep["name"]
            reasons = []

            # Very short names
            if len(name.replace("-", "").replace("_", "")) < 3:
                reasons.append("Very short package name")

            # Numeric suffix pattern (e.g. 'requests2', 'openai1')
            if re.match(r"^[a-z-]+\d+$", name):
                reasons.append("Numeric suffix — common typosquat pattern")

            # Unusual characters
            if re.search(r"[^a-z0-9._@/-]", name):
                reasons.append("Unusual characters in package name")

            # Double hyphens or underscores (obfuscation)
            if "--" in name or "__" in name:
                reasons.append("Double separator — possible obfuscation")

            if reasons:
                suspicious.append({
                    "name": name,
                    "reasons": ", ".join(reasons),
                })

        if not suspicious:
            return

        evidence_parts = [
            f"  - {s['name']}: {s['reasons']}"
            for s in suspicious
        ]

        self._add_finding(Finding(
            finding_id="MCP-SC-004",
            title="Publisher Not Verified — Suspicious Package Names",
            auditor=Auditor.SUPPLY_CHAIN,
            severity=Severity.HIGH,
            cvss_score=6.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N",
            cwe_id="CWE-345",
            cwe_name="Insufficient Verification of Data Authenticity",
            detection_mode=DetectionMode.STATIC,
            confidence=Confidence.MEDIUM,
            detection_method="Heuristic analysis of package names for patterns "
                            "associated with typosquatting and unverified publishers.",
            remote_scan_applicable=False,
            standards=[
                StandardReference(
                    id="OWASP-MCP04",
                    ref="OWASP MCP Top 10 v0.1",
                    section="MCP04 — Software Supply Chain Attacks",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="OWASP-ASI04",
                    ref="genai.owasp.org",
                    section="ASI04 — Supply Chain Vulnerabilities",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
            ],
            evidence=f"File: {dep_file}\n"
                     f"{len(suspicious)} suspicious package(s):\n"
                     + "\n".join(evidence_parts),
            risk="Packages from unverified publishers may contain malicious code. "
                 "Short names, numeric suffixes, and unusual characters are patterns "
                 "associated with dependency confusion and typosquatting attacks.",
            recommendation="Verify each flagged package on PyPI/npm. Check publisher "
                          "identity, download count, repository URL, and provenance "
                          "attestation (npm provenance, Sigstore/SLSA for Python).",
            remediation_effort=RemediationEffort.MEDIUM,
            remediation_priority=4,
        ))

    # ==================================================================
    # Helpers
    # ==================================================================

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """Compute Levenshtein edit distance between two strings."""
        if len(s1) < len(s2):
            return SupplyChainAuditor._levenshtein_distance(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]
