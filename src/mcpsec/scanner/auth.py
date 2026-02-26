"""MCPSec — Authentication Auditor.

Validates MCP server compliance with the MCP Authorization specification,
OAuth 2.1 RFCs, and FastMCP auth baseline patterns.

M1 scope: Endpoint detection mode (findings AUTH-001, 004–006, 008–009, 011–013)
M2 scope: Active mode (AUTH-003, 007, 010) and Static mode (AUTH-002)
"""

from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs

import httpx
import base64
import json as json_mod


from mcpsec.exceptions import AuditorError, TargetConnectionError
from mcpsec.models.findings import (
    AccessLevel,
    Auditor,
    Confidence,
    DetectionMode,
    Finding,
    RemediationEffort,
    RemoteHeuristic,
    RequirementLevel,
    Severity,
    StandardReference,
)
from mcpsec.scanner import BaseAuditor


class AuthAuditor(BaseAuditor):
    """Audits MCP server authentication against the MCP spec and FastMCP baseline.

    Endpoint checks (M1 — zero credentials):
        AUTH-001  Protected Resource Metadata missing
        AUTH-004  Remote server over HTTP (no TLS)
        AUTH-005  PKCE not supported
        AUTH-006  Authorization Server Metadata missing
        AUTH-008  Bearer token in URI query string
        AUTH-009  401 missing WWW-Authenticate header
        AUTH-011  No scope in WWW-Authenticate challenge
        AUTH-012  No registration mechanism
        AUTH-013  STDIO server with HTTP auth

    Active checks (M2 — requires test token):
        AUTH-003  Audience binding not enforced
        AUTH-007  Resource indicator parameter missing
        AUTH-010  Insufficient scope error handling

    Static checks (M2 — requires source code):
        AUTH-002  Token passthrough detected
    """

    @property
    def auditor_type(self) -> Auditor:
        return Auditor.AUTH

    async def audit(self) -> list[Finding]:
        """Run all auth checks appropriate for the current access level and depth."""
        self._clear_findings()

        if not self.target_url:
            return self._findings

        # --- Endpoint checks (always available for remote scans) ---
        if self._should_run_check(DetectionMode.ENDPOINT):
            await self._check_https(self.target_url)

            # Probe the MCP endpoint for 401 response
            www_authenticate = await self._probe_unauthenticated()

            # Check well-known endpoints
            as_metadata = await self._check_as_metadata()
            pr_metadata = await self._check_protected_resource_metadata()

            # Checks that depend on AS metadata
            if as_metadata:
                self._check_pkce_support(as_metadata)
                self._check_registration_mechanism(as_metadata)

            # Check for tokens in query strings
            self._check_token_in_query_string()

        # --- Active checks (M2 stub) ---
        if self._should_run_check(DetectionMode.ACTIVE):
            await self._check_audience_binding()
            await self._check_resource_indicator()
            await self._check_scope_error_handling()

        # --- Static checks (M2 stub) ---
        if self._should_run_check(DetectionMode.STATIC):
            self._check_token_passthrough()

        return self._findings

    # ==================================================================
    # Endpoint checks — M1
    # ==================================================================

    async def _check_https(self, url: str) -> None:
        """AUTH-004: Verify remote server uses HTTPS."""
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # Localhost is explicitly permitted by spec for development
        localhost_names = {"localhost", "127.0.0.1", "::1", "[::1]"}
        if hostname in localhost_names:
            return

        if parsed.scheme != "https":
            self._add_finding(Finding(
                finding_id="MCP-AUTH-004",
                title="Remote Server Accessible Over HTTP (No TLS)",
                auditor=Auditor.AUTH,
                severity=Severity.CRITICAL,
                cvss_score=8.1,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-319",
                cwe_name="Cleartext Transmission of Sensitive Information",
                detection_mode=DetectionMode.ENDPOINT,
                confidence=Confidence.DEFINITIVE,
                detection_method="URL scheme inspection — target URL uses HTTP instead of HTTPS.",
                remote_scan_applicable=True,
                standards=[
                    StandardReference(
                        id="MCP-SPEC-AUTH",
                        ref="modelcontextprotocol.io/specification/draft/basic/authorization",
                        section="Communication Security — all endpoints MUST be HTTPS",
                        requirement_level=RequirementLevel.MUST,
                    ),
                    StandardReference(
                        id="RFC6749",
                        ref="RFC 6749 §3.1",
                        section="Authorization Endpoint — MUST require TLS",
                        requirement_level=RequirementLevel.MUST,
                    ),
                    StandardReference(
                        id="OWASP-MCP01",
                        ref="OWASP MCP Top 10 v0.1",
                        section="MCP01 — Token Mismanagement & Secret Exposure",
                        requirement_level=RequirementLevel.NOT_APPLICABLE,
                    ),
                    StandardReference(
                        id="OWASP-MCP07",
                        ref="OWASP MCP Top 10 v0.1",
                        section="MCP07 — Insufficient Authentication & Authorization",
                        requirement_level=RequirementLevel.NOT_APPLICABLE,
                    ),
                ],
                evidence=f"Target URL scheme is '{parsed.scheme}://' — not HTTPS. "
                         f"Hostname '{hostname}' is not localhost.",
                risk="OAuth tokens, authorization codes, and MCP tool payloads transmitted "
                     "in cleartext. Enables MITM attacks against the entire auth flow. "
                     "CVE-2025-6514 class vulnerability facilitated by trusting unverified HTTP endpoints.",
                recommendation="Enforce HTTPS on all remote MCP server endpoints. Redirect HTTP to HTTPS. "
                               "Only localhost (127.0.0.1, ::1) is permitted over plain HTTP per spec.",
                code_example=(
                    "# FastMCP with HTTPS via reverse proxy (recommended)\n"
                    "fastmcp run server.py --transport http --host 127.0.0.1 --port 8000\n"
                    "# Place behind nginx/caddy with TLS termination\n\n"
                    "# For local development, localhost is permitted:\n"
                    "fastmcp run server.py --transport http --host 127.0.0.1 --port 8000"
                ),
                remediation_effort=RemediationEffort.LOW,
                remediation_priority=1,
            ))

    async def _probe_unauthenticated(self) -> Optional[str]:
        """Send an unauthenticated request to the MCP endpoint.

        Returns the WWW-Authenticate header value if present, else None.
        Also triggers AUTH-009 and AUTH-011 checks.
        """
        try:
            # Try the standard MCP endpoint path
            mcp_url = self.target_url.rstrip("/") + "/mcp"
            response = await self.http_get(mcp_url, headers={"Accept": "application/json"})
        except TargetConnectionError:
            # Try root URL as fallback
            try:
                response = await self.http_get(self.target_url, headers={"Accept": "application/json"})
            except TargetConnectionError:
                return None

        if response.status_code == 401:
            www_auth = response.headers.get("www-authenticate", "")

            if not www_auth:
                # AUTH-009: Missing WWW-Authenticate header
                self._add_finding(Finding(
                    finding_id="MCP-AUTH-009",
                    title="401 Response Missing WWW-Authenticate Header",
                    auditor=Auditor.AUTH,
                    severity=Severity.HIGH,
                    cvss_score=5.8,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                    cwe_id="CWE-203",
                    cwe_name="Observable Discrepancy",
                    detection_mode=DetectionMode.ENDPOINT,
                    confidence=Confidence.DEFINITIVE,
                    detection_method="Sent unauthenticated request, received 401 without WWW-Authenticate header.",
                    remote_scan_applicable=True,
                    standards=[
                        StandardReference(
                            id="MCP-SPEC-AUTH",
                            ref="modelcontextprotocol.io/specification/draft/basic/authorization",
                            section="Protected Resource Metadata Discovery — 401 MUST include WWW-Authenticate",
                            requirement_level=RequirementLevel.MUST,
                        ),
                        StandardReference(
                            id="RFC6750",
                            ref="RFC 6750 §3",
                            section="WWW-Authenticate Response Header Field",
                            requirement_level=RequirementLevel.MUST,
                        ),
                        StandardReference(
                            id="OWASP-MCP07",
                            ref="OWASP MCP Top 10 v0.1",
                            section="MCP07 — Insufficient Authentication & Authorization",
                            requirement_level=RequirementLevel.NOT_APPLICABLE,
                        ),
                    ],
                    evidence=f"HTTP 401 response from {response.url} — "
                             f"no WWW-Authenticate header present. "
                             f"Response headers: {dict(response.headers)}",
                    risk="Without WWW-Authenticate: Bearer resource_metadata=\"<url>\", "
                         "the spec-defined auth discovery chain is broken. MCP clients "
                         "have no machine-readable path to the authorization server.",
                    recommendation="Add WWW-Authenticate header to all 401 responses: "
                                   "WWW-Authenticate: Bearer resource_metadata=\"<url>\", scope=\"<scopes>\". "
                                   "FastMCP adds this automatically when auth is configured.",
                    code_example=(
                        "# FastMCP handles WWW-Authenticate automatically\n"
                        "from fastmcp import FastMCP\n"
                        "from fastmcp.server.auth import OAuthProvider\n\n"
                        "mcp = FastMCP(name='My Server', auth=OAuthProvider(...))\n"
                        "# All 401 responses will include WWW-Authenticate header"
                    ),
                    remediation_effort=RemediationEffort.LOW,
                    remediation_priority=3,
                ))
                return None

            # AUTH-011: Check for scope in WWW-Authenticate
            if "scope" not in www_auth.lower():
                self._add_finding(Finding(
                    finding_id="MCP-AUTH-011",
                    title="No Scope Guidance in WWW-Authenticate Challenge",
                    auditor=Auditor.AUTH,
                    severity=Severity.MEDIUM,
                    cvss_score=4.0,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                    cwe_id="CWE-272",
                    cwe_name="Least Privilege Violation",
                    detection_mode=DetectionMode.ENDPOINT,
                    confidence=Confidence.DEFINITIVE,
                    detection_method="WWW-Authenticate header present but missing 'scope' parameter.",
                    remote_scan_applicable=True,
                    standards=[
                        StandardReference(
                            id="MCP-SPEC-AUTH",
                            ref="modelcontextprotocol.io/specification/draft/basic/authorization",
                            section="Protected Resource Metadata Discovery — SHOULD include scope",
                            requirement_level=RequirementLevel.SHOULD,
                        ),
                        StandardReference(
                            id="RFC6750",
                            ref="RFC 6750 §3",
                            section="WWW-Authenticate scope parameter",
                            requirement_level=RequirementLevel.SHOULD,
                        ),
                        StandardReference(
                            id="OWASP-MCP02",
                            ref="OWASP MCP Top 10 v0.1",
                            section="MCP02 — Privilege Escalation via Scope Creep",
                            requirement_level=RequirementLevel.NOT_APPLICABLE,
                        ),
                    ],
                    evidence=f"WWW-Authenticate header: '{www_auth}' — no 'scope' parameter found.",
                    risk="Without scope guidance, clients fall back to requesting all available "
                         "scopes — violating the principle of least privilege. Clients cannot "
                         "request minimum required permissions.",
                    recommendation="Include scope parameter in WWW-Authenticate header to guide "
                                   "clients toward requesting appropriate scopes. "
                                   "Example: WWW-Authenticate: Bearer scope=\"read write\"",
                    remediation_effort=RemediationEffort.LOW,
                    remediation_priority=8,
                ))

            return www_auth

        # Server didn't return 401 — might have no auth at all
        if response.status_code == 200:
            # This could be a server with no auth — flag in transport auditor
            pass

        return None

    async def _check_protected_resource_metadata(self) -> Optional[dict[str, Any]]:
        """AUTH-001: Check for Protected Resource Metadata (RFC 9728)."""
        base_url = self.target_url.rstrip("/")
        pr_url = f"{base_url}/.well-known/oauth-protected-resource"

        try:
            response = await self.http_get(pr_url)
        except TargetConnectionError:
            self._emit_auth_001(pr_url, "Connection failed", None)
            return None

        if response.status_code != 200:
            self._emit_auth_001(pr_url, f"HTTP {response.status_code}", response)
            return None

        try:
            metadata = response.json()
        except Exception:
            self._emit_auth_001(pr_url, "Response is not valid JSON", response)
            return None

        # Validate required field
        if "authorization_servers" not in metadata:
            self._emit_auth_001(
                pr_url,
                "Response JSON missing 'authorization_servers' field",
                response,
            )
            return None

        return metadata

    def _emit_auth_001(
        self, url: str, reason: str, response: Optional[httpx.Response]
    ) -> None:
        """Emit AUTH-001 finding with contextual evidence."""
        evidence_parts = [f"GET {url} — {reason}."]
        if response is not None:
            evidence_parts.append(f"Status: {response.status_code}.")
            content_type = response.headers.get("content-type", "unknown")
            evidence_parts.append(f"Content-Type: {content_type}.")

        self._add_finding(Finding(
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
            detection_method="HTTP GET to /.well-known/oauth-protected-resource — "
                            "endpoint missing, invalid, or lacks required fields.",
            remote_scan_applicable=True,
            standards=[
                StandardReference(
                    id="MCP-SPEC-AUTH",
                    ref="modelcontextprotocol.io/specification/draft/basic/authorization",
                    section="Protected Resource Metadata Discovery Requirements",
                    requirement_level=RequirementLevel.MUST,
                ),
                StandardReference(
                    id="RFC9728",
                    ref="RFC 9728 §5",
                    section="Protected Resource Metadata",
                    requirement_level=RequirementLevel.MUST,
                ),
                StandardReference(
                    id="OWASP-MCP07",
                    ref="OWASP MCP Top 10 v0.1",
                    section="MCP07 — Insufficient Authentication & Authorization",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="FMCP-TIER1",
                    ref="gofastmcp.com/servers/auth/authentication",
                    section="TokenVerifier — minimum auth tier",
                    requirement_level=RequirementLevel.RECOMMENDED,
                ),
            ],
            evidence=" ".join(evidence_parts),
            risk="Entry point of the entire MCP auth discovery chain is missing. "
                 "MCP clients cannot determine authorization server location, "
                 "cannot discover required scopes, and per the spec MUST fail "
                 "the connection attempt. The server has no machine-readable auth mechanism.",
            recommendation="Serve RFC 9728 compliant metadata at /.well-known/oauth-protected-resource "
                          "with 'authorization_servers' array. Alternatively, include resource_metadata "
                          "URI in WWW-Authenticate header on 401 responses. "
                          "FastMCP serves this endpoint automatically when any auth provider is configured.",
            code_example=(
                "# FastMCP — automatic endpoint, just configure auth\n"
                "from fastmcp import FastMCP\n"
                "from fastmcp.server.auth import OAuthProvider\n\n"
                "mcp = FastMCP(\n"
                "    name='My Server',\n"
                "    auth=OAuthProvider(...)\n"
                ")\n"
                "# /.well-known/oauth-protected-resource served automatically"
            ),
            remediation_effort=RemediationEffort.HIGH,
            remediation_priority=1,
        ))

    async def _check_as_metadata(self) -> Optional[dict[str, Any]]:
        """AUTH-006: Check for Authorization Server Metadata (RFC 8414).

        Tries both OAuth 2.0 and OpenID Connect discovery endpoints.
        """
        base_url = self.target_url.rstrip("/")

        # Try OAuth 2.0 AS Metadata first (RFC 8414)
        oauth_url = f"{base_url}/.well-known/oauth-authorization-server"
        metadata = await self._try_fetch_json(oauth_url)

        if metadata is not None:
            return metadata

        # Fallback: OpenID Connect Discovery
        oidc_url = f"{base_url}/.well-known/openid-configuration"
        metadata = await self._try_fetch_json(oidc_url)

        if metadata is not None:
            return metadata

        # Neither endpoint found
        self._add_finding(Finding(
            finding_id="MCP-AUTH-006",
            title="Authorization Server Metadata Endpoint Missing",
            auditor=Auditor.AUTH,
            severity=Severity.HIGH,
            cvss_score=7.2,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H",
            cwe_id="CWE-287",
            cwe_name="Improper Authentication",
            detection_mode=DetectionMode.ENDPOINT,
            confidence=Confidence.DEFINITIVE,
            detection_method="HTTP GET to both /.well-known/oauth-authorization-server and "
                            "/.well-known/openid-configuration — neither returned valid JSON metadata.",
            remote_scan_applicable=True,
            standards=[
                StandardReference(
                    id="MCP-SPEC-AUTH",
                    ref="modelcontextprotocol.io/specification/draft/basic/authorization",
                    section="Authorization Server Metadata Discovery — MUST support RFC 8414 or OIDC",
                    requirement_level=RequirementLevel.MUST,
                ),
                StandardReference(
                    id="RFC8414",
                    ref="RFC 8414",
                    section="OAuth 2.0 Authorization Server Metadata",
                    requirement_level=RequirementLevel.MUST,
                ),
                StandardReference(
                    id="OWASP-MCP07",
                    ref="OWASP MCP Top 10 v0.1",
                    section="MCP07 — Insufficient Authentication & Authorization",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
            ],
            evidence=f"GET {oauth_url} — failed or not valid JSON. "
                     f"GET {oidc_url} — failed or not valid JSON. "
                     "Neither discovery endpoint returned valid Authorization Server Metadata.",
            risk="MCP clients cannot verify PKCE support, discover token endpoint, "
                 "or check DCR support. The spec requires clients to refuse authorization "
                 "if neither discovery mechanism returns valid metadata.",
            recommendation="Serve OAuth 2.0 Authorization Server Metadata at "
                          "/.well-known/oauth-authorization-server (preferred) or OpenID Connect "
                          "Discovery at /.well-known/openid-configuration. "
                          "FastMCP OAuthProvider serves this automatically.",
            code_example=(
                "# FastMCP OAuthProvider serves AS metadata automatically\n"
                "from fastmcp import FastMCP\n"
                "from fastmcp.server.auth import OAuthProvider\n\n"
                "mcp = FastMCP(\n"
                "    name='My Server',\n"
                "    auth=OAuthProvider(\n"
                "        issuer='https://auth.example.com',\n"
                "        # ... provider config\n"
                "    )\n"
                ")\n"
                "# /.well-known/oauth-authorization-server served automatically"
            ),
            remediation_effort=RemediationEffort.HIGH,
            remediation_priority=2,
        ))

        return None

    def _check_pkce_support(self, as_metadata: dict[str, Any]) -> None:
        """AUTH-005: Verify PKCE support (S256) in AS metadata."""
        methods = as_metadata.get("code_challenge_methods_supported", [])

        if "S256" not in methods:
            self._add_finding(Finding(
                finding_id="MCP-AUTH-005",
                title="PKCE Not Supported",
                auditor=Auditor.AUTH,
                severity=Severity.CRITICAL,
                cvss_score=7.4,
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-345",
                cwe_name="Insufficient Verification of Data Authenticity",
                detection_mode=DetectionMode.ENDPOINT,
                confidence=Confidence.DEFINITIVE,
                detection_method="Inspected 'code_challenge_methods_supported' in Authorization "
                                "Server Metadata — 'S256' not listed.",
                remote_scan_applicable=True,
                standards=[
                    StandardReference(
                        id="MCP-SPEC-AUTH",
                        ref="modelcontextprotocol.io/specification/draft/basic/authorization",
                        section="Authorization Code Protection — MUST support PKCE with S256",
                        requirement_level=RequirementLevel.MUST,
                    ),
                    StandardReference(
                        id="RFC7636",
                        ref="RFC 7636",
                        section="Proof Key for Code Exchange",
                        requirement_level=RequirementLevel.MUST,
                    ),
                    StandardReference(
                        id="OWASP-MCP07",
                        ref="OWASP MCP Top 10 v0.1",
                        section="MCP07 — Insufficient Authentication & Authorization",
                        requirement_level=RequirementLevel.NOT_APPLICABLE,
                    ),
                ],
                evidence=f"code_challenge_methods_supported: {methods or 'absent'}. "
                         "'S256' not found. Per spec, MCP clients MUST refuse to proceed "
                         "if this field is absent.",
                risk="Without PKCE, authorization codes intercepted via redirect URI attacks "
                     "or network sniffing can be exchanged for tokens. The MCP spec mandates "
                     "S256 code challenge method. A server that doesn't advertise it forces "
                     "clients to reject the auth flow entirely.",
                recommendation="Ensure authorization server includes "
                              "'code_challenge_methods_supported': ['S256'] in its metadata. "
                              "FastMCP OAuthProvider includes this by default.",
                code_example=(
                    "# FastMCP OAuthProvider includes PKCE S256 by default\n"
                    "from fastmcp import FastMCP\n"
                    "from fastmcp.server.auth import OAuthProvider\n\n"
                    "mcp = FastMCP(name='My Server', auth=OAuthProvider(...))\n"
                    "# AS metadata will include code_challenge_methods_supported: ['S256']"
                ),
                remediation_effort=RemediationEffort.MEDIUM,
                remediation_priority=2,
            ))

    def _check_registration_mechanism(self, as_metadata: dict[str, Any]) -> None:
        """AUTH-012: Check for Dynamic Client Registration or CIMD support."""
        has_dcr = "registration_endpoint" in as_metadata
        has_cimd = as_metadata.get("client_id_metadata_document_supported", False)

        if not has_dcr and not has_cimd:
            self._add_finding(Finding(
                finding_id="MCP-AUTH-012",
                title="No Client Registration Mechanism Available",
                auditor=Auditor.AUTH,
                severity=Severity.MEDIUM,
                cvss_score=3.9,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                cwe_id="CWE-287",
                cwe_name="Improper Authentication",
                detection_mode=DetectionMode.ENDPOINT,
                confidence=Confidence.DEFINITIVE,
                detection_method="AS metadata checked for 'registration_endpoint' (DCR) and "
                                "'client_id_metadata_document_supported' (CIMD). Neither present.",
                remote_scan_applicable=True,
                standards=[
                    StandardReference(
                        id="MCP-SPEC-AUTH",
                        ref="modelcontextprotocol.io/specification/draft/basic/authorization",
                        section="Dynamic Client Registration — backwards compatibility",
                        requirement_level=RequirementLevel.SHOULD,
                    ),
                    StandardReference(
                        id="RFC7591",
                        ref="RFC 7591",
                        section="Dynamic Client Registration Protocol",
                        requirement_level=RequirementLevel.SHOULD,
                    ),
                    StandardReference(
                        id="OWASP-MCP07",
                        ref="OWASP MCP Top 10 v0.1",
                        section="MCP07 — Insufficient Authentication & Authorization",
                        requirement_level=RequirementLevel.NOT_APPLICABLE,
                    ),
                ],
                evidence="AS metadata contains neither 'registration_endpoint' (DCR/RFC 7591) "
                         "nor 'client_id_metadata_document_supported' (CIMD). "
                         "No dynamic registration mechanism available for MCP clients.",
                risk="MCP clients cannot self-register. Only pre-registered clients can authenticate. "
                     "This limits interoperability, especially for new or third-party clients. "
                     "CIMD is the preferred mechanism in the current spec; DCR is backwards compatibility.",
                recommendation="Implement Client ID Metadata Documents (CIMD) as the preferred "
                              "registration mechanism, with DCR as a fallback for older clients. "
                              "FastMCP v3 supports CIMD natively.",
                code_example=(
                    "# FastMCP v3 — CIMD is the default registration mechanism\n"
                    "from fastmcp import FastMCP\n"
                    "from fastmcp.server.auth import OAuthProvider\n\n"
                    "mcp = FastMCP(\n"
                    "    name='My Server',\n"
                    "    auth=OAuthProvider(...)\n"
                    ")\n"
                    "# CIMD + DCR endpoints served automatically"
                ),
                remediation_effort=RemediationEffort.HIGH,
                remediation_priority=7,
            ))

    def _check_token_in_query_string(self) -> None:
        """AUTH-008: Flag if target URL contains token in query string.

        This is a structural check against the URL pattern, not a runtime
        traffic inspection. Catches servers that document or accept
        ?access_token= or ?token= patterns.
        """
        parsed = urlparse(self.target_url)
        query_params = parse_qs(parsed.query)

        token_params = {"access_token", "token", "bearer_token", "auth_token"}
        found_params = token_params.intersection(
            {k.lower() for k in query_params.keys()}
        )

        if found_params:
            self._add_finding(Finding(
                finding_id="MCP-AUTH-008",
                title="Bearer Token in URI Query String",
                auditor=Auditor.AUTH,
                severity=Severity.HIGH,
                cvss_score=6.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                cwe_id="CWE-598",
                cwe_name="Information Exposure Through Query Strings in GET Request",
                detection_mode=DetectionMode.ENDPOINT,
                confidence=Confidence.DEFINITIVE,
                detection_method=f"Token-like query parameter(s) detected in URL: {found_params}",
                remote_scan_applicable=True,
                standards=[
                    StandardReference(
                        id="MCP-SPEC-AUTH",
                        ref="modelcontextprotocol.io/specification/draft/basic/authorization",
                        section="Access Token Usage — MUST NOT include in URI query string",
                        requirement_level=RequirementLevel.MUST_NOT,
                    ),
                    StandardReference(
                        id="RFC6750",
                        ref="RFC 6750 §2",
                        section="Bearer Token Usage",
                        requirement_level=RequirementLevel.MUST_NOT,
                    ),
                    StandardReference(
                        id="OWASP-MCP01",
                        ref="OWASP MCP Top 10 v0.1",
                        section="MCP01 — Token Mismanagement & Secret Exposure",
                        requirement_level=RequirementLevel.NOT_APPLICABLE,
                    ),
                ],
                evidence=f"URL contains query parameter(s): {found_params}. "
                         "Tokens in query strings are exposed in server logs, "
                         "browser history, and HTTP referer headers.",
                risk="Tokens in query strings are logged by web servers, proxies, "
                     "and CDNs. They appear in browser history and HTTP Referer headers. "
                     "The spec explicitly forbids this pattern.",
                recommendation="Use Authorization: Bearer <token> header exclusively. "
                              "Never pass tokens via query parameters. "
                              "FastMCP clients and servers use header-based auth by default.",
                remediation_effort=RemediationEffort.LOW,
                remediation_priority=4,
            ))



    # ==================================================================
    # Active checks — M2
    # ==================================================================

    async def _check_audience_binding(self) -> None:
        """AUTH-003: Test audience binding by sending a wrong-audience token.

        Sends a request with a valid token whose 'aud' claim points to a
        different server. A compliant server MUST reject it with 401.
        """
        if not self.test_token:
            return

        mcp_url = self.target_url.rstrip("/") + "/mcp"
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1,
        }

        # First, send the legitimate test token to establish baseline
        try:
            client = await self.get_http_client()
            legit_response = await client.post(
                mcp_url,
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.test_token}",
                },
            )
        except Exception:
            return

        if legit_response.status_code not in (200, 401):
            return

        # Now craft a token with wrong audience
        # We modify the test token's audience by creating a new request
        # with the token but targeting a method that requires auth
        call_payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "read_data", "arguments": {"query": "test"}},
            "id": 2,
        }

        # Try with the test token first to see if it works at all
        try:
            authed_response = await client.post(
                mcp_url,
                json=call_payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.test_token}",
                },
            )
        except Exception:
            return

        # If the server accepts tool calls with the provided token,
        # we can test audience binding by crafting a wrong-audience token.
        # Since we can't craft JWTs for arbitrary servers, we use a
        # heuristic: check if the server validates the aud claim at all
        # by sending a token with a tampered payload section.

        # Create a clearly wrong token by replacing the middle segment
        parts = self.test_token.split(".")
        if len(parts) != 3:
            return

        import base64
        import json as json_mod

        try:
            # Decode payload (add padding)
            padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
            payload_bytes = base64.urlsafe_b64decode(padded)
            payload_data = json_mod.loads(payload_bytes)

            # Tamper the audience
            original_aud = payload_data.get("aud", "")
            payload_data["aud"] = "http://wrong-server.example.com"

            # Re-encode (signature will be invalid for compliant servers)
            new_payload = base64.urlsafe_b64encode(
                json_mod.dumps(payload_data).encode()
            ).rstrip(b"=").decode()
            tampered_token = f"{parts[0]}.{new_payload}.{parts[2]}"
        except Exception:
            return

        try:
            tampered_response = await client.post(
                mcp_url,
                json=call_payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {tampered_token}",
                },
            )
        except Exception:
            return

        # If server accepts the tampered token, audience is not enforced
        if tampered_response.status_code == 200:
            self._add_finding(Finding(
                finding_id="MCP-AUTH-003",
                title="Token Audience Binding Not Enforced",
                auditor=Auditor.AUTH,
                severity=Severity.CRITICAL,
                cvss_score=8.8,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-1270",
                cwe_name="Generation of Incorrect Security Identifiers",
                detection_mode=DetectionMode.ACTIVE,
                confidence=Confidence.HIGH,
                detection_method="Sent request with tampered JWT where aud claim was changed "
                                "to 'http://wrong-server.example.com'. Server accepted the "
                                "token and returned HTTP 200 instead of rejecting with 401.",
                remote_scan_applicable=True,
                standards=[
                    StandardReference(
                        id="MCP-SPEC-AUTH",
                        ref="modelcontextprotocol.io/specification/draft/basic/authorization",
                        section="Token Audience Binding — servers MUST validate aud claim",
                        requirement_level=RequirementLevel.MUST,
                    ),
                    StandardReference(
                        id="RFC8707",
                        ref="RFC 8707 §2",
                        section="Resource Indicators for OAuth 2.0",
                        requirement_level=RequirementLevel.MUST,
                    ),
                    StandardReference(
                        id="OWASP-MCP01",
                        ref="OWASP MCP Top 10 v0.1",
                        section="MCP01 — Token Mismanagement & Secret Exposure",
                        requirement_level=RequirementLevel.NOT_APPLICABLE,
                    ),
                    StandardReference(
                        id="OWASP-MCP07",
                        ref="OWASP MCP Top 10 v0.1",
                        section="MCP07 — Insufficient Authentication & Authorization",
                        requirement_level=RequirementLevel.NOT_APPLICABLE,
                    ),
                ],
                evidence=f"Sent tampered JWT with aud='http://wrong-server.example.com' to {mcp_url}. "
                         f"Server returned HTTP {tampered_response.status_code} (expected 401). "
                         f"Original audience: '{original_aud}'.",
                risk="Tokens issued for other services are accepted. Enables cross-service "
                     "token reuse and lateral movement across MCP deployments. In multi-agent "
                     "pipelines, a token stolen from one service can be replayed against this server.",
                recommendation="Validate the audience claim on every inbound token matches "
                              "your server's canonical URI. Reject tokens where aud does not match.",
                code_example=(
                    "# FastMCP v3 — audience validation via JWTVerifier\n"
                    "from fastmcp.server.auth import JWTVerifier\n\n"
                    "auth = JWTVerifier(\n"
                    "    jwks_uri='https://auth.example.com/.well-known/jwks.json',\n"
                    "    issuer='https://auth.example.com',\n"
                    "    audience='https://your-mcp-server.com'  # ✅ enforces aud\n"
                    ")"
                ),
                remediation_effort=RemediationEffort.MEDIUM,
                remediation_priority=1,
            ))

    async def _check_resource_indicator(self) -> None:
        """AUTH-007: Test resource indicator parameter enforcement.

        Checks if the server's token endpoint accepts requests without the
        'resource' parameter. Per spec, tokens MUST be bound to a resource.
        We verify by checking if the Protected Resource Metadata advertises
        resource binding and if the AS metadata supports resource indicators.
        """
        if not self.test_token:
            return

        base_url = self.target_url.rstrip("/")

        # Check Protected Resource Metadata for resource field
        pr_metadata = await self._try_fetch_json(
            f"{base_url}/.well-known/oauth-protected-resource"
        )

        # Check AS metadata for resource indicator support
        as_metadata = await self._try_fetch_json(
            f"{base_url}/.well-known/oauth-authorization-server"
        )

        issues = []

        if pr_metadata:
            if "resource" not in pr_metadata:
                issues.append(
                    "Protected Resource Metadata missing 'resource' field — "
                    "clients cannot determine the resource identifier for token requests"
                )

        if as_metadata:
            # Check if the server supports resource indicators
            grant_types = as_metadata.get("grant_types_supported", [])
            # Servers that support resource indicators typically
            # advertise it in their metadata
            if "resource_indicators_supported" in as_metadata:
                if not as_metadata["resource_indicators_supported"]:
                    issues.append(
                        "AS metadata explicitly sets resource_indicators_supported=false"
                    )

        # Active check: send a tool call and inspect if the token
        # was audience-bound (complementary to AUTH-003)
        mcp_url = f"{base_url}/mcp"
        call_payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "read_data", "arguments": {"query": "test"}},
            "id": 1,
        }

        try:
            client = await self.get_http_client()
            response = await client.post(
                mcp_url,
                json=call_payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.test_token}",
                },
            )

            # If the server accepts any token without resource binding,
            # the resource indicator flow is not enforced
            if response.status_code == 200 and pr_metadata and "resource" not in pr_metadata:
                issues.append(
                    f"Server accepted tool call (HTTP {response.status_code}) "
                    "despite missing resource identifier in metadata — "
                    "tokens may not be audience-bound"
                )
        except Exception:
            pass

        if not issues:
            return

        self._add_finding(Finding(
            finding_id="MCP-AUTH-007",
            title="Resource Indicator Parameter Not Enforced",
            auditor=Auditor.AUTH,
            severity=Severity.HIGH,
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
            cwe_id="CWE-346",
            cwe_name="Origin Validation Error",
            detection_mode=DetectionMode.ACTIVE,
            confidence=Confidence.HIGH,
            detection_method="Inspected Protected Resource Metadata and AS Metadata for "
                            "resource indicator support. Verified token binding via active probing.",
            remote_scan_applicable=True,
            standards=[
                StandardReference(
                    id="MCP-SPEC-AUTH",
                    ref="modelcontextprotocol.io/specification/draft/basic/authorization",
                    section="Resource Parameter Implementation — MUST include resource parameter",
                    requirement_level=RequirementLevel.MUST,
                ),
                StandardReference(
                    id="RFC8707",
                    ref="RFC 8707",
                    section="Resource Indicators for OAuth 2.0",
                    requirement_level=RequirementLevel.MUST,
                ),
                StandardReference(
                    id="RFC9728",
                    ref="RFC 9728 §7.4",
                    section="Protected Resource Metadata — resource field",
                    requirement_level=RequirementLevel.MUST,
                ),
                StandardReference(
                    id="OWASP-MCP01",
                    ref="OWASP MCP Top 10 v0.1",
                    section="MCP01 — Token Mismanagement & Secret Exposure",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
            ],
            evidence="Resource indicator issues:\n" + "\n".join(f"  - {i}" for i in issues),
            risk="Without the resource parameter, tokens are not bound to their intended "
                 "audience at issuance time. Tokens can potentially be replayed against "
                 "other services. The spec states MCP clients MUST send this parameter "
                 "regardless of whether authorization servers support it.",
            recommendation="Include the 'resource' field in Protected Resource Metadata. "
                          "Ensure the authorization server binds tokens to the resource parameter. "
                          "Validate resource binding on every token.",
            code_example=(
                "# Protected Resource Metadata must include 'resource'\n"
                "{\n"
                "    'resource': 'https://your-mcp-server.com',\n"
                "    'authorization_servers': ['https://auth.example.com'],\n"
                "    'scopes_supported': ['read', 'write']\n"
                "}"
            ),
            remediation_effort=RemediationEffort.MEDIUM,
            remediation_priority=3,
        ))

    async def _check_scope_error_handling(self) -> None:
        """AUTH-010: Test insufficient scope error response format.

        Sends a request with a valid but under-privileged token to a tool
        that requires higher scope. Checks if the server responds with:
            - HTTP 403
            - WWW-Authenticate: Bearer error="insufficient_scope", scope="..."

        A non-compliant server returns generic 403 with no guidance.
        """
        if not self.test_token:
            return

        mcp_url = self.target_url.rstrip("/") + "/mcp"

        # First, get tools list to find a tool to test against
        try:
            client = await self.get_http_client()
            init_response = await client.post(
                mcp_url,
                json={
                    "jsonrpc": "2.0",
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {},
                        "clientInfo": {"name": "mcpsec-scanner", "version": "0.1.0"},
                    },
                    "id": 1,
                },
                headers={"Content-Type": "application/json"},
            )
        except Exception:
            return

        # Try calling a tool with the test token — if the token has
        # limited scope, the server should return proper 403
        call_payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "admin_delete", "arguments": {"target": "test"}},
            "id": 2,
        }

        try:
            response = await client.post(
                mcp_url,
                json=call_payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.test_token}",
                },
            )
        except Exception:
            return

        # We're looking for a 403 response
        if response.status_code != 403:
            # Server either accepted (no scope enforcement) or returned
            # something else — AUTH-010 specifically checks 403 format
            return

        # Server returned 403 — check the WWW-Authenticate header format
        www_auth = response.headers.get("www-authenticate", "")

        issues = []

        if not www_auth:
            issues.append("403 response has no WWW-Authenticate header")

        elif 'error="insufficient_scope"' not in www_auth:
            issues.append(
                f"WWW-Authenticate header present but missing "
                f'error="insufficient_scope". Got: {www_auth}'
            )

        elif "scope=" not in www_auth:
            issues.append(
                "WWW-Authenticate has error=\"insufficient_scope\" but "
                "missing scope parameter — client cannot determine required scopes"
            )

        if not issues:
            return

        self._add_finding(Finding(
            finding_id="MCP-AUTH-010",
            title="Insufficient Scope Error Handling Non-Compliant",
            auditor=Auditor.AUTH,
            severity=Severity.MEDIUM,
            cvss_score=5.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
            cwe_id="CWE-285",
            cwe_name="Improper Authorization",
            detection_mode=DetectionMode.ACTIVE,
            confidence=Confidence.DEFINITIVE,
            detection_method="Sent tool call with insufficient scope token. "
                            "Server returned 403 but WWW-Authenticate header does not "
                            "conform to spec requirements.",
            remote_scan_applicable=True,
            standards=[
                StandardReference(
                    id="MCP-SPEC-AUTH",
                    ref="modelcontextprotocol.io/specification/draft/basic/authorization",
                    section="Scope Challenge Handling — SHOULD respond with proper 403",
                    requirement_level=RequirementLevel.SHOULD,
                ),
                StandardReference(
                    id="RFC6750",
                    ref="RFC 6750 §3.1",
                    section="Error Codes — insufficient_scope",
                    requirement_level=RequirementLevel.SHOULD,
                ),
                StandardReference(
                    id="OWASP-MCP02",
                    ref="OWASP MCP Top 10 v0.1",
                    section="MCP02 — Privilege Escalation via Scope Creep",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
            ],
            evidence=f"POST {mcp_url} with limited-scope token → HTTP 403.\n"
                     f"WWW-Authenticate: '{www_auth or '(absent)'}'\n"
                     f"Issues:\n" + "\n".join(f"  - {i}" for i in issues),
            risk="Breaks the step-up authorization flow. Clients cannot request "
                 "additional scopes programmatically. The spec requires 403 responses "
                 "to include WWW-Authenticate with error=\"insufficient_scope\" and "
                 "the required scope list.",
            recommendation="Return proper 403 with WWW-Authenticate header: "
                          'Bearer error="insufficient_scope", scope="required_scope". '
                          "FastMCP handles this automatically with require_scopes().",
            code_example=(
                "# Correct 403 response format:\n"
                "# HTTP/1.1 403 Forbidden\n"
                '# WWW-Authenticate: Bearer error="insufficient_scope", scope="admin"\n\n'
                "# FastMCP handles this automatically:\n"
                "from fastmcp.server.auth import require_scopes\n\n"
                "@mcp.tool()\n"
                "@require_scopes('admin')\n"
                "def admin_delete(target: str) -> str:\n"
                "    ...  # 403 with proper header returned automatically"
            ),
            remediation_effort=RemediationEffort.LOW,
            remediation_priority=6,
        ))

    # ==================================================================
    # Static checks — M2 stubs
    # ==================================================================

    def _check_token_passthrough(self) -> None:
        """AUTH-002: Detect token passthrough in source code (M2 — requires source)."""
        # TODO M2: Use semgrep rules to detect patterns like:
        #   - Forwarding Authorization header to upstream requests
        #   - Using inbound token in outbound httpx/requests calls
        pass

    # ==================================================================
    # Helpers
    # ==================================================================

    async def _try_fetch_json(self, url: str) -> Optional[dict[str, Any]]:
        """Attempt to fetch a URL and parse as JSON. Returns None on any failure."""
        try:
            response = await self.http_get(url)
            if response.status_code == 200:
                return response.json()
        except (TargetConnectionError, Exception):
            pass
        return None
