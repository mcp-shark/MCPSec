"""MCPSec — Transport Security Auditor.

Validates MCP server transport layer compliance with the MCP specification,
including transport type, SSRF protection, and session security.

M1 scope: Endpoint detection mode (TRANS-001, TRANS-002)
M2 scope: Active mode (TRANS-003, TRANS-004)
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from mcpsec.exceptions import TargetConnectionError
from mcpsec.models.findings import (
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


# ---------------------------------------------------------------------------
# SSRF detection constants
# ---------------------------------------------------------------------------

# Private / reserved IP ranges that should never appear in metadata URLs
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local / cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),             # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),            # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),           # IPv6 link-local
    ipaddress.ip_network("fd00:ec2::/32"),       # AWS EC2 IPv6 metadata
]

# Known cloud metadata hostnames / IPs
_CLOUD_METADATA_INDICATORS = {
    "169.254.169.254",       # AWS / GCP / Azure metadata
    "metadata.google.internal",
    "metadata.goog",
    "100.100.100.200",       # Alibaba Cloud metadata
}


class TransportAuditor(BaseAuditor):
    """Audits MCP server transport layer security.

    Endpoint checks (M1 — zero credentials):
        TRANS-001  Deprecated SSE transport in use
        TRANS-002  SSRF-vulnerable metadata URL detected

    Active checks (M2 — requires session interaction):
        TRANS-003  Session ID low entropy
        TRANS-004  Session binding not enforced
    """

    @property
    def auditor_type(self) -> Auditor:
        return Auditor.TRANSPORT

    async def audit(self) -> list[Finding]:
        """Run all transport checks appropriate for the current access level."""
        self._clear_findings()

        if not self.target_url:
            return self._findings

        # --- Endpoint checks (M1) ---
        if self._should_run_check(DetectionMode.ENDPOINT):
            await self._check_sse_transport()
            await self._check_ssrf_metadata_urls()

        # --- Active checks (M2 stub) ---
        if self._should_run_check(DetectionMode.ACTIVE):
            await self._check_session_entropy()
            await self._check_session_binding()

        return self._findings

    # ==================================================================
    # Endpoint checks — M1
    # ==================================================================

    async def _check_sse_transport(self) -> None:
        """TRANS-001: Detect deprecated SSE transport.

        Probes for SSE-specific endpoints that indicate the server is using
        the deprecated HTTP+SSE transport instead of Streamable HTTP.
        """
        base_url = self.target_url.rstrip("/")

        # SSE servers typically expose /sse endpoint for event streams
        # Streamable HTTP servers expose /mcp
        sse_indicators = []

        # Check for /sse endpoint (classic SSE transport pattern)
        try:
            response = await self.http_get(
                f"{base_url}/sse",
                headers={"Accept": "text/event-stream"},
            )
            content_type = response.headers.get("content-type", "")

            if response.status_code == 200 and "text/event-stream" in content_type:
                sse_indicators.append(
                    f"GET /sse returned 200 with Content-Type: {content_type}"
                )
        except TargetConnectionError:
            pass

        # Check response headers for SSE-specific patterns
        try:
            response = await self.http_get(base_url)
            server_header = response.headers.get("server", "").lower()

            # Some SSE implementations advertise in headers
            if "sse" in server_header:
                sse_indicators.append(
                    f"Server header contains SSE indicator: '{response.headers.get('server')}'"
                )
        except TargetConnectionError:
            pass

        # Check that /mcp endpoint does NOT exist (strong SSE signal)
        mcp_endpoint_exists = False
        try:
            response = await self.http_get(f"{base_url}/mcp")
            if response.status_code != 404:
                mcp_endpoint_exists = True
        except TargetConnectionError:
            pass

        if sse_indicators:
            self._add_finding(Finding(
                finding_id="MCP-TRANS-001",
                title="Deprecated SSE Transport in Use",
                auditor=Auditor.TRANSPORT,
                severity=Severity.HIGH,
                cvss_score=4.3,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                cwe_id="CWE-477",
                cwe_name="Use of Obsolete Function",
                detection_mode=DetectionMode.ENDPOINT,
                confidence=Confidence.HIGH,
                detection_method="Probed for SSE-specific endpoints and response patterns. "
                                "Detected SSE transport indicators.",
                remote_scan_applicable=True,
                standards=[
                    StandardReference(
                        id="MCP-SPEC-TRANSPORT",
                        ref="modelcontextprotocol.io/specification/draft/basic/transports",
                        section="SSE transport deprecated as of 2024-11-05 spec",
                        requirement_level=RequirementLevel.SHOULD_NOT,
                    ),
                    StandardReference(
                        id="OWASP-MCP07",
                        ref="OWASP MCP Top 10 v0.1",
                        section="MCP07 — Insufficient Authentication & Authorization",
                        requirement_level=RequirementLevel.NOT_APPLICABLE,
                    ),
                ],
                evidence=f"SSE transport indicators detected: {'; '.join(sse_indicators)}. "
                         f"Streamable HTTP /mcp endpoint {'found' if mcp_endpoint_exists else 'not found'}.",
                risk="SSE transport is deprecated since the 2024-11-05 MCP spec revision. "
                     "It will eventually lose client support. SSE lacks Streamable HTTP's "
                     "session management improvements and bidirectional communication. "
                     "Continued use increases migration cost over time.",
                recommendation="Migrate from SSE to Streamable HTTP transport. "
                              "FastMCP v3 uses Streamable HTTP by default.",
                code_example=(
                    "# FastMCP v3 — Streamable HTTP is the default\n"
                    "fastmcp run server.py --transport http --host 127.0.0.1 --port 8000\n\n"
                    "# Server is now accessible at http://127.0.0.1:8000/mcp\n"
                    "# Replace any SSE client configuration to point to /mcp endpoint"
                ),
                remediation_effort=RemediationEffort.MEDIUM,
                remediation_priority=6,
            ))

    async def _check_ssrf_metadata_urls(self) -> None:
        """TRANS-002: Check OAuth metadata responses for SSRF-vulnerable URLs.

        Inspects Protected Resource Metadata and AS Metadata for URLs
        pointing to private IPs, cloud metadata endpoints, or link-local addresses.
        """
        base_url = self.target_url.rstrip("/")
        ssrf_findings: list[dict[str, str]] = []

        # Collect all metadata URLs to inspect
        urls_to_check: list[tuple[str, str]] = []

        # Fetch Protected Resource Metadata
        pr_metadata = await self._try_fetch_json(
            f"{base_url}/.well-known/oauth-protected-resource"
        )
        if pr_metadata:
            # Check authorization_servers URLs
            for server_url in pr_metadata.get("authorization_servers", []):
                urls_to_check.append(("authorization_servers", server_url))

        # Fetch AS Metadata
        as_metadata = await self._try_fetch_json(
            f"{base_url}/.well-known/oauth-authorization-server"
        )
        if as_metadata:
            url_fields = [
                "authorization_endpoint",
                "token_endpoint",
                "registration_endpoint",
                "jwks_uri",
                "userinfo_endpoint",
                "revocation_endpoint",
                "introspection_endpoint",
            ]
            for field in url_fields:
                if field in as_metadata:
                    urls_to_check.append((field, as_metadata[field]))

        # Check each URL for SSRF indicators
        for field_name, url in urls_to_check:
            ssrf_issue = self._check_url_for_ssrf(url)
            if ssrf_issue:
                ssrf_findings.append({
                    "field": field_name,
                    "url": url,
                    "reason": ssrf_issue,
                })

        if ssrf_findings:
            evidence_parts = [
                f"  - {f['field']}: {f['url']} → {f['reason']}"
                for f in ssrf_findings
            ]

            self._add_finding(Finding(
                finding_id="MCP-TRANS-002",
                title="SSRF-Vulnerable Metadata URL Detected",
                auditor=Auditor.TRANSPORT,
                severity=Severity.CRITICAL,
                cvss_score=9.0,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                cwe_id="CWE-918",
                cwe_name="Server-Side Request Forgery (SSRF)",
                detection_mode=DetectionMode.ENDPOINT,
                confidence=Confidence.HIGH,
                detection_method="Parsed OAuth metadata responses and checked all URL fields "
                                "for private IPs, cloud metadata endpoints, and reserved ranges.",
                remote_scan_applicable=True,
                standards=[
                    StandardReference(
                        id="MCP-SPEC-AUTH",
                        ref="modelcontextprotocol.io/specification/draft/basic/authorization",
                        section="Client ID Metadata Document Security — SSRF risk",
                        requirement_level=RequirementLevel.MUST,
                    ),
                    StandardReference(
                        id="OWASP-MCP07",
                        ref="OWASP MCP Top 10 v0.1",
                        section="MCP07 — Insufficient Authentication & Authorization",
                        requirement_level=RequirementLevel.NOT_APPLICABLE,
                    ),
                    StandardReference(
                        id="OWASP-LLM07",
                        ref="OWASP Top 10 for LLM Applications 2025",
                        section="LLM07 — System Prompt Leakage (via SSRF)",
                        requirement_level=RequirementLevel.NOT_APPLICABLE,
                    ),
                ],
                evidence=f"SSRF-vulnerable URLs in OAuth metadata:\n"
                         + "\n".join(evidence_parts),
                risk="A malicious client can supply metadata URLs pointing to internal "
                     "endpoints (AWS metadata at 169.254.169.254, internal admin panels, "
                     "cloud provider APIs). The MCP spec explicitly calls out SSRF risk "
                     "in Client ID Metadata Document handling. This is the attack vector "
                     "that enabled CVE-2025-6514's class of vulnerability.",
                recommendation="Validate all URLs in OAuth metadata responses before following them. "
                              "Reject URLs pointing to: private IP ranges (10.x, 172.16-31.x, 192.168.x), "
                              "link-local (169.254.x), cloud metadata (169.254.169.254), "
                              "and localhost (unless the server itself is localhost). "
                              "Use an allowlist of permitted URL schemes (https only for remote).",
                code_example=(
                    "# URL validation helper for SSRF prevention\n"
                    "import ipaddress\n"
                    "from urllib.parse import urlparse\n\n"
                    "def is_safe_url(url: str) -> bool:\n"
                    "    parsed = urlparse(url)\n"
                    "    if parsed.scheme != 'https':\n"
                    "        return False\n"
                    "    try:\n"
                    "        ip = ipaddress.ip_address(parsed.hostname)\n"
                    "        return ip.is_global\n"
                    "    except ValueError:\n"
                    "        # Hostname, not IP — resolve and check\n"
                    "        return True  # DNS resolution check recommended\n"
                ),
                remediation_effort=RemediationEffort.MEDIUM,
                remediation_priority=2,
            ))

    

    # ==================================================================
    # Active checks — M2
    # ==================================================================

    async def _check_session_entropy(self) -> None:
        """TRANS-003: Analyze session ID entropy.

        Collects multiple session IDs from the server and measures
        Shannon entropy and effective bit length. Flags if below
        NIST SP 800-63B minimum of 112 bits.
        """
        base_url = self.target_url.rstrip("/")
        session_ids: list[str] = []
        sample_size = 10

        try:
            client = await self.get_http_client()
        except Exception:
            return

        # Collect session IDs via /session endpoint if available
        session_url = f"{base_url}/session"
        try:
            for _ in range(sample_size):
                response = await client.post(session_url)
                if response.status_code == 200:
                    data = response.json()
                    sid = data.get("session_id", "")
                    if sid:
                        session_ids.append(sid)
        except Exception:
            pass

        # Fallback: collect from MCP endpoint via mcp-session-id header
        if len(session_ids) < 3:
            mcp_url = f"{base_url}/mcp"
            init_payload = {
                "jsonrpc": "2.0",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "mcpsec-scanner", "version": "0.1.0"},
                },
                "id": 1,
            }
            try:
                for _ in range(sample_size):
                    response = await client.post(
                        mcp_url,
                        json=init_payload,
                        headers={"Content-Type": "application/json"},
                    )
                    sid = response.headers.get("mcp-session-id", "")
                    if sid:
                        session_ids.append(sid)
            except Exception:
                pass

        if len(session_ids) < 3:
            return

        # Analyze entropy
        avg_length = sum(len(s) for s in session_ids) / len(session_ids)
        charset_size = len(set("".join(session_ids)))
        avg_entropy = self._calculate_avg_entropy(session_ids)

        # Estimate effective bits: log2(charset_size) * avg_length
        import math
        if charset_size > 1 and avg_length > 0:
            bits_per_char = math.log2(charset_size)
            effective_bits = bits_per_char * avg_length
        else:
            effective_bits = 0.0

        # Check for sequential/predictable patterns
        is_sequential = self._detect_sequential(session_ids)

        # NIST SP 800-63B minimum: 112 bits
        nist_minimum = 112.0

        issues = []

        if effective_bits < nist_minimum:
            issues.append(
                f"Effective entropy: ~{effective_bits:.0f} bits "
                f"(NIST minimum: {nist_minimum:.0f} bits)"
            )

        if is_sequential:
            issues.append(
                "Session IDs appear sequential or predictable — "
                f"samples: {session_ids[:5]}"
            )

        if avg_entropy < 3.0:
            issues.append(
                f"Low Shannon entropy: {avg_entropy:.2f} bits/char "
                f"(expected >4.0 for random strings)"
            )

        if not issues:
            return

        self._add_finding(Finding(
            finding_id="MCP-TRANS-003",
            title="Session ID Low Entropy",
            auditor=Auditor.TRANSPORT,
            severity=Severity.HIGH,
            cvss_score=7.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            cwe_id="CWE-331",
            cwe_name="Insufficient Entropy",
            detection_mode=DetectionMode.ACTIVE,
            confidence=Confidence.HIGH,
            detection_method=f"Collected {len(session_ids)} session IDs and analyzed entropy. "
                            f"Avg length: {avg_length:.0f} chars, charset size: {charset_size}, "
                            f"effective bits: ~{effective_bits:.0f}, Shannon entropy: {avg_entropy:.2f}.",
            remote_scan_applicable=True,
            standards=[
                StandardReference(
                    id="MCP-SPEC-TRANSPORT",
                    ref="modelcontextprotocol.io/specification/draft/basic/transports",
                    section="Session Management — session ID entropy",
                    requirement_level=RequirementLevel.MUST,
                ),
                StandardReference(
                    id="NIST-SP800-63B",
                    ref="NIST SP 800-63B",
                    section="Session identifiers — minimum 112 bits of entropy",
                    requirement_level=RequirementLevel.MUST,
                ),
                StandardReference(
                    id="OWASP-MCP07",
                    ref="OWASP MCP Top 10 v0.1",
                    section="MCP07 — Insufficient Authentication & Authorization",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
            ],
            evidence=f"Session ID analysis ({len(session_ids)} samples):\n"
                     + "\n".join(f"  - {i}" for i in issues)
                     + f"\n  Sample IDs: {session_ids[:3]}",
            risk="Low-entropy or predictable session IDs can be brute-forced or guessed. "
                 "An attacker who predicts a valid session ID can hijack an active MCP "
                 "session, gaining access to all tools and data the session owner has.",
            recommendation="Use cryptographically secure random session IDs with at least "
                          "112 bits of entropy (NIST SP 800-63B). "
                          "Python: secrets.token_urlsafe(32) provides 256 bits.",
            code_example=(
                "import secrets\n\n"
                "# BAD — predictable session IDs\n"
                "session_id = str(counter)       # ❌ sequential\n"
                "session_id = str(uuid.uuid4())  # ⚠️ only 122 bits, not crypto-random\n\n"
                "# GOOD — cryptographically secure\n"
                "session_id = secrets.token_urlsafe(32)  # ✅ 256 bits"
            ),
            remediation_effort=RemediationEffort.LOW,
            remediation_priority=4,
        ))

    async def _check_session_binding(self) -> None:
        """TRANS-004: Test session binding enforcement.

        Obtains a session ID, then attempts to reuse it with a different
        client identity. A compliant server MUST reject the reuse.
        """
        base_url = self.target_url.rstrip("/")
        mcp_url = f"{base_url}/mcp"

        init_payload = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "mcpsec-scanner", "version": "0.1.0"},
            },
            "id": 1,
        }

        # Step 1: Obtain a session from the server
        try:
            client = await self.get_http_client()
            response = await client.post(
                mcp_url,
                json=init_payload,
                headers={"Content-Type": "application/json"},
            )
        except Exception:
            return

        session_id = response.headers.get("mcp-session-id", "")
        if not session_id:
            return

        # Step 2: Replay the session ID with a spoofed client identity
        # We send the same session but with X-Forwarded-For header
        # to simulate a different client origin
        tools_payload = {
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 2,
        }

        spoofed_headers = {
            "Content-Type": "application/json",
            "mcp-session-id": session_id,
            "X-Forwarded-For": "203.0.113.99",
            "X-Real-IP": "203.0.113.99",
        }

        try:
            replay_response = await client.post(
                mcp_url,
                json=tools_payload,
                headers=spoofed_headers,
            )
        except Exception:
            return

        # Step 3: Check if the server accepted the replayed session
        # A compliant server should reject or at least not blindly trust it
        # Note: testing from the same IP with spoofed headers is a
        # heuristic — a definitive test would require two different IPs

        # Also test with a completely fabricated session ID
        fake_session_id = "fake-session-" + session_id[:8]
        fake_headers = {
            "Content-Type": "application/json",
            "mcp-session-id": fake_session_id,
        }

        try:
            fake_response = await client.post(
                mcp_url,
                json=tools_payload,
                headers=fake_headers,
            )
        except Exception:
            return

        issues = []

        # If the server accepts a fabricated session ID, binding is absent
        if fake_response.status_code == 200:
            issues.append(
                f"Server accepted fabricated session ID '{fake_session_id}' "
                f"(HTTP {fake_response.status_code}) — no session validation"
            )

        # If X-Forwarded-For changes are accepted, IP binding may be absent
        if replay_response.status_code == 200:
            replay_session = replay_response.headers.get("mcp-session-id", "")
            if replay_session == session_id:
                issues.append(
                    f"Session '{session_id[:16]}...' accepted with spoofed "
                    f"X-Forwarded-For: 203.0.113.99 — IP binding may not be enforced"
                )

        if not issues:
            return

        self._add_finding(Finding(
            finding_id="MCP-TRANS-004",
            title="Session Binding Not Enforced",
            auditor=Auditor.TRANSPORT,
            severity=Severity.HIGH,
            cvss_score=7.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            cwe_id="CWE-384",
            cwe_name="Session Fixation",
            detection_mode=DetectionMode.ACTIVE,
            confidence=Confidence.MEDIUM,
            detection_method="Obtained a valid session ID, then attempted replay with "
                            "spoofed client identity headers and fabricated session IDs. "
                            "Server accepted one or both — session binding not enforced.",
            remote_scan_applicable=True,
            remote_heuristic=RemoteHeuristic(
                available=True,
                confidence=Confidence.MEDIUM,
                description="Tested with spoofed X-Forwarded-For and fabricated session ID. "
                           "Definitive test requires requests from two different source IPs.",
            ),
            standards=[
                StandardReference(
                    id="MCP-SPEC-TRANSPORT",
                    ref="modelcontextprotocol.io/specification/draft/basic/transports",
                    section="Session Management — session binding",
                    requirement_level=RequirementLevel.SHOULD,
                ),
                StandardReference(
                    id="OWASP-MCP07",
                    ref="OWASP MCP Top 10 v0.1",
                    section="MCP07 — Insufficient Authentication & Authorization",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
            ],
            evidence=f"Session binding test against {mcp_url}:\n"
                     + "\n".join(f"  - {i}" for i in issues),
            risk="Sessions not bound to their originating client can be hijacked. "
                 "An attacker who obtains a valid session ID (via network sniffing, "
                 "log exposure, or prediction) can impersonate the original client "
                 "and access all their tools and data.",
            recommendation="Bind sessions to the originating client's IP address or "
                          "TLS client certificate. Reject session IDs presented from "
                          "a different client than the one that created the session. "
                          "Validate session IDs exist in the session store before accepting.",
            code_example=(
                "import secrets\n\n"
                "class SessionManager:\n"
                "    def create(self, client_ip: str) -> str:\n"
                "        sid = secrets.token_urlsafe(32)\n"
                "        self._sessions[sid] = {'ip': client_ip}  # ✅ bind to IP\n"
                "        return sid\n\n"
                "    def validate(self, sid: str, client_ip: str) -> bool:\n"
                "        session = self._sessions.get(sid)\n"
                "        if not session:\n"
                "            return False  # ✅ reject unknown sessions\n"
                "        return session['ip'] == client_ip  # ✅ enforce binding"
            ),
            remediation_effort=RemediationEffort.MEDIUM,
            remediation_priority=5,
        ))

    # ==================================================================
    # Entropy analysis helpers
    # ==================================================================

    @staticmethod
    def _calculate_avg_entropy(session_ids: list[str]) -> float:
        """Calculate average Shannon entropy across session IDs."""
        import math

        if not session_ids:
            return 0.0

        total = 0.0
        for sid in session_ids:
            if not sid:
                continue
            freq: dict[str, int] = {}
            for ch in sid:
                freq[ch] = freq.get(ch, 0) + 1
            entropy = 0.0
            length = len(sid)
            for count in freq.values():
                prob = count / length
                if prob > 0:
                    entropy -= prob * math.log2(prob)
            total += entropy

        return total / len(session_ids)

    @staticmethod
    def _detect_sequential(session_ids: list[str]) -> bool:
        """Detect if session IDs follow a sequential pattern."""
        # Try to parse as integers
        try:
            nums = [int(s) for s in session_ids]
            diffs = [nums[i + 1] - nums[i] for i in range(len(nums) - 1)]
            if len(set(diffs)) == 1:
                return True
        except (ValueError, TypeError):
            pass

        # Check if IDs share a long common prefix with incrementing suffix
        if len(session_ids) >= 2:
            prefix_len = 0
            s0, s1 = session_ids[0], session_ids[1]
            for a, b in zip(s0, s1):
                if a == b:
                    prefix_len += 1
                else:
                    break
            if prefix_len > 0 and prefix_len >= len(s0) * 0.8:
                return True

        return False


    # ==================================================================
    # Helpers
    # ==================================================================

    def _check_url_for_ssrf(self, url: str) -> Optional[str]:
        """Check a single URL for SSRF indicators.

        Returns a reason string if vulnerable, None if safe.
        """
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return "Empty or unparseable hostname"

        # Check against known cloud metadata indicators
        if hostname in _CLOUD_METADATA_INDICATORS:
            return f"Cloud metadata endpoint: {hostname}"

        # Try to parse as IP address
        try:
            ip = ipaddress.ip_address(hostname)

            # Check against all private/reserved ranges
            for network in _PRIVATE_NETWORKS:
                if ip in network:
                    return f"Private/reserved IP range: {hostname} in {network}"

            # Additional check for non-global IPs
            if not ip.is_global:
                return f"Non-global IP address: {hostname}"

        except ValueError:
            # Not an IP — check for suspicious hostname patterns
            hostname_lower = hostname.lower()

            # Check for localhost aliases
            if hostname_lower in ("localhost", "localhost.localdomain"):
                # localhost is permitted if the MCP server itself is localhost
                server_host = urlparse(self.target_url).hostname
                if server_host not in ("localhost", "127.0.0.1", "::1", "[::1]"):
                    return f"Localhost reference from non-localhost server: {hostname}"
                return None 

            # Check for metadata subdomains
            if any(
                indicator in hostname_lower
                for indicator in ("metadata", "internal", "local")
            ):
                return f"Suspicious hostname pattern: {hostname}"

        # Check scheme — non-HTTPS in metadata is suspicious for remote
        if parsed.scheme and parsed.scheme != "https":
            server_host = urlparse(self.target_url).hostname
            localhost_names = {"localhost", "127.0.0.1", "::1", "[::1]"}
            if server_host not in localhost_names:
                return f"Non-HTTPS scheme in metadata URL: {parsed.scheme}://"

        return None

    async def _try_fetch_json(self, url: str) -> Optional[dict]:
        """Attempt to fetch a URL and parse as JSON. Returns None on failure."""
        try:
            response = await self.http_get(url)
            if response.status_code == 200:
                return response.json()
        except (TargetConnectionError, Exception):
            pass
        return None
