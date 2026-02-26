"""MCPSec — Authorization Model Auditor.

Validates MCP server authorization patterns against the FastMCP baseline
and OWASP MCP Top 10 scope/permission requirements.

M1 scope: Introspection mode (AUTHZ-002, AUTHZ-003) via MCP tools/list
M2 scope: Active mode (AUTHZ-001, AUTHZ-004) via token probing
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

import httpx

from mcpsec.exceptions import MCPProtocolError, TargetConnectionError
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
# Patterns indicating privileged/admin tools
# ---------------------------------------------------------------------------

_PRIVILEGED_TOOL_PATTERNS = re.compile(
    r"(admin|delete|remove|drop|destroy|execute|exec|eval|sudo|root|"
    r"shell|command|deploy|migrate|truncate|purge|reset|override|"
    r"write_all|grant|revoke|impersonate|escalat)",
    re.IGNORECASE,
)

_WILDCARD_SCOPE_PATTERNS = re.compile(
    r"^(\*|all|admin:\*|.+:\*|full[_-]?access|superuser|root)$",
    re.IGNORECASE,
)

_BROAD_SCOPE_PATTERNS = re.compile(
    r"^(read[_-]?write|admin|full|manage|all[_-]?access)$",
    re.IGNORECASE,
)


class AuthorizationAuditor(BaseAuditor):
    """Audits MCP server authorization model against FastMCP baseline.

    Introspection checks (M1 — MCP client connection):
        AUTHZ-002  No per-tool scope requirements
        AUTHZ-003  Wildcard or overly broad scope definitions

    Active checks (M2 — requires test tokens):
        AUTHZ-001  Admin/privileged tool without authorization check
        AUTHZ-004  Privilege escalation via scope manipulation
    """

    @property
    def auditor_type(self) -> Auditor:
        return Auditor.AUTHORIZATION

    async def audit(self) -> list[Finding]:
        """Run all authorization checks appropriate for the current access level."""
        self._clear_findings()

        if not self.target_url:
            return self._findings

        # --- Introspection checks (M1) ---
        if self._should_run_check(DetectionMode.INTROSPECTION):
            tools = await self._get_tools_list()
            scopes_supported = await self._get_scopes_supported()

            if tools is not None:
                self._check_per_tool_scopes(tools, scopes_supported)
            if scopes_supported is not None:
                self._check_wildcard_scopes(scopes_supported)

        # --- Active checks (M2 stubs) ---
        if self._should_run_check(DetectionMode.ACTIVE):
            await self._check_admin_tool_auth()
            await self._check_scope_escalation()

        return self._findings

    # ==================================================================
    # MCP Protocol introspection helpers
    # ==================================================================

    async def _mcp_request(
        self, method: str, params: Optional[dict] = None
    ) -> Optional[dict[str, Any]]:
        """Send a JSON-RPC 2.0 request to the MCP server.

        Handles the Streamable HTTP transport protocol:
        POST to /mcp with JSON-RPC payload.
        """
        mcp_url = self.target_url.rstrip("/") + "/mcp"
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "id": 1,
        }
        if params:
            payload["params"] = params

        try:
            client = await self.get_http_client()
            response = await client.post(
                mcp_url,
                json=payload,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json, text/event-stream",
                },
            )
        except (httpx.ConnectError, httpx.TimeoutException):
            return None

        if response.status_code == 401:
            # Server requires auth — we can't introspect without tokens
            return None

        if response.status_code != 200:
            return None

        # Handle both direct JSON and SSE-wrapped responses
        content_type = response.headers.get("content-type", "")

        if "text/event-stream" in content_type:
            return self._parse_sse_response(response.text)

        try:
            result = response.json()
            if "result" in result:
                return result["result"]
            if "error" in result:
                return None
        except Exception:
            return None

        return None

    def _parse_sse_response(self, text: str) -> Optional[dict[str, Any]]:
        """Extract JSON-RPC result from an SSE event stream response."""
        for line in text.split("\n"):
            line = line.strip()
            if line.startswith("data:"):
                data_str = line[5:].strip()
                try:
                    data = json.loads(data_str)
                    if "result" in data:
                        return data["result"]
                except (json.JSONDecodeError, KeyError):
                    continue
        return None

    async def _mcp_initialize(self) -> Optional[dict[str, Any]]:
        """Send MCP initialize request to establish protocol session."""
        return await self._mcp_request("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {
                "name": "mcpsec-scanner",
                "version": "0.1.0",
            },
        })

    async def _get_tools_list(self) -> Optional[list[dict[str, Any]]]:
        """Connect to MCP server and retrieve tools/list.

        Returns list of tool definitions or None if introspection failed.
        """
        # Initialize MCP session first
        init_result = await self._mcp_initialize()
        if init_result is None:
            return None

        # Request tools list
        result = await self._mcp_request("tools/list")
        if result is None:
            return None

        tools = result.get("tools", [])
        return tools if tools else None

    async def _get_scopes_supported(self) -> Optional[list[str]]:
        """Retrieve scopes_supported from AS or Protected Resource metadata."""
        base_url = self.target_url.rstrip("/")

        # Try Protected Resource Metadata first (closer to actual resource scopes)
        pr_metadata = await self._try_fetch_json(
            f"{base_url}/.well-known/oauth-protected-resource"
        )
        if pr_metadata and "scopes_supported" in pr_metadata:
            return pr_metadata["scopes_supported"]

        # Fallback to AS Metadata
        as_metadata = await self._try_fetch_json(
            f"{base_url}/.well-known/oauth-authorization-server"
        )
        if as_metadata and "scopes_supported" in as_metadata:
            return as_metadata["scopes_supported"]

        return None

    # ==================================================================
    # Introspection checks — M1
    # ==================================================================

    def _check_per_tool_scopes(
        self,
        tools: list[dict[str, Any]],
        scopes_supported: Optional[list[str]],
    ) -> None:
        """AUTHZ-002: Check if tools have per-tool scope requirements.

        Inspects tool metadata for scope annotations. In the absence of
        explicit per-tool scopes, flags the finding if the server has
        privileged tools but no authorization granularity.
        """
        privileged_tools: list[str] = []
        total_tools = len(tools)

        for tool in tools:
            name = tool.get("name", "")
            description = tool.get("description", "")

            # Check if tool name or description suggests privileged operation
            if (_PRIVILEGED_TOOL_PATTERNS.search(name) or
                    _PRIVILEGED_TOOL_PATTERNS.search(description)):
                privileged_tools.append(name)

        # If there are privileged tools but no scopes defined, flag it
        # Also flag if server has scopes but no per-tool mapping is visible
        if privileged_tools and not scopes_supported:
            self._add_finding(Finding(
                finding_id="MCP-AUTHZ-002",
                title="No Per-Tool Scope Requirements",
                auditor=Auditor.AUTHORIZATION,
                severity=Severity.HIGH,
                cvss_score=7.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
                cwe_id="CWE-272",
                cwe_name="Least Privilege Violation",
                detection_mode=DetectionMode.INTROSPECTION,
                confidence=Confidence.HIGH,
                detection_method="MCP tools/list introspection detected privileged tools. "
                                "No scopes_supported found in OAuth metadata. "
                                "Server appears to use blanket auth without per-tool granularity.",
                remote_scan_applicable=True,
                standards=[
                    StandardReference(
                        id="OWASP-MCP02",
                        ref="OWASP MCP Top 10 v0.1",
                        section="MCP02 — Privilege Escalation via Scope Creep",
                        requirement_level=RequirementLevel.NOT_APPLICABLE,
                    ),
                    StandardReference(
                        id="FMCP-SCOPES",
                        ref="gofastmcp.com/servers/authorization",
                        section="Per-tool scope requirements via require_scopes()",
                        requirement_level=RequirementLevel.RECOMMENDED,
                    ),
                    StandardReference(
                        id="OWASP-ASI03",
                        ref="genai.owasp.org",
                        section="ASI03 — Privilege Escalation",
                        requirement_level=RequirementLevel.NOT_APPLICABLE,
                    ),
                    StandardReference(
                        id="NIST-RMF-MAP",
                        ref="NIST AI Risk Management Framework",
                        section="Map 1.1 — Intended purpose and context of use",
                        requirement_level=RequirementLevel.NOT_APPLICABLE,
                    ),
                ],
                evidence=f"Server exposes {total_tools} tools, {len(privileged_tools)} appear privileged: "
                         f"{privileged_tools[:10]}{'...' if len(privileged_tools) > 10 else ''}. "
                         "No scopes_supported in OAuth metadata. "
                         "All tools accessible to any authenticated client regardless of scope.",
                risk="All tools are accessible to any authenticated client regardless of their "
                     "token scope. A read-only token can invoke write/delete/admin operations. "
                     "Violates principle of least privilege and enables unintended tool execution.",
                recommendation="Define granular scopes for tools based on operation type "
                              "(read, write, admin, etc.). Use FastMCP's require_scopes() decorator "
                              "to enforce per-tool scope requirements.",
                code_example=(
                    "from fastmcp import FastMCP\n"
                    "from fastmcp.server.auth import require_scopes\n\n"
                    "@mcp.tool()\n"
                    "@require_scopes('files:read')  # read-only scope\n"
                    "def read_file(path: str) -> str:\n"
                    "    ...\n\n"
                    "@mcp.tool()\n"
                    "@require_scopes('files:write')  # write scope\n"
                    "def write_file(path: str, content: str) -> str:\n"
                    "    ...\n\n"
                    "@mcp.tool()\n"
                    "@require_scopes('admin')  # admin scope\n"
                    "def delete_all_records() -> str:\n"
                    "    ..."
                ),
                remediation_effort=RemediationEffort.MEDIUM,
                remediation_priority=4,
            ))
        elif privileged_tools and scopes_supported:
            # Server has scopes but we can't verify per-tool assignment from introspection alone
            # Lower confidence advisory
            self._add_finding(Finding(
                finding_id="MCP-AUTHZ-002",
                title="No Per-Tool Scope Requirements (Verification Recommended)",
                auditor=Auditor.AUTHORIZATION,
                severity=Severity.HIGH,
                cvss_score=7.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
                cwe_id="CWE-272",
                cwe_name="Least Privilege Violation",
                detection_mode=DetectionMode.INTROSPECTION,
                confidence=Confidence.MEDIUM,
                detection_method="MCP tools/list introspection detected privileged tools. "
                                "Server defines scopes_supported in metadata, but per-tool "
                                "scope assignment cannot be verified via introspection alone. "
                                "Run with --access authenticated for active verification.",
                remote_scan_applicable=True,
                remote_heuristic=RemoteHeuristic(
                    available=True,
                    confidence=Confidence.MEDIUM,
                    description="Privileged tools detected via naming patterns. "
                               "Scopes exist in metadata but per-tool binding unverified. "
                               "Active scan (--access authenticated) can verify enforcement.",
                ),
                standards=[
                    StandardReference(
                        id="OWASP-MCP02",
                        ref="OWASP MCP Top 10 v0.1",
                        section="MCP02 — Privilege Escalation via Scope Creep",
                        requirement_level=RequirementLevel.NOT_APPLICABLE,
                    ),
                    StandardReference(
                        id="FMCP-SCOPES",
                        ref="gofastmcp.com/servers/authorization",
                        section="Per-tool scope requirements via require_scopes()",
                        requirement_level=RequirementLevel.RECOMMENDED,
                    ),
                ],
                evidence=f"Server exposes {total_tools} tools, {len(privileged_tools)} appear privileged: "
                         f"{privileged_tools[:10]}{'...' if len(privileged_tools) > 10 else ''}. "
                         f"scopes_supported: {scopes_supported[:5]}{'...' if len(scopes_supported) > 5 else ''}. "
                         "Per-tool scope binding cannot be verified without active token probing.",
                risk="Scopes are defined but may not be enforced at the per-tool level. "
                     "Without per-tool scope requirements, any valid token may access privileged operations.",
                recommendation="Verify that each privileged tool has explicit scope requirements. "
                              "Use active scanning mode (--access authenticated) for definitive verification. "
                              "Use FastMCP's require_scopes() decorator on all sensitive tools.",
                code_example=(
                    "from fastmcp.server.auth import require_scopes\n\n"
                    "@mcp.tool()\n"
                    "@require_scopes('admin')  # enforce admin scope\n"
                    "def delete_all_records() -> str:\n"
                    "    ..."
                ),
                remediation_effort=RemediationEffort.MEDIUM,
                remediation_priority=4,
            ))

    def _check_wildcard_scopes(self, scopes_supported: list[str]) -> None:
        """AUTHZ-003: Check for wildcard or overly broad scope definitions."""
        wildcard_scopes: list[str] = []
        broad_scopes: list[str] = []

        for scope in scopes_supported:
            if _WILDCARD_SCOPE_PATTERNS.match(scope):
                wildcard_scopes.append(scope)
            elif _BROAD_SCOPE_PATTERNS.match(scope):
                broad_scopes.append(scope)

        problematic = wildcard_scopes + broad_scopes

        if not problematic:
            return

        # Wildcard scopes are more severe than merely broad ones
        if wildcard_scopes:
            severity = Severity.HIGH
            cvss = 6.8
            title = "Wildcard Scope Definitions Detected"
        else:
            severity = Severity.HIGH
            cvss = 5.5
            title = "Overly Broad Scope Definitions Detected"

        self._add_finding(Finding(
            finding_id="MCP-AUTHZ-003",
            title=title,
            auditor=Auditor.AUTHORIZATION,
            severity=severity,
            cvss_score=cvss,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
            cwe_id="CWE-732",
            cwe_name="Incorrect Permission Assignment for Critical Resource",
            detection_mode=DetectionMode.INTROSPECTION,
            confidence=Confidence.HIGH,
            detection_method="Inspected scopes_supported in OAuth metadata for wildcard "
                            "patterns (*), overly broad single-scope definitions, and "
                            "scopes that combine read+write without separation.",
            remote_scan_applicable=True,
            standards=[
                StandardReference(
                    id="OWASP-MCP02",
                    ref="OWASP MCP Top 10 v0.1",
                    section="MCP02 — Privilege Escalation via Scope Creep",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="MCP-SPEC-AUTH",
                    ref="modelcontextprotocol.io/specification/draft/basic/authorization",
                    section="Scope Selection Strategy",
                    requirement_level=RequirementLevel.SHOULD,
                ),
                StandardReference(
                    id="OWASP-ASI03",
                    ref="genai.owasp.org",
                    section="ASI03 — Privilege Escalation",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="NIST-RMF-GOVERN",
                    ref="NIST AI Risk Management Framework",
                    section="Govern 1.4 — Processes for risk management",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
            ],
            evidence=f"scopes_supported: {scopes_supported}. "
                     f"Wildcard scopes: {wildcard_scopes or 'none'}. "
                     f"Overly broad scopes: {broad_scopes or 'none'}.",
            risk="Wildcard or overly broad scopes grant more permissions than necessary. "
                 "A token with scope '*' or 'admin' effectively bypasses authorization. "
                 "Violates the principle of least privilege and enables scope creep attacks.",
            recommendation="Replace wildcard scopes with granular, resource-specific scopes. "
                          "Separate read and write operations. Use a hierarchical scope model "
                          "(e.g. 'files:read', 'files:write', 'users:admin').",
            code_example=(
                "# BAD — overly broad scopes\n"
                "scopes = ['*', 'admin', 'full_access']  # ❌\n\n"
                "# GOOD — granular scopes\n"
                "scopes = [\n"
                "    'files:read',\n"
                "    'files:write',\n"
                "    'users:read',\n"
                "    'users:admin',\n"
                "    'tools:execute',\n"
                "]  # ✅\n\n"
                "# FastMCP — enforce granular scopes per tool\n"
                "from fastmcp.server.auth import require_scopes\n\n"
                "@mcp.tool()\n"
                "@require_scopes('files:read')\n"
                "def read_file(path: str) -> str:\n"
                "    ..."
            ),
            remediation_effort=RemediationEffort.MEDIUM,
            remediation_priority=5,
        ))

    # ==================================================================
    # Active checks — M2
    # ==================================================================

    async def _check_admin_tool_auth(self) -> None:
        """AUTHZ-001: Test if admin/privileged tools enforce authorization.

        Sends a tool call to privileged tools using a minimal-scope token.
        A compliant server MUST reject with 403. A non-compliant server
        executes the tool regardless of scope.
        """
        if not self.test_token:
            return

        mcp_url = self.target_url.rstrip("/") + "/mcp"

        # Get tools list to identify privileged tools
        tools = await self._get_tools_list()
        if not tools:
            return

        privileged_tools = []
        for tool in tools:
            name = tool.get("name", "")
            description = tool.get("description", "")
            if _PRIVILEGED_TOOL_PATTERNS.search(name) or _PRIVILEGED_TOOL_PATTERNS.search(description):
                privileged_tools.append(tool)

        if not privileged_tools:
            return

        # Try calling each privileged tool with the test token
        # The test token should have minimal scope — if the server
        # accepts the call, the tool lacks authorization checks
        unprotected: list[dict[str, str]] = []

        try:
            client = await self.get_http_client()
        except Exception:
            return

        for tool in privileged_tools:
            tool_name = tool.get("name", "")
            schema = tool.get("inputSchema", {})
            properties = schema.get("properties", {})
            required = schema.get("required", [])

            # Build minimal valid arguments from schema
            arguments = {}
            for param_name in required:
                param_schema = properties.get(param_name, {})
                param_type = param_schema.get("type", "string")
                if param_type == "string":
                    arguments[param_name] = "mcpsec-test"
                elif param_type == "integer":
                    arguments[param_name] = 1
                elif param_type == "boolean":
                    arguments[param_name] = True
                else:
                    arguments[param_name] = "mcpsec-test"

            call_payload = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments},
                "id": 1,
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

                # If server returns 200, the privileged tool executed
                # without proper scope enforcement
                if response.status_code == 200:
                    try:
                        body = response.json()
                        if "error" not in body:
                            unprotected.append({
                                "tool": tool_name,
                                "status": str(response.status_code),
                            })
                    except Exception:
                        pass

            except Exception:
                continue

        if not unprotected:
            return

        evidence_parts = [
            f"  - {u['tool']}: HTTP {u['status']} — tool executed without scope enforcement"
            for u in unprotected
        ]

        self._add_finding(Finding(
            finding_id="MCP-AUTHZ-001",
            title="Admin/Privileged Tool Without Authorization Check",
            auditor=Auditor.AUTHORIZATION,
            severity=Severity.CRITICAL,
            cvss_score=9.3,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
            cwe_id="CWE-285",
            cwe_name="Improper Authorization",
            detection_mode=DetectionMode.ACTIVE,
            confidence=Confidence.HIGH,
            detection_method="Called privileged tools with a minimal-scope test token. "
                            "Server executed the tools without rejecting for insufficient scope.",
            remote_scan_applicable=True,
            standards=[
                StandardReference(
                    id="OWASP-MCP02",
                    ref="OWASP MCP Top 10 v0.1",
                    section="MCP02 — Privilege Escalation via Scope Creep",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="OWASP-MCP07",
                    ref="OWASP MCP Top 10 v0.1",
                    section="MCP07 — Insufficient Authentication & Authorization",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="OWASP-ASI03",
                    ref="genai.owasp.org",
                    section="ASI03 — Privilege Escalation",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="FMCP-SCOPES",
                    ref="gofastmcp.com/servers/authorization",
                    section="Per-tool scope requirements via require_scopes()",
                    requirement_level=RequirementLevel.RECOMMENDED,
                ),
                StandardReference(
                    id="NIST-RMF-GOVERN",
                    ref="NIST AI Risk Management Framework",
                    section="Govern 1.2 — Processes for risk management",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
            ],
            evidence=f"{len(unprotected)} privileged tool(s) executed without authorization:\n"
                     + "\n".join(evidence_parts),
            risk="Any authenticated client can invoke privileged operations regardless of "
                 "their token scope. A read-only token can trigger admin deletions, "
                 "deployments, or data modifications. Violates the principle of least privilege.",
            recommendation="Add explicit scope requirements to all privileged tools. "
                          "Use FastMCP's require_scopes() decorator or AuthMiddleware "
                          "to enforce per-tool authorization.",
            code_example=(
                "from fastmcp.server.auth import require_scopes\n\n"
                "# Require 'admin' scope for privileged tools\n"
                "@mcp.tool()\n"
                "@require_scopes('admin')\n"
                "def admin_delete(target: str) -> str:\n"
                "    '''Delete all records matching target.'''\n"
                "    ...\n\n"
                "# Require 'write' scope for write operations\n"
                "@mcp.tool()\n"
                "@require_scopes('write')\n"
                "def write_data(key: str, value: str) -> str:\n"
                "    '''Write data to the database.'''\n"
                "    ..."
            ),
            remediation_effort=RemediationEffort.LOW,
            remediation_priority=1,
        ))

    async def _check_scope_escalation(self) -> None:
        """AUTHZ-004: Test privilege escalation via scope manipulation.

        Sends a read-only token to tools requiring write or admin scope.
        A compliant server MUST reject. A non-compliant server executes.

        This differs from AUTHZ-001: here we specifically test scope
        *boundaries* — can a read token do write operations?
        """
        if not self.test_token:
            return

        mcp_url = self.target_url.rstrip("/") + "/mcp"

        # Get tools list
        tools = await self._get_tools_list()
        if not tools:
            return

        # Identify write/admin tools by name patterns
        write_patterns = re.compile(
            r"(write|update|create|insert|put|patch|set|modify|edit|save)",
            re.IGNORECASE,
        )
        admin_patterns = re.compile(
            r"(admin|delete|remove|drop|destroy|purge|truncate|reset|deploy)",
            re.IGNORECASE,
        )

        escalation_targets: list[dict[str, str]] = []
        for tool in tools:
            name = tool.get("name", "")
            description = tool.get("description", "")
            combined = f"{name} {description}"

            if admin_patterns.search(combined):
                escalation_targets.append({"tool": tool, "level": "admin"})
            elif write_patterns.search(combined):
                escalation_targets.append({"tool": tool, "level": "write"})

        if not escalation_targets:
            return

        # Try calling write/admin tools with the test token
        # We assume the test token has minimal (read) scope
        escalated: list[dict[str, str]] = []

        try:
            client = await self.get_http_client()
        except Exception:
            return

        for target in escalation_targets:
            tool = target["tool"]
            level = target["level"]
            tool_name = tool.get("name", "")
            schema = tool.get("inputSchema", {})
            properties = schema.get("properties", {})
            required = schema.get("required", [])

            # Build minimal arguments
            arguments = {}
            for param_name in required:
                param_schema = properties.get(param_name, {})
                param_type = param_schema.get("type", "string")
                if param_type == "string":
                    arguments[param_name] = "mcpsec-escalation-test"
                elif param_type == "integer":
                    arguments[param_name] = 0
                elif param_type == "boolean":
                    arguments[param_name] = False
                else:
                    arguments[param_name] = "mcpsec-escalation-test"

            call_payload = {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments},
                "id": 1,
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

                if response.status_code == 200:
                    try:
                        body = response.json()
                        if "error" not in body:
                            escalated.append({
                                "tool": tool_name,
                                "required_level": level,
                                "status": str(response.status_code),
                            })
                    except Exception:
                        pass

            except Exception:
                continue

        if not escalated:
            return

        evidence_parts = [
            f"  - {e['tool']}: requires '{e['required_level']}' scope — "
            f"executed with test token (HTTP {e['status']})"
            for e in escalated
        ]

        self._add_finding(Finding(
            finding_id="MCP-AUTHZ-004",
            title="Privilege Escalation via Scope Manipulation",
            auditor=Auditor.AUTHORIZATION,
            severity=Severity.CRITICAL,
            cvss_score=8.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
            cwe_id="CWE-269",
            cwe_name="Improper Privilege Management",
            detection_mode=DetectionMode.ACTIVE,
            confidence=Confidence.HIGH,
            detection_method="Called write/admin tools with a read-scope test token. "
                            "Server executed the operations without rejecting for "
                            "insufficient scope — privilege escalation confirmed.",
            remote_scan_applicable=True,
            standards=[
                StandardReference(
                    id="OWASP-MCP02",
                    ref="OWASP MCP Top 10 v0.1",
                    section="MCP02 — Privilege Escalation via Scope Creep",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="OWASP-ASI03",
                    ref="genai.owasp.org",
                    section="ASI03 — Privilege Escalation",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="MITRE-ATLAS-T0056",
                    ref="MITRE ATLAS",
                    section="AML.T0056 — Privilege Escalation",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
            ],
            evidence=f"{len(escalated)} tool(s) allow scope escalation:\n"
                     + "\n".join(evidence_parts),
            risk="A token with read-only scope can execute write and admin operations. "
                 "This is a confirmed privilege escalation vulnerability. Any client "
                 "with minimal access can perform destructive operations. In multi-agent "
                 "systems, a compromised read-only agent gains full control.",
            recommendation="Enforce scope checks at the per-tool level. Each tool should "
                          "declare its required scope and reject tokens that don't have it. "
                          "Use FastMCP's require_scopes() decorator.",
            code_example=(
                "from fastmcp.server.auth import require_scopes\n\n"
                "# Read tool — requires 'read' scope\n"
                "@mcp.tool()\n"
                "@require_scopes('read')\n"
                "def read_data(query: str) -> str:\n"
                "    ...\n\n"
                "# Write tool — requires 'write' scope (not 'read')\n"
                "@mcp.tool()\n"
                "@require_scopes('write')\n"
                "def write_data(key: str, value: str) -> str:\n"
                "    ...\n\n"
                "# Admin tool — requires 'admin' scope\n"
                "@mcp.tool()\n"
                "@require_scopes('admin')\n"
                "def admin_delete(target: str) -> str:\n"
                "    ..."
            ),
            remediation_effort=RemediationEffort.LOW,
            remediation_priority=2,
        ))


    # ==================================================================
    # Helpers
    # ==================================================================

    async def _try_fetch_json(self, url: str) -> Optional[dict]:
        """Attempt to fetch a URL and parse as JSON. Returns None on failure."""
        try:
            response = await self.http_get(url)
            if response.status_code == 200:
                return response.json()
        except (TargetConnectionError, Exception):
            pass
        return None
