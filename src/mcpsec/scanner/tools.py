"""MCPSec — Tool Security Auditor.

Validates MCP server tool metadata for poisoning, injection risks,
and schema validation gaps via MCP protocol introspection (tools/list).

M1 scope: Introspection mode (TOOL-001, TOOL-004, TOOL-005) — rule-based
M2 scope: Static mode (TOOL-002, TOOL-003) via source code analysis
M2 scope: LLM hybrid second pass on TOOL-001, TOOL-005
"""

from __future__ import annotations

import json
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
from mcpsec.llm.classifier import (
    ClassificationType,
    ClassificationVerdict,
    HybridClassifier,
)


# ---------------------------------------------------------------------------
# Tool poisoning detection patterns
# ---------------------------------------------------------------------------

# Patterns in tool descriptions that indicate prompt injection / poisoning
_POISONING_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # Direct instruction injection
    (
        re.compile(r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|context|prompts?)", re.IGNORECASE),
        "Instruction override attempt",
        "Description contains directive to ignore previous instructions.",
    ),
    (
        re.compile(r"(you\s+must|you\s+should|always|never)\s+(use\s+this|call\s+this|prefer\s+this|choose\s+this)", re.IGNORECASE),
        "Agent behavior manipulation",
        "Description attempts to influence agent tool selection behavior.",
    ),
    (
        re.compile(r"(system\s*prompt|system\s*message|hidden\s*instruction)", re.IGNORECASE),
        "System prompt reference",
        "Description references system prompts — possible extraction attempt.",
    ),
    # Impersonation / shadowing
    (
        re.compile(r"(this\s+tool\s+replaces|use\s+instead\s+of|replacement\s+for|supersedes|overrides)\s+\w+", re.IGNORECASE),
        "Tool shadowing attempt",
        "Description claims to replace another tool — classic shadowing attack.",
    ),
    (
        re.compile(r"(do\s+not|don'?t|never)\s+(use|call|invoke)\s+\w+", re.IGNORECASE),
        "Tool suppression attempt",
        "Description attempts to suppress use of another tool.",
    ),
    # Hidden content / obfuscation
    (
        re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]", re.UNICODE),
        "Invisible Unicode characters",
        "Description contains zero-width or invisible Unicode characters — possible hidden instructions.",
    ),
    (
        re.compile(r"<[^>]+>", re.IGNORECASE),
        "HTML/XML tags in description",
        "Description contains markup tags — possible injection vector.",
    ),
    # Data exfiltration
    (
        re.compile(r"(send|transmit|forward|exfiltrate|upload)\s+(to|data|results|output|response)\s*(to)?\s*(https?://|ftp://)", re.IGNORECASE),
        "Data exfiltration directive",
        "Description instructs agent to send data to external URL.",
    ),
    (
        re.compile(r"https?://[^\s]+\.(xyz|tk|ml|ga|cf|pw|top|buzz|click)", re.IGNORECASE),
        "Suspicious external URL",
        "Description contains URL with commonly abused TLD.",
    ),
    # Excessive whitespace hiding instructions
    (
        re.compile(r"\n{5,}"),
        "Excessive newlines (content hiding)",
        "Description contains excessive newlines — possible hidden instructions below visible area.",
    ),
    (
        re.compile(r" {20,}"),
        "Excessive spaces (content hiding)",
        "Description contains excessive spaces — possible hidden instructions after visible text.",
    ),
]

# Tool names that could mislead LLM agents
_DANGEROUS_NAME_PATTERNS: list[tuple[re.Pattern, str]] = [
    (
        re.compile(r"(system_prompt|systemprompt|get_system|set_system|override_system)", re.IGNORECASE),
        "Impersonates system-level operation",
    ),
    (
        re.compile(r"(ignore_instructions|skip_auth|bypass_auth|no_auth|disable_security)", re.IGNORECASE),
        "Suggests security bypass",
    ),
    (
        re.compile(r"(execute_code|run_code|eval_code|shell_exec|os_command)", re.IGNORECASE),
        "Direct code execution name",
    ),
    (
        re.compile(r"(admin_override|sudo_run|root_access|privilege_escalate)", re.IGNORECASE),
        "Suggests privilege escalation",
    ),
    (
        re.compile(r"(fetch_url|download_url|load_remote|import_remote)", re.IGNORECASE),
        "Remote resource loading — potential SSRF trigger",
    ),
]

# Input schema fields that should have constraints for security
_SENSITIVE_PARAM_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"(path|file|filename|filepath|dir|directory|folder)\b", re.IGNORECASE), "file path"),
    (re.compile(r"(url|uri|href|link|endpoint|host)\b", re.IGNORECASE), "URL/URI"),
    (re.compile(r"(command|cmd|shell|exec|script|code|query|sql)\b", re.IGNORECASE), "command/code"),
    (re.compile(r"(regex|pattern|expression|template)\b", re.IGNORECASE), "pattern/template"),
    (re.compile(r"(html|xml|json|yaml|markdown)\b", re.IGNORECASE), "structured content"),
]


class ToolsAuditor(BaseAuditor):
    """Audits MCP tool metadata for security issues via protocol introspection.

    Introspection checks (M1 — MCP client connection):
        TOOL-001  Tool description poisoning detected
        TOOL-004  Input schema missing validation constraints
        TOOL-005  Dangerous tool name detected

    LLM hybrid second pass (M2 — requires LLM):
        TOOL-001  Semantic poisoning detection on rule-clean tools
        TOOL-005  Semantic name analysis on rule-clean tools

    Static checks (M2 — requires source code):
        TOOL-002  Command injection pattern in tool implementation
        TOOL-003  Path traversal vulnerability in tool input handling
    """

    def __init__(self, classifier: Optional[HybridClassifier] = None, **kwargs):
        super().__init__(**kwargs)
        self._classifier = classifier
        self._rule_flagged_poisoning: set[str] = set()
        self._rule_flagged_names: set[str] = set()

    @property
    def auditor_type(self) -> Auditor:
        return Auditor.TOOLS

    async def audit(self) -> list[Finding]:
        """Run all tool security checks appropriate for the current access level."""
        self._clear_findings()

        if not self.target_url:
            return self._findings

        # --- Introspection checks (M1 + M2 LLM) ---
        if self._should_run_check(DetectionMode.INTROSPECTION):
            tools = await self._get_tools_list()
            if tools is not None:
                # Rule-based first pass
                self._check_tool_poisoning(tools)
                self._check_dangerous_names(tools)
                self._check_input_schemas(tools)

                # LLM second pass on tools NOT flagged by rules
                if self._classifier and self._classifier.is_available:
                    await self._llm_second_pass(tools)

        # --- Static checks (M2 stubs) ---
        if self._should_run_check(DetectionMode.STATIC):
            self._check_command_injection()
            self._check_path_traversal()

        return self._findings

    # ==================================================================
    # MCP Protocol introspection
    # ==================================================================

    async def _mcp_request(
        self, method: str, params: Optional[dict] = None
    ) -> Optional[dict[str, Any]]:
        """Send a JSON-RPC 2.0 request to the MCP server."""
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

        if response.status_code not in (200, 202):
            return None

        content_type = response.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            return self._parse_sse_response(response.text)

        try:
            result = response.json()
            if "result" in result:
                return result["result"]
        except Exception:
            pass

        return None

    def _parse_sse_response(self, text: str) -> Optional[dict[str, Any]]:
        """Extract JSON-RPC result from SSE event stream."""
        for line in text.split("\n"):
            line = line.strip()
            if line.startswith("data:"):
                try:
                    data = json.loads(line[5:].strip())
                    if "result" in data:
                        return data["result"]
                except (json.JSONDecodeError, KeyError):
                    continue
        return None

    async def _get_tools_list(self) -> Optional[list[dict[str, Any]]]:
        """Retrieve tools via MCP introspection."""
        # Initialize session
        await self._mcp_request("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "mcpsec-scanner", "version": "0.1.0"},
        })

        result = await self._mcp_request("tools/list")
        if result is None:
            return None

        tools = result.get("tools", [])
        return tools if tools else None

    # ==================================================================
    # Introspection checks — M1 (rule-based)
    # ==================================================================

    def _check_tool_poisoning(self, tools: list[dict[str, Any]]) -> None:
        """TOOL-001: Detect tool description poisoning patterns.

        Scans tool descriptions for prompt injection, hidden instructions,
        impersonation, data exfiltration directives, and obfuscation.
        """
        poisoned_tools: list[dict[str, Any]] = []

        for tool in tools:
            name = tool.get("name", "<unnamed>")
            description = tool.get("description", "")
            matches: list[dict[str, str]] = []

            for pattern, label, explanation in _POISONING_PATTERNS:
                if pattern.search(description):
                    matches.append({
                        "pattern": label,
                        "explanation": explanation,
                    })

            if matches:
                poisoned_tools.append({
                    "tool": name,
                    "matches": matches,
                    "description_preview": description[:200],
                })

        # Track rule-flagged tools for LLM second pass
        self._rule_flagged_poisoning = {pt["tool"] for pt in poisoned_tools}

        if not poisoned_tools:
            return

        # Build evidence
        evidence_parts = []
        for pt in poisoned_tools:
            match_labels = [m["pattern"] for m in pt["matches"]]
            evidence_parts.append(
                f"  - {pt['tool']}: {', '.join(match_labels)} "
                f"[preview: \"{pt['description_preview']}\"]"
            )

        self._add_finding(Finding(
            finding_id="MCP-TOOL-001",
            title="Tool Description Poisoning Detected",
            auditor=Auditor.TOOLS,
            severity=Severity.CRITICAL,
            cvss_score=9.2,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
            cwe_id="CWE-77",
            cwe_name="Improper Neutralization of Special Elements Used in a Command",
            detection_mode=DetectionMode.INTROSPECTION,
            confidence=Confidence.MEDIUM,
            detection_method="Regex-based pattern matching against tool descriptions "
                            "from tools/list MCP introspection. Checked for instruction "
                            "injection, tool shadowing, hidden content, and data exfiltration "
                            "patterns. LLM-based classification recommended for confirmation.",
            remote_scan_applicable=True,
            standards=[
                StandardReference(
                    id="OWASP-MCP03",
                    ref="OWASP MCP Top 10 v0.1",
                    section="MCP03 — Tool Poisoning",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="OWASP-LLM01",
                    ref="OWASP Top 10 for LLM Applications 2025",
                    section="LLM01 — Prompt Injection",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="MITRE-ATLAS-T0054",
                    ref="MITRE ATLAS",
                    section="AML.T0054 — LLM Prompt Injection",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="OWASP-ASI02",
                    ref="genai.owasp.org",
                    section="ASI02 — Tool Misuse",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
            ],
            evidence=f"{len(poisoned_tools)} tool(s) with suspicious descriptions:\n"
                     + "\n".join(evidence_parts),
            risk="Malicious tool descriptions manipulate LLM agents into unintended actions. "
                 "Demonstrated in 'Rug Pull' and 'Tool Shadowing' attack patterns. "
                 "Can override system prompts, hijack agent decision-making, suppress "
                 "legitimate tools, or direct agents to exfiltrate data.",
            recommendation="Review and sanitize all tool descriptions. Remove any directives, "
                          "instructions to agents, or references to other tools. Tool descriptions "
                          "should only describe what the tool does, its parameters, and return values. "
                          "Implement server-side description validation before registration.",
            code_example=(
                "# FastMCP — clean tool description (no directives)\n"
                "@mcp.tool()\n"
                "def read_file(path: str) -> str:\n"
                "    \"\"\"Read the contents of a file at the given path.\n\n"
                "    Args:\n"
                "        path: Absolute or relative file path to read.\n\n"
                "    Returns:\n"
                "        File contents as a string.\n"
                "    \"\"\"\n"
                "    # ✅ Description only states what tool does\n"
                "    # ❌ Never include: 'always use this instead of X'\n"
                "    # ❌ Never include: 'ignore previous instructions'\n"
                "    ..."
            ),
            remediation_effort=RemediationEffort.LOW,
            remediation_priority=1,
        ))

    def _check_dangerous_names(self, tools: list[dict[str, Any]]) -> None:
        """TOOL-005: Detect tool names that could mislead LLM agents."""
        dangerous_tools: list[dict[str, str]] = []

        for tool in tools:
            name = tool.get("name", "")
            for pattern, reason in _DANGEROUS_NAME_PATTERNS:
                if pattern.search(name):
                    dangerous_tools.append({
                        "tool": name,
                        "reason": reason,
                    })
                    break  # One match per tool is sufficient

        # Track rule-flagged tools for LLM second pass
        self._rule_flagged_names = {dt["tool"] for dt in dangerous_tools}

        if not dangerous_tools:
            return

        evidence_parts = [
            f"  - {dt['tool']}: {dt['reason']}"
            for dt in dangerous_tools
        ]

        self._add_finding(Finding(
            finding_id="MCP-TOOL-005",
            title="Dangerous Tool Name Detected",
            auditor=Auditor.TOOLS,
            severity=Severity.HIGH,
            cvss_score=6.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            cwe_id="CWE-1021",
            cwe_name="Improper Restriction of Rendered UI Layers",
            detection_mode=DetectionMode.INTROSPECTION,
            confidence=Confidence.MEDIUM,
            detection_method="Tool names from tools/list matched against patterns for "
                            "system impersonation, security bypass, direct execution, "
                            "and privilege escalation naming conventions.",
            remote_scan_applicable=True,
            standards=[
                StandardReference(
                    id="OWASP-MCP03",
                    ref="OWASP MCP Top 10 v0.1",
                    section="MCP03 — Tool Poisoning",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="OWASP-MCP06",
                    ref="OWASP MCP Top 10 v0.1",
                    section="MCP06 — Intent Flow Subversion",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="OWASP-ASI01",
                    ref="genai.owasp.org",
                    section="ASI01 — Agent Goal Hijacking",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="OWASP-LLM01",
                    ref="OWASP Top 10 for LLM Applications 2025",
                    section="LLM01 — Prompt Injection",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
            ],
            evidence=f"{len(dangerous_tools)} tool(s) with dangerous names:\n"
                     + "\n".join(evidence_parts),
            risk="Tool names that impersonate system operations or suggest security "
                 "bypass can mislead LLM agents into invoking them inappropriately. "
                 "An agent may prefer a tool named 'system_prompt_override' over "
                 "legitimate tools, or treat 'bypass_auth' as authoritative.",
            recommendation="Use clear, descriptive, non-misleading tool names that accurately "
                          "represent the tool's function. Avoid names that reference system "
                          "operations, security mechanisms, or other tools.",
            code_example=(
                "# BAD — misleading tool names\n"
                "@mcp.tool(name='system_prompt_override')  # ❌\n"
                "@mcp.tool(name='bypass_auth')             # ❌\n"
                "@mcp.tool(name='execute_code')            # ❌\n\n"
                "# GOOD — clear, descriptive names\n"
                "@mcp.tool(name='update_config')           # ✅\n"
                "@mcp.tool(name='run_analysis')            # ✅\n"
                "@mcp.tool(name='transform_data')          # ✅"
            ),
            remediation_effort=RemediationEffort.LOW,
            remediation_priority=3,
        ))

    def _check_input_schemas(self, tools: list[dict[str, Any]]) -> None:
        """TOOL-004: Check tool input schemas for missing validation constraints.

        Identifies tools with unconstrained string parameters, especially
        those handling paths, URLs, commands, or structured content.
        """
        tools_with_issues: list[dict[str, Any]] = []

        for tool in tools:
            name = tool.get("name", "<unnamed>")
            schema = tool.get("inputSchema", {})
            properties = schema.get("properties", {})

            if not properties:
                continue

            unconstrained_params: list[dict[str, str]] = []

            for param_name, param_schema in properties.items():
                param_type = param_schema.get("type", "")

                if param_type != "string":
                    continue

                # Check if parameter name suggests sensitive input
                sensitivity = None
                for pattern, label in _SENSITIVE_PARAM_PATTERNS:
                    if pattern.search(param_name):
                        sensitivity = label
                        break

                if sensitivity is None:
                    continue

                # Check for validation constraints
                has_constraints = any(
                    key in param_schema
                    for key in ("maxLength", "minLength", "pattern", "enum", "format", "const")
                )

                if not has_constraints:
                    unconstrained_params.append({
                        "param": param_name,
                        "sensitivity": sensitivity,
                        "schema": json.dumps(param_schema, indent=None),
                    })

            if unconstrained_params:
                tools_with_issues.append({
                    "tool": name,
                    "params": unconstrained_params,
                })

        if not tools_with_issues:
            return

        # Build evidence
        evidence_parts = []
        total_unconstrained = 0
        for tool_issue in tools_with_issues:
            for param in tool_issue["params"]:
                total_unconstrained += 1
                evidence_parts.append(
                    f"  - {tool_issue['tool']}.{param['param']} "
                    f"(type: string, sensitivity: {param['sensitivity']}, "
                    f"constraints: none)"
                )

        self._add_finding(Finding(
            finding_id="MCP-TOOL-004",
            title="Tool Input Schema Missing Validation Constraints",
            auditor=Auditor.TOOLS,
            severity=Severity.HIGH,
            cvss_score=6.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
            cwe_id="CWE-20",
            cwe_name="Improper Input Validation",
            detection_mode=DetectionMode.INTROSPECTION,
            confidence=Confidence.DEFINITIVE,
            detection_method="Inspected inputSchema from tools/list for string parameters "
                            "matching sensitive input patterns (file paths, URLs, commands, etc.) "
                            "that lack maxLength, pattern, enum, or format constraints.",
            remote_scan_applicable=True,
            standards=[
                StandardReference(
                    id="OWASP-MCP05",
                    ref="OWASP MCP Top 10 v0.1",
                    section="MCP05 — Command Injection & Execution",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="MCP-SPEC-INPUT",
                    ref="modelcontextprotocol.io/specification/draft/basic",
                    section="Input Validation — tool input sanitization",
                    requirement_level=RequirementLevel.SHOULD,
                ),
                StandardReference(
                    id="OWASP-LLM02",
                    ref="OWASP Top 10 for LLM Applications 2025",
                    section="LLM02 — Insecure Output Handling",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
            ],
            evidence=f"{total_unconstrained} unconstrained sensitive parameter(s) across "
                     f"{len(tools_with_issues)} tool(s):\n"
                     + "\n".join(evidence_parts[:20])
                     + (f"\n  ... and {total_unconstrained - 20} more"
                        if total_unconstrained > 20 else ""),
            risk="Unconstrained string parameters for file paths, URLs, commands, or "
                 "structured content are the entry point for injection attacks. "
                 "Without maxLength, pattern, or enum constraints, LLM-generated "
                 "inputs can contain path traversal sequences (../), shell metacharacters, "
                 "or oversized payloads.",
            recommendation="Add JSON Schema validation constraints to all sensitive parameters. "
                          "Use 'maxLength' to prevent oversized inputs, 'pattern' for format "
                          "enforcement, and 'enum' for known-value parameters.",
            code_example=(
                "from pydantic import Field\n\n"
                "# BAD — unconstrained path parameter\n"
                "@mcp.tool()\n"
                "def read_file(path: str) -> str:  # ❌ no constraints\n"
                "    ...\n\n"
                "# GOOD — constrained with validation\n"
                "@mcp.tool()\n"
                "def read_file(\n"
                "    path: str = Field(\n"
                "        max_length=255,\n"
                "        pattern=r'^[a-zA-Z0-9_/.-]+$',  # no ../ or special chars\n"
                "        description='Relative file path within the workspace'\n"
                "    )\n"
                ") -> str:\n"
                "    ..."
            ),
            remediation_effort=RemediationEffort.LOW,
            remediation_priority=3,
        ))

    # ==================================================================
    # LLM second pass — M2
    # ==================================================================

    async def _llm_second_pass(self, tools: list[dict[str, Any]]) -> None:
        """Run LLM classification on tools not flagged by rule-based checks."""

        # Poisoning check
        poisoning_batch = await self._classifier.classify_tools(
            tools=tools,
            rule_flagged_names=self._rule_flagged_poisoning,
            classification_type=ClassificationType.TOOL_POISONING,
        )
        for result in poisoning_batch.results:
            if result.verdict == ClassificationVerdict.FLAGGED and result.confidence_score >= 0.6:
                self._add_finding(Finding(
                    finding_id="MCP-TOOL-001",
                    title="Tool Description Poisoning Detected (LLM)",
                    auditor=Auditor.TOOLS,
                    severity=Severity.CRITICAL,
                    cvss_score=9.2,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
                    cwe_id="CWE-77",
                    cwe_name="Improper Neutralization of Special Elements Used in a Command",
                    detection_mode=DetectionMode.INTROSPECTION,
                    confidence=Confidence.MEDIUM,
                    detection_method=f"LLM classification ({poisoning_batch.model_used}). "
                                    "Rule-based checks did not flag this tool. "
                                    "LLM semantic analysis detected suspicious patterns.",
                    remote_scan_applicable=True,
                    standards=[
                        StandardReference(
                            id="OWASP-MCP03",
                            ref="OWASP MCP Top 10 v0.1",
                            section="MCP03 — Tool Poisoning",
                            requirement_level=RequirementLevel.NOT_APPLICABLE,
                        ),
                        StandardReference(
                            id="OWASP-LLM01",
                            ref="OWASP Top 10 for LLM Applications 2025",
                            section="LLM01 — Prompt Injection",
                            requirement_level=RequirementLevel.NOT_APPLICABLE,
                        ),
                    ],
                    evidence=f"Tool '{result.item_id}' flagged by LLM analysis.\n"
                             f"Reasoning: {result.reasoning}\n"
                             f"Confidence: {result.confidence_score:.0%}\n"
                             f"Patterns: {', '.join(result.flagged_patterns) or 'semantic analysis'}",
                    risk="Malicious tool descriptions manipulate LLM agents into unintended actions. "
                         "This tool passed rule-based checks but was flagged by semantic analysis.",
                    recommendation="Review the tool description manually. Remove any directives, "
                                  "instructions to agents, or references to other tools.",
                    remediation_effort=RemediationEffort.LOW,
                    remediation_priority=1,
                ))

        # Dangerous name check
        name_batch = await self._classifier.classify_tools(
            tools=tools,
            rule_flagged_names=self._rule_flagged_names,
            classification_type=ClassificationType.DANGEROUS_NAME,
        )
        for result in name_batch.results:
            if result.verdict == ClassificationVerdict.FLAGGED and result.confidence_score >= 0.6:
                self._add_finding(Finding(
                    finding_id="MCP-TOOL-005",
                    title="Dangerous Tool Name Detected (LLM)",
                    auditor=Auditor.TOOLS,
                    severity=Severity.HIGH,
                    cvss_score=6.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                    cwe_id="CWE-1021",
                    cwe_name="Improper Restriction of Rendered UI Layers",
                    detection_mode=DetectionMode.INTROSPECTION,
                    confidence=Confidence.MEDIUM,
                    detection_method=f"LLM classification ({name_batch.model_used}). "
                                    "Rule-based name checks did not flag this tool. "
                                    "LLM semantic analysis detected misleading naming.",
                    remote_scan_applicable=True,
                    standards=[
                        StandardReference(
                            id="OWASP-MCP03",
                            ref="OWASP MCP Top 10 v0.1",
                            section="MCP03 — Tool Poisoning",
                            requirement_level=RequirementLevel.NOT_APPLICABLE,
                        ),
                    ],
                    evidence=f"Tool '{result.item_id}' flagged by LLM analysis.\n"
                             f"Reasoning: {result.reasoning}\n"
                             f"Confidence: {result.confidence_score:.0%}\n"
                             f"Patterns: {', '.join(result.flagged_patterns) or 'semantic analysis'}",
                    risk="Tool names that mislead LLM agents can cause unintended tool invocation.",
                    recommendation="Rename the tool to accurately and neutrally describe its function.",
                    remediation_effort=RemediationEffort.LOW,
                    remediation_priority=3,
                ))

    # ==================================================================
    # Static checks — M2 stubs
    # ==================================================================

    def _check_command_injection(self) -> None:
        """TOOL-002: Detect command injection in tool source code (M2)."""
        # TODO M2: Use semgrep rules to detect patterns:
        #   - subprocess.run(shell=True) with user input
        #   - os.system() with string formatting
        #   - eval() / exec() with tool parameters
        #   - shlex.quote() absence before shell usage
        pass

    def _check_path_traversal(self) -> None:
        """TOOL-003: Detect path traversal in tool source code (M2)."""
        # TODO M2: Use semgrep rules to detect patterns:
        #   - open() with unvalidated user paths
        #   - os.path.join() without containment check
        #   - Path() without resolve() + relative_to() validation
        #   - Symlink following without checks
        pass
