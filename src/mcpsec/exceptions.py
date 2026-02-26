"""MCPSec — Custom exceptions.

Structured exception hierarchy for scanner operations.
All exceptions inherit from MCPSecError for unified catch-all handling.
"""


class MCPSecError(Exception):
    """Base exception for all MCPSec errors."""


# ---------------------------------------------------------------------------
# Connection / Target errors
# ---------------------------------------------------------------------------

class TargetConnectionError(MCPSecError):
    """Cannot reach the target MCP server."""

class TargetTimeoutError(TargetConnectionError):
    """Target server did not respond within timeout."""

class TLSError(TargetConnectionError):
    """TLS handshake or certificate validation failed."""

class MCPProtocolError(MCPSecError):
    """Target responded but not with valid MCP protocol."""


# ---------------------------------------------------------------------------
# Scanner errors
# ---------------------------------------------------------------------------

class ScanError(MCPSecError):
    """A scanner module encountered an error during a scan."""

    def __init__(self, auditor: str, message: str):
        self.auditor = auditor
        super().__init__(f"[{auditor}] {message}")

class ScanConfigError(ScanError):
    """Invalid scan configuration (bad access level, missing params, etc.)."""

class AuditorError(ScanError):
    """An individual auditor failed during execution."""


# ---------------------------------------------------------------------------
# Auth / Token errors (for active scanning)
# ---------------------------------------------------------------------------

class TokenError(MCPSecError):
    """Problem with test token for active scanning."""

class TokenExpiredError(TokenError):
    """Supplied test token has expired."""

class TokenCraftError(TokenError):
    """Failed to craft a test token via DCR or other mechanism."""


# ---------------------------------------------------------------------------
# Static analysis errors
# ---------------------------------------------------------------------------

class FileAccessError(MCPSecError):
    """Cannot read target file or directory for static analysis."""

class ConfigParseError(MCPSecError):
    """Failed to parse an MCP configuration file."""


# ---------------------------------------------------------------------------
# Storage errors
# ---------------------------------------------------------------------------

class StorageError(MCPSecError):
    """Problem with SQLite scan history storage."""

class ScanNotFoundError(StorageError):
    """Requested scan ID does not exist in storage."""
