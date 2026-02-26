"""MCPSec — Non-Compliant Test MCP Server.

A FastMCP server that deliberately violates the MCP authorization spec.
Used as the negative baseline for active check validation.

Spec violations implemented:
    AUTH-003  Accepts any JWT regardless of aud claim
    AUTH-007  Ignores resource parameter, no audience binding on tokens
    AUTH-010  Returns generic 403 with no WWW-Authenticate header
    AUTHZ-001 admin_delete has no scope requirement — any token works
    AUTHZ-004 write_data executes with read-only token
    TRANS-003 Uses sequential integer session IDs (zero entropy)
    TRANS-004 Accepts session from any client, no IP binding

Run standalone:
    python tests/servers/non_compliant.py
"""

from __future__ import annotations

import itertools
import json
import time
from typing import Any, Optional

import jwt
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Shared test constants — same as compliant server
# ---------------------------------------------------------------------------

SERVER_URI = "http://localhost:{port}"
ISSUER = "http://localhost:{port}/auth"
JWT_SECRET = "mcpsec-test-secret-do-not-use-in-production"
JWT_ALGORITHM = "HS256"

SCOPES = ["read", "write", "admin"]


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def create_test_token(
    port: int,
    scopes: list[str] | None = None,
    audience: str | None = None,
    issuer: str | None = None,
    expires_in: int = 3600,
    extra_claims: dict | None = None,
) -> str:
    """Create a signed JWT for testing.

    Same signature as compliant server — tests use this to craft tokens.
    """
    now = int(time.time())
    payload = {
        "iss": issuer or ISSUER.format(port=port),
        "aud": audience or SERVER_URI.format(port=port),
        "sub": "test-client",
        "iat": now,
        "exp": now + expires_in,
        "scope": " ".join(scopes or ["read"]),
        "client_id": "mcpsec-test-client",
    }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


# ---------------------------------------------------------------------------
# Token validation (NON-COMPLIANT — deliberately weak)
# ---------------------------------------------------------------------------

class WeakTokenValidator:
    """Validates Bearer tokens WITHOUT spec-required checks.

    Violations:
        AUTH-003: Does NOT validate audience claim
        AUTH-007: Does NOT check resource parameter binding
    """

    def __init__(self, port: int):
        self.port = port

    def validate(self, token: str) -> dict[str, Any] | None:
        """Validate token signature only — ignores audience and issuer."""
        try:
            claims = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=[JWT_ALGORITHM],
                options={
                    "verify_aud": False,   # AUTH-003: ❌ audience NOT checked
                    "verify_iss": False,   # ❌ issuer NOT checked
                    "verify_exp": True,    # at least check expiry
                },
            )
            return claims
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def get_scopes(self, claims: dict) -> set[str]:
        """Extract scopes from claims."""
        scope_str = claims.get("scope", "")
        return set(scope_str.split()) if scope_str else set()


# ---------------------------------------------------------------------------
# Session manager (NON-COMPLIANT — deliberately weak)
# ---------------------------------------------------------------------------

class WeakSessionManager:
    """Manages MCP sessions with NO entropy and NO binding.

    Violations:
        TRANS-003: Uses sequential integers as session IDs (zero entropy)
        TRANS-004: Does NOT bind sessions to client IP
    """

    def __init__(self):
        self._counter = itertools.count(1)
        self._sessions: dict[str, dict[str, Any]] = {}

    def create_session(self, client_ip: str) -> str:
        """Create a session with a predictable sequential ID."""
        # TRANS-003: ❌ Sequential integer — zero entropy
        session_id = str(next(self._counter))
        self._sessions[session_id] = {
            "created_at": time.time(),
            # TRANS-004: ❌ client_ip NOT stored — no binding
        }
        return session_id

    def validate_session(self, session_id: str, client_ip: str) -> bool:
        """Accept any session from any client.

        TRANS-004: ❌ No IP binding check — always returns True if session exists.
        """
        return session_id in self._sessions

    def get_session_id(self) -> str:
        """Get a raw session ID for entropy analysis."""
        return str(next(self._counter))


# ---------------------------------------------------------------------------
# Well-known endpoint handlers (partially non-compliant)
# ---------------------------------------------------------------------------

def protected_resource_metadata(port: int) -> dict:
    """RFC 9728 Protected Resource Metadata.

    Present but missing scopes_supported — minor violation.
    """
    return {
        "resource": SERVER_URI.format(port=port),
        "authorization_servers": [ISSUER.format(port=port)],
        # ❌ scopes_supported missing
    }


def authorization_server_metadata(port: int) -> dict:
    """RFC 8414 Authorization Server Metadata.

    Present but missing code_challenge_methods_supported and
    client_id_metadata_document_supported.
    """
    issuer = ISSUER.format(port=port)
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "scopes_supported": SCOPES,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        # ❌ code_challenge_methods_supported missing (AUTH-005)
        # ❌ registration_endpoint missing (AUTH-012)
        # ❌ client_id_metadata_document_supported missing (AUTH-012)
    }


# ---------------------------------------------------------------------------
# Build the non-compliant server
# ---------------------------------------------------------------------------

def build_non_compliant_server(port: int = 9200) -> Starlette:
    """Build a non-compliant MCP server with weak auth.

    Returns a Starlette app with deliberate spec violations.
    """
    validator = WeakTokenValidator(port)
    sessions = WeakSessionManager()

    # --- FastMCP server with tools ---
    mcp = FastMCP(
        name="MCPSec Non-Compliant Test Server",
        instructions="A non-compliant test server for MCPSec active checks.",
    )

    @mcp.tool()
    def read_data(query: str) -> str:
        """Read data from the test database."""
        return f"Data for query: {query}"

    @mcp.tool()
    def write_data(key: str, value: str) -> str:
        """Write data to the test database."""
        return f"Written: {key}={value}"

    @mcp.tool()
    def admin_delete(target: str) -> str:
        """Delete all records matching target. Admin only."""
        return f"Deleted: {target}"

    # ❌ AUTHZ-001 / AUTHZ-004: NO per-tool scope requirements defined
    # All tools accessible with any valid token

    # --- HTTP route handlers ---

    async def well_known_protected_resource(request: Request) -> JSONResponse:
        return JSONResponse(protected_resource_metadata(port))

    async def well_known_oauth_as(request: Request) -> JSONResponse:
        return JSONResponse(authorization_server_metadata(port))

    async def mcp_endpoint(request: Request) -> Response:
        """Main MCP endpoint with weak auth enforcement."""
        client_ip = request.client.host if request.client else "unknown"

        # --- Session handling (non-compliant) ---
        session_id = request.headers.get("mcp-session-id")
        if session_id:
            # TRANS-004: ❌ Accepts session from any IP
            if not sessions.validate_session(session_id, client_ip):
                session_id = sessions.create_session(client_ip)
        else:
            session_id = sessions.create_session(client_ip)

        # --- Parse body ---
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None},
                status_code=400,
            )

        method = body.get("method", "")

        # Allow initialize and tools/list without auth
        auth_not_required = {"initialize", "notifications/initialized", "tools/list"}
        if method in auth_not_required:
            result = _dispatch_mcp(method, body.get("params", {}))
            return JSONResponse(
                {"jsonrpc": "2.0", "result": result, "id": body.get("id")},
                headers={"mcp-session-id": session_id},
            )

        # --- Auth check (weak) ---
        auth_header = request.headers.get("authorization", "")

        if not auth_header.startswith("Bearer "):
            # ❌ AUTH-009 violation: 401 but with minimal WWW-Authenticate
            # Missing resource_metadata and scope parameters
            return JSONResponse(
                {"jsonrpc": "2.0", "error": {"code": -32000, "message": "Auth required"}, "id": body.get("id")},
                status_code=401,
                headers={
                    "WWW-Authenticate": "Bearer",  # ❌ No resource_metadata, no scope
                    "mcp-session-id": session_id,
                },
            )

        token = auth_header[7:]
        # AUTH-003: ❌ Validates signature only, NOT audience
        claims = validator.validate(token)

        if claims is None:
            return JSONResponse(
                {"jsonrpc": "2.0", "error": {"code": -32000, "message": "Invalid token"}, "id": body.get("id")},
                status_code=401,
                headers={
                    "WWW-Authenticate": "Bearer",  # ❌ Minimal header
                    "mcp-session-id": session_id,
                },
            )

        # --- Tool call (NO scope enforcement) ---
        if method == "tools/call":
            tool_name = body.get("params", {}).get("name", "")

            # AUTHZ-001: ❌ admin_delete has NO scope check
            # AUTHZ-004: ❌ write_data has NO scope check
            # Any authenticated user can call any tool

            # AUTH-010: ❌ Even if we wanted to check scope,
            # the error response would be wrong:
            # Returns generic 403 with NO WWW-Authenticate header

            # For testing AUTH-010: if a special header is set,
            # simulate a "scope check" that fails incorrectly
            if request.headers.get("x-mcpsec-test-scope-check") == "true":
                return JSONResponse(
                    {"jsonrpc": "2.0", "error": {"code": -32000, "message": "Forbidden"}, "id": body.get("id")},
                    status_code=403,
                    # AUTH-010: ❌ No WWW-Authenticate header
                    # ❌ No error="insufficient_scope"
                    # ❌ No scope guidance
                    headers={"mcp-session-id": session_id},
                )

        # --- Dispatch (no scope check) ---
        result = _dispatch_mcp(method, body.get("params", {}))
        return JSONResponse(
            {"jsonrpc": "2.0", "result": result, "id": body.get("id")},
            headers={"mcp-session-id": session_id},
        )

    async def session_endpoint(request: Request) -> JSONResponse:
        """Endpoint to obtain session IDs for entropy testing."""
        client_ip = request.client.host if request.client else "unknown"
        session_id = sessions.create_session(client_ip)
        return JSONResponse({"session_id": session_id})

    # --- Build Starlette app ---
    routes = [
        Route("/.well-known/oauth-protected-resource", well_known_protected_resource),
        Route("/.well-known/oauth-authorization-server", well_known_oauth_as),
        Route("/mcp", mcp_endpoint, methods=["POST"]),
        Route("/session", session_endpoint, methods=["POST"]),
    ]

    app = Starlette(routes=routes)
    return app


# ---------------------------------------------------------------------------
# Simple MCP dispatch
# ---------------------------------------------------------------------------

def _dispatch_mcp(method: str, params: dict) -> Any:
    """Minimal JSON-RPC method dispatcher."""
    if method == "initialize":
        return {
            "protocolVersion": "2025-03-26",
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "MCPSec Non-Compliant Test Server", "version": "1.0.0"},
        }

    if method == "notifications/initialized":
        return {}

    if method == "tools/list":
        return {
            "tools": [
                {
                    "name": "read_data",
                    "description": "Read data from the test database.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string"},  # ❌ No constraints
                        },
                        "required": ["query"],
                    },
                },
                {
                    "name": "write_data",
                    "description": "Write data to the test database.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "key": {"type": "string"},    # ❌ No constraints
                            "value": {"type": "string"},  # ❌ No constraints
                        },
                        "required": ["key", "value"],
                    },
                },
                {
                    "name": "admin_delete",
                    "description": "Delete all records matching target. Admin only.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string"},  # ❌ No constraints
                        },
                        "required": ["target"],
                    },
                },
            ],
        }

    if method == "tools/call":
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})

        if tool_name == "read_data":
            return {"content": [{"type": "text", "text": f"Data for query: {arguments.get('query', '')}"}]}
        elif tool_name == "write_data":
            return {"content": [{"type": "text", "text": f"Written: {arguments.get('key', '')}={arguments.get('value', '')}"}]}
        elif tool_name == "admin_delete":
            return {"content": [{"type": "text", "text": f"Deleted: {arguments.get('target', '')}"}]}
        else:
            return {"error": {"code": -32601, "message": f"Unknown tool: {tool_name}"}}

    return {"error": {"code": -32601, "message": f"Unknown method: {method}"}}


# ---------------------------------------------------------------------------
# Standalone runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    port = 9200
    print(f"Starting non-compliant test server on port {port}...")
    print(f"Server URI: {SERVER_URI.format(port=port)}")
    print(f"Test token: {create_test_token(port, scopes=['read'])}")
    app = build_non_compliant_server(port)
    uvicorn.run(app, host="127.0.0.1", port=port)
