"""MCPSec — Spec-Compliant Test MCP Server.

A FastMCP server that correctly implements the MCP authorization spec.
Used as the positive baseline for active check validation.

Spec requirements implemented:
    AUTH-003  Token audience binding — validates aud claim matches server URI
    AUTH-007  Resource indicator — tokens bound to resource parameter
    AUTH-010  Scope error handling — proper 403 + WWW-Authenticate
    AUTHZ-001 Admin tool auth — admin_delete requires 'admin' scope
    AUTHZ-004 Scope enforcement — write_data requires 'write' scope
    TRANS-003 Session entropy — secrets.token_urlsafe(32) = 256 bits
    TRANS-004 Session binding — sessions bound to client IP

Run standalone:
    python tests/servers/compliant.py
"""

from __future__ import annotations

import json
import secrets
import time
from datetime import datetime, timezone
from typing import Any, Optional

import jwt
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

from fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Shared test constants — tests use these to craft tokens
# ---------------------------------------------------------------------------

SERVER_URI = "http://localhost:{port}"
ISSUER = "http://localhost:{port}/auth"
JWT_SECRET = "mcpsec-test-secret-do-not-use-in-production"
JWT_ALGORITHM = "HS256"

# Available scopes
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

    This function is called by tests to craft tokens with specific claims.
    The compliant server validates all of these fields.
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
# Token validation (spec-compliant)
# ---------------------------------------------------------------------------

class TokenValidator:
    """Validates Bearer tokens according to MCP spec requirements.

    Checks:
        - Token signature (HS256 with shared secret)
        - Issuer matches expected issuer
        - Audience matches THIS server's URI (AUTH-003)
        - Token is not expired
        - Scopes are present
    """

    def __init__(self, port: int):
        self.port = port
        self.server_uri = SERVER_URI.format(port=port)
        self.issuer = ISSUER.format(port=port)

    def validate(self, token: str) -> dict[str, Any] | None:
        """Validate token and return decoded claims, or None on failure."""
        try:
            claims = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=[JWT_ALGORITHM],
                audience=self.server_uri,   # AUTH-003: enforce audience
                issuer=self.issuer,
                options={
                    "require": ["iss", "aud", "exp", "sub", "scope"],
                    "verify_aud": True,      # AUTH-003: strict audience check
                    "verify_iss": True,
                    "verify_exp": True,
                },
            )
            return claims
        except jwt.InvalidAudienceError:
            return None  # AUTH-003: wrong audience → reject
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None

    def get_scopes(self, claims: dict) -> set[str]:
        """Extract scopes from validated claims."""
        scope_str = claims.get("scope", "")
        return set(scope_str.split()) if scope_str else set()


# ---------------------------------------------------------------------------
# Session manager (spec-compliant)
# ---------------------------------------------------------------------------

class SessionManager:
    """Manages MCP sessions with proper entropy and binding.

    TRANS-003: Session IDs use secrets.token_urlsafe(32) = 256 bits
    TRANS-004: Sessions are bound to originating client IP
    """

    def __init__(self):
        self._sessions: dict[str, dict[str, Any]] = {}

    def create_session(self, client_ip: str) -> str:
        """Create a new session bound to the client IP."""
        session_id = secrets.token_urlsafe(32)  # TRANS-003: 256-bit entropy
        self._sessions[session_id] = {
            "client_ip": client_ip,
            "created_at": time.time(),
        }
        return session_id

    def validate_session(self, session_id: str, client_ip: str) -> bool:
        """Validate session exists and is bound to the requesting client.

        TRANS-004: Reject if client IP doesn't match the session creator.
        """
        session = self._sessions.get(session_id)
        if session is None:
            return False
        return session["client_ip"] == client_ip  # TRANS-004: binding check

    def get_session_id(self) -> str:
        """Get a raw session ID for entropy analysis."""
        return secrets.token_urlsafe(32)


# ---------------------------------------------------------------------------
# Well-known endpoint handlers
# ---------------------------------------------------------------------------

def protected_resource_metadata(port: int) -> dict:
    """RFC 9728 Protected Resource Metadata."""
    return {
        "resource": SERVER_URI.format(port=port),
        "authorization_servers": [ISSUER.format(port=port)],
        "scopes_supported": SCOPES,
        "bearer_methods_supported": ["header"],
    }


def authorization_server_metadata(port: int) -> dict:
    """RFC 8414 Authorization Server Metadata."""
    issuer = ISSUER.format(port=port)
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "registration_endpoint": f"{issuer}/register",
        "scopes_supported": SCOPES,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "client_id_metadata_document_supported": True,
    }


# ---------------------------------------------------------------------------
# Build the compliant server
# ---------------------------------------------------------------------------

def build_compliant_server(port: int = 9100) -> Starlette:
    """Build a spec-compliant MCP server with proper auth.

    Returns a Starlette app that wraps FastMCP with auth middleware.
    """
    validator = TokenValidator(port)
    sessions = SessionManager()

    # --- FastMCP server with tools ---
    mcp = FastMCP(
        name="MCPSec Compliant Test Server",
        instructions="A spec-compliant test server for MCPSec active checks.",
    )

    @mcp.tool()
    def read_data(query: str) -> str:
        """Read data from the test database.

        Requires scope: read
        """
        return f"Data for query: {query}"

    @mcp.tool()
    def write_data(key: str, value: str) -> str:
        """Write data to the test database.

        Requires scope: write
        """
        return f"Written: {key}={value}"

    @mcp.tool()
    def admin_delete(target: str) -> str:
        """Delete all records matching target. Admin only.

        Requires scope: admin
        """
        return f"Deleted: {target}"

    # Tool → required scope mapping
    tool_scopes = {
        "read_data": {"read"},
        "write_data": {"write"},
        "admin_delete": {"admin"},
    }

    # --- HTTP route handlers ---

    async def well_known_protected_resource(request: Request) -> JSONResponse:
        return JSONResponse(protected_resource_metadata(port))

    async def well_known_oauth_as(request: Request) -> JSONResponse:
        return JSONResponse(authorization_server_metadata(port))

    async def mcp_endpoint(request: Request) -> Response:
        """Main MCP endpoint with full auth enforcement."""
        client_ip = request.client.host if request.client else "unknown"

        # --- Session handling ---
        session_id = request.headers.get("mcp-session-id")
        if session_id:
            # TRANS-004: Validate session binding
            if not sessions.validate_session(session_id, client_ip):
                return JSONResponse(
                    {"error": "Invalid or unbound session"},
                    status_code=403,
                )
        else:
            # Create new session
            session_id = sessions.create_session(client_ip)

        # --- Auth check ---
        auth_header = request.headers.get("authorization", "")

        # Parse JSON-RPC body to check method
        try:
            body = await request.json()
        except Exception:
            return JSONResponse(
                {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None},
                status_code=400,
            )

        method = body.get("method", "")

        # Allow initialize and tools/list without auth (spec permits this)
        auth_not_required = {"initialize", "notifications/initialized", "tools/list"}
        if method in auth_not_required:
            # Process via simple JSON-RPC dispatch
            result = _dispatch_mcp(mcp, method, body.get("params", {}), tool_scopes, None, None)
            response = JSONResponse(
                {"jsonrpc": "2.0", "result": result, "id": body.get("id")},
                headers={"mcp-session-id": session_id},
            )
            return response

        # All other methods require auth
        if not auth_header.startswith("Bearer "):
            # AUTH-009: Proper 401 with WWW-Authenticate
            return JSONResponse(
                {"jsonrpc": "2.0", "error": {"code": -32000, "message": "Authentication required"}, "id": body.get("id")},
                status_code=401,
                headers={
                    "WWW-Authenticate": (
                        f'Bearer resource_metadata="'
                        f'{SERVER_URI.format(port=port)}/.well-known/oauth-protected-resource", '
                        f'scope="{" ".join(SCOPES)}"'
                    ),
                    "mcp-session-id": session_id,
                },
            )

        token = auth_header[7:]  # Strip "Bearer "
        claims = validator.validate(token)

        if claims is None:
            # AUTH-003: Token rejected (wrong audience, expired, invalid)
            return JSONResponse(
                {"jsonrpc": "2.0", "error": {"code": -32000, "message": "Invalid token"}, "id": body.get("id")},
                status_code=401,
                headers={
                    "WWW-Authenticate": (
                        f'Bearer error="invalid_token", '
                        f'resource_metadata="'
                        f'{SERVER_URI.format(port=port)}/.well-known/oauth-protected-resource", '
                        f'scope="{" ".join(SCOPES)}"'
                    ),
                    "mcp-session-id": session_id,
                },
            )

        token_scopes = validator.get_scopes(claims)

        # --- Tool call scope enforcement ---
        if method == "tools/call":
            tool_name = body.get("params", {}).get("name", "")
            required = tool_scopes.get(tool_name, set())

            if required and not required.intersection(token_scopes):
                # AUTH-010 / AUTHZ-004: Insufficient scope → proper 403
                return JSONResponse(
                    {"jsonrpc": "2.0", "error": {"code": -32000, "message": "Insufficient scope"}, "id": body.get("id")},
                    status_code=403,
                    headers={
                        "WWW-Authenticate": (
                            f'Bearer error="insufficient_scope", '
                            f'scope="{" ".join(required)}"'
                        ),
                        "mcp-session-id": session_id,
                    },
                )

        # --- Dispatch authorized request ---
        result = _dispatch_mcp(mcp, method, body.get("params", {}), tool_scopes, claims, token_scopes)
        return JSONResponse(
            {"jsonrpc": "2.0", "result": result, "id": body.get("id")},
            headers={"mcp-session-id": session_id},
        )

    async def session_endpoint(request: Request) -> JSONResponse:
        """Endpoint to obtain session IDs for entropy testing (TRANS-003)."""
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
# Simple MCP dispatch (for test server only)
# ---------------------------------------------------------------------------

def _dispatch_mcp(
    mcp: FastMCP,
    method: str,
    params: dict,
    tool_scopes: dict,
    claims: dict | None,
    token_scopes: set | None,
) -> Any:
    """Minimal JSON-RPC method dispatcher for the test server."""
    if method == "initialize":
        return {
            "protocolVersion": "2025-03-26",
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "MCPSec Compliant Test Server", "version": "1.0.0"},
        }

    if method == "notifications/initialized":
        return {}

    if method == "tools/list":
        return {
            "tools": [
                {
                    "name": "read_data",
                    "description": "Read data from the test database. Requires scope: read",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string", "description": "Search query"},
                        },
                        "required": ["query"],
                    },
                },
                {
                    "name": "write_data",
                    "description": "Write data to the test database. Requires scope: write",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "key": {"type": "string", "description": "Data key"},
                            "value": {"type": "string", "description": "Data value"},
                        },
                        "required": ["key", "value"],
                    },
                },
                {
                    "name": "admin_delete",
                    "description": "Delete all records matching target. Admin only. Requires scope: admin",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "target": {"type": "string", "description": "Delete target"},
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

    port = 9100
    print(f"Starting compliant test server on port {port}...")
    print(f"Server URI: {SERVER_URI.format(port=port)}")
    print(f"Test token: {create_test_token(port, scopes=['read', 'write', 'admin'])}")
    app = build_compliant_server(port)
    uvicorn.run(app, host="127.0.0.1", port=port)
