"""MCPSec — Pytest fixtures for test servers.

Spins up compliant and non-compliant MCP servers on random ports
before tests, tears them down after.
"""

from __future__ import annotations

import asyncio
import socket
import time
from typing import Generator

import pytest
import uvicorn
from multiprocessing import Process

from tests.servers.compliant import (
    build_compliant_server,
    create_test_token as create_compliant_token,
)
from tests.servers.non_compliant import (
    build_non_compliant_server,
    create_test_token as create_non_compliant_token,
)


# ---------------------------------------------------------------------------
# Port helpers
# ---------------------------------------------------------------------------

def _find_free_port() -> int:
    """Find an available port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_server(port: int, timeout: float = 5.0) -> None:
    """Block until the server is accepting connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except (ConnectionRefusedError, OSError):
            time.sleep(0.1)
    raise RuntimeError(f"Server on port {port} did not start within {timeout}s")


def _run_server(app_builder, port: int) -> None:
    """Run a Starlette app in a subprocess."""
    app = app_builder(port)
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="error")


# ---------------------------------------------------------------------------
# Fixtures — compliant server
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def compliant_port() -> Generator[int, None, None]:
    """Start the compliant test server and yield its port."""
    port = _find_free_port()
    process = Process(
        target=_run_server,
        args=(build_compliant_server, port),
        daemon=True,
    )
    process.start()
    try:
        _wait_for_server(port)
        yield port
    finally:
        process.terminate()
        process.join(timeout=3)


@pytest.fixture(scope="session")
def compliant_url(compliant_port: int) -> str:
    """Base URL for the compliant test server."""
    return f"http://127.0.0.1:{compliant_port}"


@pytest.fixture()
def compliant_token(compliant_port: int) -> str:
    """Valid token for the compliant server with all scopes."""
    return create_compliant_token(compliant_port, scopes=["read", "write", "admin"])


@pytest.fixture()
def compliant_read_token(compliant_port: int) -> str:
    """Token with read-only scope for the compliant server."""
    return create_compliant_token(compliant_port, scopes=["read"])


@pytest.fixture()
def compliant_wrong_audience_token(compliant_port: int) -> str:
    """Token with wrong audience claim — should be rejected by compliant server."""
    return create_compliant_token(
        compliant_port,
        scopes=["read", "write", "admin"],
        audience="http://wrong-server.example.com",
    )


# ---------------------------------------------------------------------------
# Fixtures — non-compliant server
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def non_compliant_port() -> Generator[int, None, None]:
    """Start the non-compliant test server and yield its port."""
    port = _find_free_port()
    process = Process(
        target=_run_server,
        args=(build_non_compliant_server, port),
        daemon=True,
    )
    process.start()
    try:
        _wait_for_server(port)
        yield port
    finally:
        process.terminate()
        process.join(timeout=3)


@pytest.fixture(scope="session")
def non_compliant_url(non_compliant_port: int) -> str:
    """Base URL for the non-compliant test server."""
    return f"http://127.0.0.1:{non_compliant_port}"


@pytest.fixture()
def non_compliant_token(non_compliant_port: int) -> str:
    """Valid token for the non-compliant server with all scopes."""
    return create_non_compliant_token(non_compliant_port, scopes=["read", "write", "admin"])


@pytest.fixture()
def non_compliant_read_token(non_compliant_port: int) -> str:
    """Token with read-only scope for the non-compliant server."""
    return create_non_compliant_token(non_compliant_port, scopes=["read"])


@pytest.fixture()
def non_compliant_wrong_audience_token(non_compliant_port: int) -> str:
    """Token with wrong audience — non-compliant server should ACCEPT this (bug)."""
    return create_non_compliant_token(
        non_compliant_port,
        scopes=["read", "write", "admin"],
        audience="http://wrong-server.example.com",
    )
