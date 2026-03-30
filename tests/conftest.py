"""
pytest configuration — shared fixtures for KEMTLS + OIDC integration tests.

Provides a session-scoped fixture that starts the KEMTLS TCP server as a
subprocess, waits for it to bind, yields for the test session, then tears
it down cleanly.

Usage in test files:
    def test_something(kemtls_server):
        # server is running on localhost:9999
        ...

Or mark autouse=True on a per-module basis:
    pytestmark = pytest.mark.usefixtures("kemtls_server")
"""

import subprocess
import sys
import os
import time
import socket

import pytest


def _wait_for_port(host: str, port: int, timeout: float = 5.0) -> bool:
    """Poll until the TCP port accepts connections or timeout expires."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except (ConnectionRefusedError, OSError):
            time.sleep(0.1)
    return False


@pytest.fixture(scope="session")
def kemtls_server():
    """Start the KEMTLS TCP server as a subprocess for integration tests.

    The server is started once per pytest session and torn down after all
    tests complete.  Tests that require it should declare it as a parameter:

        def test_handshake(kemtls_server): ...

    The fixture yields the subprocess.Popen object so tests can inspect
    returncode or stdout/stderr if needed.
    """
    project_root = os.path.dirname(os.path.abspath(__file__))
    server_script = os.path.join(project_root, "kemtls_server_tcp.py")

    proc = subprocess.Popen(
        [sys.executable, server_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=project_root,
    )

    # Wait until the server port is ready (up to 5 s)
    ready = _wait_for_port("127.0.0.1", 9999, timeout=5.0)
    if not ready:
        proc.terminate()
        proc.wait()
        pytest.fail(
            "KEMTLS server did not become ready within 5 seconds. "
            "Check kemtls_server_tcp.py for errors."
        )

    yield proc

    # Teardown
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
