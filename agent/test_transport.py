"""Transport regression tests for the agent's Gateway (MCP) connection.

These exist because a dependency drift broke `agent_core`'s transport import with no
test failure: the suite deliberately avoided importing agent_core, so the only signal
was a container that would not start. This runs the real transport against a real
local MCP server, so the same class of break fails here instead.

Needs the agent's pinned deps (`uv run --with-requirements agent/requirements.txt`),
which also makes this a check that the dependency set still resolves.
"""

from __future__ import annotations

import multiprocessing
import os
import socket
import sys
import time
import urllib.error
import urllib.request

import pytest

sys.path.insert(0, os.path.dirname(__file__))
os.environ.setdefault("AWS_REGION", "us-west-2")

TOKEN = "test-user-jwt-abc123"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _serve(port: int, header_log: str) -> None:
    """Minimal MCP streamable-http server that records the Authorization header."""
    from mcp.server.mcpserver import MCPServer
    import uvicorn

    server = MCPServer("test-server")

    @server.tool()
    def echo(text: str) -> str:
        """Echo the input back."""
        return f"echo:{text}"

    inner = server.streamable_http_app()

    async def app(scope, receive, send):
        if scope["type"] == "http":
            headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
            if "authorization" in headers:
                with open(header_log, "a") as fh:
                    fh.write(headers["authorization"] + "\n")
        await inner(scope, receive, send)

    uvicorn.run(app, host="127.0.0.1", port=port, log_level="error")


@pytest.fixture(scope="module")
def mcp_server(tmp_path_factory):
    port = _free_port()
    header_log = str(tmp_path_factory.mktemp("hdr") / "auth.txt")
    proc = multiprocessing.Process(target=_serve, args=(port, header_log), daemon=True)
    proc.start()
    url = f"http://127.0.0.1:{port}/mcp"
    for _ in range(100):
        try:
            urllib.request.urlopen(url, timeout=1)
            break
        except urllib.error.HTTPError:
            break  # responding, just not to a bare GET
        except Exception:
            time.sleep(0.1)
    else:
        proc.terminate()
        pytest.fail("local MCP server did not start")
    yield url, header_log
    proc.terminate()
    proc.join(timeout=5)


@pytest.fixture
def connected(mcp_server, monkeypatch):
    """Open a session through the agent's own transport; record the http clients it
    creates so the test can assert they are closed again."""
    url, header_log = mcp_server
    import agent_core
    from strands.tools.mcp.mcp_client import MCPClient

    created = []
    real_factory = agent_core.create_mcp_http_client

    def spy(*args, **kwargs):
        client = real_factory(*args, **kwargs)
        created.append(client)
        return client

    monkeypatch.setattr(agent_core, "create_mcp_http_client", spy)

    client = MCPClient(lambda: agent_core._gateway_transport(url, TOKEN))
    client.__enter__()
    try:
        yield client, created, header_log
    finally:
        client.__exit__(None, None, None)


def test_strands_accepts_the_transport_and_lists_tools(connected):
    client, _, _ = connected
    assert "echo" in [t.tool_name for t in client.list_tools_sync()]


def test_user_token_reaches_the_server(connected):
    client, _, header_log = connected
    client.list_tools_sync()
    assert f"Bearer {TOKEN}" in open(header_log).read().splitlines()


def test_owned_http_client_is_closed_on_exit(connected):
    client, created, _ = connected
    client.list_tools_sync()
    client.__exit__(None, None, None)  # the fixture's exit is then a no-op
    assert created, "transport created no http client"
    # mcp 2.x only closes a client it created itself; ours must not leak per session.
    assert all(c.is_closed for c in created)
