"""Core agent: Strands Agent on Bedrock, with AgentCore Memory for session
continuity and an MCP Gateway client for per-user tool identity pass-through.

Server-reuse model (see AWS AgentCore + Strands guidance): the model, the MCP
client, and the agent are built ONCE per session and cached — not rebuilt per
message. Rebuilding per message re-handshakes the Gateway and re-lists tools
every time, which adds ~15–20s of latency. AgentCore gives each session its own
microVM, so the cache holds essentially one entry per container.

Memory: AgentCoreMemorySessionManager with batch_size=1 persists each turn to
Memory immediately (STM), so history survives idle-termination + a new microVM,
and is keyed by (actor_id, session_id) — one long thread per user, shared across
reconnects and both Lark entrypoints.

Identity pass-through: the caller supplies the user's Cognito access token, already
verified by `identity.verify_access_token`, and it is used verbatim as the Bearer on
the MCP connection. The agent mints nothing, so it cannot assert an identity it was
not given; the Gateway authorizer + interceptor see the real end-user.

`run_chat` returns the final text; `stream_chat` yields text deltas.
"""

from __future__ import annotations

import hashlib
import os
import time
import logging
import threading
from contextlib import asynccontextmanager
from typing import Iterator

from strands import Agent
from strands.models import BedrockModel
from strands.tools.mcp.mcp_client import MCPClient
from mcp.client.streamable_http import streamable_http_client
from mcp.shared._httpx_utils import create_mcp_http_client

from identity import jwt_exp

log = logging.getLogger("agent.core")

_REGION = os.environ.get("AWS_REGION", "us-west-2")
_MODEL_ID = os.environ.get("BEDROCK_MODEL_ID", "global.anthropic.claude-sonnet-5")
_GATEWAY_URL = os.environ.get("GATEWAY_URL", "").rstrip("/")
_MEMORY_ID = os.environ.get("BEDROCK_AGENTCORE_MEMORY_ID", "")
_SYSTEM = os.environ.get(
    "AGENT_SYSTEM_PROMPT",
    "You are a helpful assistant embedded in Lark. Be concise. "
    "Use the provided tools when they help answer the user.",
)
# Rebuild a cached session this many seconds before its forwarded token expires.
_EXPIRY_MARGIN = int(os.environ.get("SESSION_EXPIRY_MARGIN", "60"))
# Text that marks a Gateway rejection of the forwarded token.
_AUTH_FAILURE_MARKERS = ("401", "403", "unauthorized", "insufficient_scope", "invalid_token")

_model = BedrockModel(model_id=_MODEL_ID, streaming=True)

# session_id -> {agent, mcp, token, expires_at}. One microVM ≈ one session.
_sessions: dict[str, dict] = {}
_lock = threading.Lock()


def _session_id_for(actor_id: str) -> str:
    """Deterministic per-user session id: one long conversation thread per user,
    shared across reconnects and entrypoints (STM retains it 30 days)."""
    return "sess-" + hashlib.sha256(actor_id.encode()).hexdigest()[:32]


def _make_session_manager(actor_id: str, session_id: str):
    """AgentCore Memory (STM) session manager, or None if Memory isn't configured.
    batch_size=1 → each turn is sent to Memory immediately (no close() needed)."""
    if not _MEMORY_ID:
        return None
    from bedrock_agentcore.memory.integrations.strands.config import AgentCoreMemoryConfig
    from bedrock_agentcore.memory.integrations.strands.session_manager import (
        AgentCoreMemorySessionManager,
    )
    cfg = AgentCoreMemoryConfig(
        memory_id=_MEMORY_ID, session_id=session_id, actor_id=actor_id, batch_size=1,
    )
    return AgentCoreMemorySessionManager(cfg, region_name=_REGION)


@asynccontextmanager
async def _gateway_transport(url: str, token: str):
    """MCP transport carrying this user's JWT. mcp 2.x only closes an http client it
    created itself, so own it here: the session is rebuilt when the token nears expiry
    and a caller-supplied client would otherwise leak its connection pool each time."""
    async with create_mcp_http_client(headers={"Authorization": f"Bearer {token}"}) as http_client:
        async with streamable_http_client(url, http_client=http_client) as streams:
            yield streams


def _build_session(actor_id: str, token: str) -> dict:
    """Build a fresh (agent, mcp) for a session. MCP client is entered once and
    kept open; tools are listed once here, not per message."""
    session_id = _session_id_for(actor_id)
    mcp = None
    tools = []
    if _GATEWAY_URL:
        mcp = MCPClient(lambda: _gateway_transport(_GATEWAY_URL, token))
        mcp.__enter__()  # persistent connection for the session's lifetime
        tools = mcp.list_tools_sync()
    agent = Agent(
        model=_model, system_prompt=_SYSTEM, tools=tools,
        session_manager=_make_session_manager(actor_id, session_id),
    )
    return {"agent": agent, "mcp": mcp, "token": token,
            "expires_at": jwt_exp(token) - _EXPIRY_MARGIN}


def _close(session: dict) -> None:
    if session.get("mcp"):
        try:
            session["mcp"].__exit__(None, None, None)
        except Exception:
            pass


def _get_session(actor_id: str, token: str) -> dict:
    """Return the cached session for this user, rebuilding it if absent, if its
    forwarded token is near expiry, or if the caller supplied a fresher token."""
    session_id = _session_id_for(actor_id)
    with _lock:
        s = _sessions.get(session_id)
        fresh = s and time.time() < s["expires_at"] and s["token"] == token
        if fresh:
            return s
        if s:
            _close(s)  # stale token pinned in the MCP client — drop the connection
        s = _build_session(actor_id, token)
        _sessions[session_id] = s
        return s


def _invalidate(actor_id: str) -> None:
    """Drop the cached session so the next call rebuilds with the current token."""
    session_id = _session_id_for(actor_id)
    with _lock:
        s = _sessions.pop(session_id, None)
    if s:
        _close(s)


def _is_auth_failure(exc: Exception) -> bool:
    text = str(exc).lower()
    return any(m in text for m in _AUTH_FAILURE_MARKERS)


def run_chat(actor_id: str, message: str, token: str) -> str:
    """Non-streaming chat → assistant's final text. History via Memory.

    Retries once on a Gateway auth failure: the cached MCP client pins the token it
    was built with, so a rebuild with the current one is the recovery path.
    """
    try:
        return str(_get_session(actor_id, token)["agent"](message))
    except Exception as e:
        if not _is_auth_failure(e):
            raise
        log.warning("gateway rejected the forwarded token; rebuilding session once")
        _invalidate(actor_id)
        return str(_get_session(actor_id, token)["agent"](message))


def stream_chat(actor_id: str, message: str, token: str) -> Iterator[str]:
    """Streaming chat for the WebSocket path. Yields text deltas.

    Only retries before the first delta reaches the client, so a recovery can never
    duplicate output that was already rendered.
    """
    try:
        yield from _stream_once(actor_id, message, token)
    except _AuthFailedBeforeOutput:
        log.warning("gateway rejected the forwarded token; rebuilding session once")
        _invalidate(actor_id)
        yield from _stream_once(actor_id, message, token)


class _AuthFailedBeforeOutput(Exception):
    """Gateway auth failed with nothing emitted yet, so a retry is safe."""


def _stream_once(actor_id: str, message: str, token: str) -> Iterator[str]:
    import asyncio

    emitted = False
    try:
        agent = _get_session(actor_id, token)["agent"]
    except Exception as e:
        if _is_auth_failure(e):
            raise _AuthFailedBeforeOutput(str(e)) from e
        raise

    loop = asyncio.new_event_loop()
    try:
        agen = agent.stream_async(message)
        while True:
            try:
                event = loop.run_until_complete(agen.__anext__())
            except StopAsyncIteration:
                break
            except Exception as e:
                if not emitted and _is_auth_failure(e):
                    raise _AuthFailedBeforeOutput(str(e)) from e
                raise
            # Strands emits {"data": "<text chunk>"} for streamed model text.
            if isinstance(event, dict) and "data" in event:
                emitted = True
                yield event["data"]
    finally:
        loop.close()
