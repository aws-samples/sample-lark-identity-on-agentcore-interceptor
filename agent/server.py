"""AgentCore container server: HTTP contract (8080) + WebSocket (18789).

HTTP 8080 — the AgentCore Runtime contract:
  GET  /ping          -> {"status":"Healthy"}   (must respond within seconds)
  POST /invocations   -> action in {warmup, status, chat}
      chat   : {action,accessToken,message} -> {reply}  (history via Memory)
      warmup : {action} -> {ready:true}
      status : {action} -> {ready, uptime}

WebSocket 18789 — the desktop (Lark-embedded web UI) path. The AgentCore platform
bridges a browser's presigned WSS connection to this port. Protocol (JSON frames):
  client -> {"type":"chat","accessToken":"<jwt>","message":"..."}
  server -> {"type":"delta","text":"..."} *  then  {"type":"final"}
  errors -> {"type":"error","message":"..."}

Identity: every chat carries the caller's Cognito **access** token, which this
server verifies against the pool's JWKS before use — the Runtime's inbound auth is
SigV4, so nothing upstream has checked it. `actorId` is the verified `username`
claim; an unsigned identity is never accepted, and the agent cannot mint one.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time

from aiohttp import web, WSMsgType

import agent_core
from identity import IdentityError, verify_access_token

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("agent.server")

_START = time.time()
_HTTP_PORT = int(os.environ.get("PORT", "8080"))
_WS_PORT = int(os.environ.get("WS_PORT", "18789"))


# ----------------------------- HTTP contract --------------------------------

async def handle_ping(request: web.Request) -> web.Response:
    return web.json_response({"status": "Healthy"})


async def handle_invocations(request: web.Request) -> web.Response:
    try:
        payload = await request.json()
    except Exception:
        return web.json_response({"error": "invalid JSON"}, status=400)

    action = payload.get("action", "chat")

    if action == "status":
        return web.json_response({"ready": True, "uptime": round(time.time() - _START, 1)})

    if action == "warmup":
        return web.json_response({"ready": True})

    if action == "chat":
        message = payload.get("message", "")
        if not message:
            return web.json_response({"error": "message required"}, status=400)
        try:
            token = payload.get("accessToken", "")
            actor_id, _ = verify_access_token(token)
        except IdentityError as e:
            log.warning("rejected chat: %s", e)
            return web.json_response({"error": f"unauthenticated: {e}"})
        try:
            reply = await asyncio.get_event_loop().run_in_executor(
                None, agent_core.run_chat, actor_id, message, token
            )
            return web.json_response({"reply": reply})
        except Exception as e:
            log.exception("chat failed")
            # Return 200: AgentCore wraps non-2xx as RuntimeClientError and drops
            # the body, hiding the real error from callers. The Router surfaces
            # the error field instead.
            return web.json_response({"error": str(e)})

    return web.json_response({"error": f"unknown action: {action}"}, status=400)


# ----------------------------- WebSocket path -------------------------------

async def handle_ws(request: web.Request) -> web.WebSocketResponse:
    ws = web.WebSocketResponse(max_msg_size=64 * 1024)  # AgentCore WS frame limit is 64 KB
    await ws.prepare(request)
    log.info("ws client connected")

    async for msg in ws:
        if msg.type != WSMsgType.TEXT:
            continue
        try:
            frame = json.loads(msg.data)
        except Exception:
            await ws.send_json({"type": "error", "message": "invalid JSON"})
            continue

        if frame.get("type") != "chat":
            await ws.send_json({"type": "error", "message": "unsupported frame type"})
            continue

        message = frame.get("message", "")
        if not message:
            await ws.send_json({"type": "error", "message": "message required"})
            continue
        try:
            token = frame.get("accessToken", "")
            actor_id, _ = verify_access_token(token)
        except IdentityError as e:
            log.warning("rejected ws chat: %s", e)
            await ws.send_json({"type": "error", "message": f"unauthenticated: {e}"})
            continue

        loop = asyncio.get_event_loop()
        try:
            # stream_chat is a sync generator; drain it in an executor, forwarding
            # each delta onto the loop.
            queue: asyncio.Queue = asyncio.Queue()

            def produce():
                try:
                    for delta in agent_core.stream_chat(actor_id, message, token):
                        loop.call_soon_threadsafe(queue.put_nowait, ("delta", delta))
                except Exception as e:  # noqa: BLE001
                    loop.call_soon_threadsafe(queue.put_nowait, ("error", str(e)))
                finally:
                    loop.call_soon_threadsafe(queue.put_nowait, ("final", None))

            loop.run_in_executor(None, produce)

            while True:
                kind, data = await queue.get()
                if kind == "delta":
                    await ws.send_json({"type": "delta", "text": data})
                elif kind == "error":
                    await ws.send_json({"type": "error", "message": data})
                elif kind == "final":
                    await ws.send_json({"type": "final"})
                    break
        except Exception as e:  # noqa: BLE001
            log.exception("ws chat failed")
            await ws.send_json({"type": "error", "message": str(e)})

    log.info("ws client disconnected")
    return ws


# ------------------------------- bootstrap ----------------------------------

def build_http_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/ping", handle_ping)
    app.router.add_post("/invocations", handle_invocations)
    # AgentCore bridges browser WSS to /ws on THIS port (8080), matching the
    # official SDK contract (Route /invocations + WebSocketRoute /ws).
    app.router.add_get("/ws", handle_ws)
    return app


def build_ws_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/", handle_ws)
    app.router.add_get("/ws", handle_ws)
    return app


async def main() -> None:
    http_runner = web.AppRunner(build_http_app())
    await http_runner.setup()
    await web.TCPSite(http_runner, "0.0.0.0", _HTTP_PORT).start()
    log.info("HTTP contract on :%d", _HTTP_PORT)

    ws_runner = web.AppRunner(build_ws_app())
    await ws_runner.setup()
    await web.TCPSite(ws_runner, "0.0.0.0", _WS_PORT).start()
    log.info("WebSocket on :%d", _WS_PORT)

    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    asyncio.run(main())
