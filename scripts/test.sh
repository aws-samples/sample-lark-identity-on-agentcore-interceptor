#!/usr/bin/env bash
# Run all unit tests. Each suite runs in its own process because the three
# Lambda/agent dirs each define an `index.py`/`identity.py` — running them in a
# single pytest session would cross-import the wrong module.
set -euo pipefail
cd "$(cd "$(dirname "$0")/.." && pwd)"

echo "== agent =="
uv run --with boto3 --with aiohttp --with pytest python -m pytest agent/test_agent.py -q

# Identity is the root of trust: the Runtime authenticates inbound with SigV4, so the
# agent itself must verify the caller-supplied token. Needs real RSA signing.
echo "== agent identity (JWT verification) =="
uv run --with PyJWT --with cryptography --with pytest python -m pytest agent/test_identity.py -q

# Uses the pinned agent deps, so it also checks that dependency set still resolves.
echo "== agent transport (real MCP round-trip) =="
uv run --with-requirements agent/requirements.txt --with pytest python -m pytest agent/test_transport.py -q

echo "== router =="
uv run --with cryptography --with boto3 --with pytest python -m pytest lambda/router/test_router.py -q

echo "== web_api =="
uv run --with boto3 --with pytest python -m pytest lambda/web_api/test_web_api.py -q

echo "== all green =="
