"""Verify the caller-supplied Cognito access token; never mint one.

The agent adds nothing of its own to the identity chain: the caller (router, after
verifying the Lark webhook signature; or web_api, after verifying the Lark login)
mints the user's token, and the agent only proves it is genuine and forwards it as
the Bearer on outbound MCP/Gateway calls.

The Runtime's inbound auth is SigV4, so nothing upstream has checked this token —
verification here is mandatory, not a formality. `iss`, signature, `exp`,
`token_use` and `client_id` are all enforced; an access token is required because
the Gateway's `allowedClients` matches the `client_id` claim, which ID tokens lack.
"""

from __future__ import annotations

import base64
import json
import logging
import os

import jwt
from jwt import PyJWKClient

log = logging.getLogger("agent.identity")

_REGION = os.environ.get("AWS_REGION", "us-west-2")
_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")

_ISSUER = f"https://cognito-idp.{_REGION}.amazonaws.com/{_USER_POOL_ID}"
_JWKS_URL = f"{_ISSUER}/.well-known/jwks.json"

# PyJWKClient caches the signing keys, so steady-state verification is local.
_jwks_client: PyJWKClient | None = None


class IdentityError(Exception):
    """The supplied token is missing, malformed, expired or not ours."""


def _client() -> PyJWKClient:
    global _jwks_client
    if not (_USER_POOL_ID and _CLIENT_ID):
        raise IdentityError("Cognito env not configured (COGNITO_USER_POOL_ID/CLIENT_ID)")
    if _jwks_client is None:
        _jwks_client = PyJWKClient(_JWKS_URL, cache_keys=True)
    return _jwks_client


def verify_access_token(token: str) -> tuple[str, dict]:
    """Return (actor_id, claims) for a genuine Cognito access token from our pool.

    actor_id is the `username` claim, i.e. ``lark:{open_id}``. Raises IdentityError
    on anything that is not a live access token issued to our app client.
    """
    if not token:
        raise IdentityError("no token supplied")
    token = token[7:].strip() if token.lower().startswith("bearer ") else token.strip()

    try:
        signing_key = _client().get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=_ISSUER,
            # Access tokens carry `client_id`, not `aud`; checked explicitly below.
            options={"verify_aud": False, "require": ["exp", "iss", "sub"]},
        )
    except jwt.PyJWTError as e:
        raise IdentityError(f"token rejected: {e}") from e
    except Exception as e:  # JWKS fetch/parse problems
        raise IdentityError(f"token could not be verified: {e}") from e

    if claims.get("token_use") != "access":
        raise IdentityError(f"expected an access token, got token_use={claims.get('token_use')!r}")
    if claims.get("client_id") != _CLIENT_ID:
        raise IdentityError("token was issued to a different app client")

    actor_id = claims.get("username") or ""
    if not actor_id.startswith("lark:"):
        raise IdentityError(f"unexpected username claim: {actor_id!r}")

    return actor_id, claims


def jwt_exp(token: str) -> float:
    """Read the `exp` claim without verifying — callers must verify first.

    Used to expire a cached session before the token it carries goes stale.
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return float(json.loads(base64.urlsafe_b64decode(payload)).get("exp", 0))
    except Exception:
        return 0.0
