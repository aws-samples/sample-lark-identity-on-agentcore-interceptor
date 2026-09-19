"""Mint the user's Cognito access token (router side).

The router is an identity authority: it has already verified the Lark webhook
signature fail-closed, so it is entitled to assert who the sender is. It mints the
token here and passes it in the Runtime payload; the agent verifies that signature
and can only forward it — it cannot mint one of its own.

An **access** token is required: the Gateway's `allowedClients` matches the
`client_id` claim, which only access tokens carry. Passwords are HMAC-derived from a
Secrets Manager salt, so they are deterministic and never stored.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time

import boto3
from botocore.exceptions import ClientError

log = logging.getLogger("router.cognito")

_REGION = os.environ.get("AWS_REGION", "us-west-2")
_USER_POOL_ID = os.environ.get("COGNITO_USER_POOL_ID", "")
_CLIENT_ID = os.environ.get("COGNITO_CLIENT_ID", "")
_PASSWORD_SECRET_ID = os.environ.get("COGNITO_PASSWORD_SECRET_ID", "")

_cognito = boto3.client("cognito-idp", region_name=_REGION)
_secrets = boto3.client("secretsmanager", region_name=_REGION)

_salt: str | None = None
_token_cache: dict[str, tuple[str, float]] = {}  # username -> (token, exp)


def _get_salt() -> str:
    global _salt
    if _salt is None:
        _salt = _secrets.get_secret_value(SecretId=_PASSWORD_SECRET_ID)["SecretString"]
    return _salt


def _password(username: str) -> str:
    """Deterministic per-user password; suffix guarantees Cognito complexity."""
    digest = hmac.new(_get_salt().encode(), username.encode(), hashlib.sha256).hexdigest()
    return digest[:32] + "Aa1!"


def _jwt_exp(token: str) -> float:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return float(json.loads(base64.urlsafe_b64decode(payload)).get("exp", 0))
    except Exception:
        return 0.0


def _ensure_user(username: str, email: str = "") -> None:
    try:
        _cognito.admin_get_user(UserPoolId=_USER_POOL_ID, Username=username)
        return
    except ClientError as e:
        if e.response["Error"]["Code"] != "UserNotFoundException":
            raise
    # username is "lark:ou_xxx" — a colon is invalid in an email local part
    safe_local = username.replace(":", "-")
    _cognito.admin_create_user(
        UserPoolId=_USER_POOL_ID, Username=username,
        UserAttributes=[{"Name": "email", "Value": email or f"{safe_local}@lark.local"},
                        {"Name": "email_verified", "Value": "true"}],
        MessageAction="SUPPRESS",
    )
    _cognito.admin_set_user_password(
        UserPoolId=_USER_POOL_ID, Username=username,
        Password=_password(username), Permanent=True,
    )
    log.info("provisioned cognito user %s", username)


def mint_access_token(actor_id: str, email: str = "") -> str:
    """Return a valid Cognito access token for ``actor_id`` (``lark:{open_id}``).

    Cached with a 60s early-refresh margin; provisions the user on first message.
    """
    if not (_USER_POOL_ID and _CLIENT_ID and _PASSWORD_SECRET_ID):
        raise RuntimeError("Cognito env not configured for the router")

    cached = _token_cache.get(actor_id)
    if cached and time.time() < cached[1] - 60:
        return cached[0]

    _ensure_user(actor_id, email)
    try:
        resp = _cognito.admin_initiate_auth(
            UserPoolId=_USER_POOL_ID, ClientId=_CLIENT_ID,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": actor_id, "PASSWORD": _password(actor_id)},
        )
    except ClientError as e:
        # Password drift (salt rotated) — reset once and retry.
        if e.response["Error"]["Code"] not in ("NotAuthorizedException", "UserNotFoundException"):
            raise
        _cognito.admin_set_user_password(
            UserPoolId=_USER_POOL_ID, Username=actor_id,
            Password=_password(actor_id), Permanent=True,
        )
        resp = _cognito.admin_initiate_auth(
            UserPoolId=_USER_POOL_ID, ClientId=_CLIENT_ID,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": actor_id, "PASSWORD": _password(actor_id)},
        )

    token = resp["AuthenticationResult"]["AccessToken"]
    _token_cache[actor_id] = (token, _jwt_exp(token))
    return token
