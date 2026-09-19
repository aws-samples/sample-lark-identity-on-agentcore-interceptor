"""Tests for the agent's identity root of trust.

The Runtime's inbound auth is SigV4, so nothing upstream verifies the caller-supplied
token — every rejection path here is load-bearing. Tokens are signed with a locally
generated RSA key and the JWKS client is pointed at it, so no AWS calls are made.

Run: uv run --with-requirements agent/requirements.txt --with pytest \
       python -m pytest agent/test_identity.py -q
"""

from __future__ import annotations

import importlib
import os
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

POOL = "us-west-2_TESTPOOL"
CLIENT = "test-client-id"
REGION = "us-west-2"
ISSUER = f"https://cognito-idp.{REGION}.amazonaws.com/{POOL}"
KID = "test-key-1"


@pytest.fixture(scope="module")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def identity(monkeypatch, signing_key):
    """Import the module with test env, then stub JWKS lookup with the local key."""
    monkeypatch.setenv("AWS_REGION", REGION)
    monkeypatch.setenv("COGNITO_USER_POOL_ID", POOL)
    monkeypatch.setenv("COGNITO_CLIENT_ID", CLIENT)
    import identity as mod
    mod = importlib.reload(mod)

    class StubKey:
        key = signing_key.public_key()

    class StubClient:
        def get_signing_key_from_jwt(self, token):
            return StubKey()

    monkeypatch.setattr(mod, "_jwks_client", StubClient())
    return mod


def make_token(signing_key, **overrides) -> str:
    claims = {
        "iss": ISSUER,
        "sub": "11112222-3333-4444-5555-666677778888",
        "username": "lark:ou_abc123",
        "client_id": CLIENT,
        "token_use": "access",
        "exp": int(time.time()) + 600,
        "iat": int(time.time()),
    }
    claims.update(overrides)
    for k in [k for k, v in overrides.items() if v is None]:
        claims.pop(k, None)
    return jwt.encode(claims, signing_key, algorithm="RS256", headers={"kid": KID})


# ------------------------------- accepted ------------------------------------

def test_valid_access_token_yields_actor_id(identity, signing_key):
    actor_id, claims = identity.verify_access_token(make_token(signing_key))
    assert actor_id == "lark:ou_abc123"
    assert claims["client_id"] == CLIENT


def test_bearer_prefix_is_tolerated(identity, signing_key):
    actor_id, _ = identity.verify_access_token("Bearer " + make_token(signing_key))
    assert actor_id == "lark:ou_abc123"


# ------------------------------- rejected ------------------------------------

def test_missing_token_is_rejected(identity):
    with pytest.raises(identity.IdentityError):
        identity.verify_access_token("")


def test_id_token_is_rejected(identity, signing_key):
    """The Gateway matches client_id, which ID tokens do not carry."""
    token = make_token(signing_key, token_use="id")
    with pytest.raises(identity.IdentityError, match="access token"):
        identity.verify_access_token(token)


def test_token_for_another_client_is_rejected(identity, signing_key):
    token = make_token(signing_key, client_id="someone-elses-client")
    with pytest.raises(identity.IdentityError, match="different app client"):
        identity.verify_access_token(token)


def test_expired_token_is_rejected(identity, signing_key):
    token = make_token(signing_key, exp=int(time.time()) - 10)
    with pytest.raises(identity.IdentityError, match="rejected"):
        identity.verify_access_token(token)


def test_wrong_issuer_is_rejected(identity, signing_key):
    token = make_token(signing_key, iss="https://evil.example.com/pool")
    with pytest.raises(identity.IdentityError, match="rejected"):
        identity.verify_access_token(token)


def test_token_signed_by_another_key_is_rejected(identity):
    """A correctly shaped token is worthless without our pool's signature."""
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = make_token(attacker)
    with pytest.raises(identity.IdentityError, match="rejected"):
        identity.verify_access_token(token)


def test_unsigned_token_is_rejected(identity, signing_key):
    """alg=none must never be accepted — this is the old unsigned-actorId hole."""
    token = jwt.encode({"username": "lark:ou_victim", "token_use": "access",
                        "client_id": CLIENT, "iss": ISSUER, "sub": "x",
                        "exp": int(time.time()) + 600},
                       key="", algorithm="none")
    with pytest.raises(identity.IdentityError):
        identity.verify_access_token(token)


def test_non_lark_username_is_rejected(identity, signing_key):
    token = make_token(signing_key, username="someone-else")
    with pytest.raises(identity.IdentityError, match="username claim"):
        identity.verify_access_token(token)


# ------------------------------- jwt_exp -------------------------------------

def test_jwt_exp_reads_expiry_without_verifying(identity, signing_key):
    exp = int(time.time()) + 1234
    assert identity.jwt_exp(make_token(signing_key, exp=exp)) == float(exp)


def test_jwt_exp_returns_zero_on_garbage(identity):
    assert identity.jwt_exp("not-a-jwt") == 0.0
