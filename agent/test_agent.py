"""Unit tests for agent logic that doesn't require live AWS or the (ARM64) deps.

Run: cd agent && uv run --with pytest python -m pytest test_agent.py -v

Identity is the security-critical part and now needs real RSA signing, so it lives in
test_identity.py; the MCP transport lives in test_transport.py. This suite stays
dependency-light and only covers logic with no external requirements.
"""

import hashlib
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))


# ------------------------------- agent_core session id ----------------------

def test_session_id_deterministic_per_user():
    """Load just the _session_id_for function without importing the heavy deps."""
    src = open(os.path.join(os.path.dirname(__file__), "agent_core.py"), encoding="utf-8").read()
    ns = {"hashlib": hashlib}
    # exec only the function definition we care about
    start = src.index("def _session_id_for")
    end = src.index("\n\ndef ", start)
    exec(src[start:end], ns)
    sid = ns["_session_id_for"]
    assert sid("lark:ou_abc") == sid("lark:ou_abc")          # stable
    assert sid("lark:ou_abc") != sid("lark:ou_xyz")          # per-user
    assert sid("lark:ou_abc").startswith("sess-")


def test_agent_never_mints_a_token():
    """Regression guard: the container must not be able to assert an identity.

    The impersonation hole this repo closed was an unsigned actorId feeding a Cognito
    admin auth call inside the container; these APIs must never come back here.
    """
    agent_dir = os.path.dirname(__file__)
    forbidden = ("admin_initiate_auth", "admin_create_user", "admin_set_user_password",
                 "AdminInitiateAuth", "_derive_password")
    for name in ("identity.py", "agent_core.py", "server.py"):
        src = open(os.path.join(agent_dir, name), encoding="utf-8").read()
        for token in forbidden:
            assert token not in src, f"{name} must not mint credentials ({token})"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
