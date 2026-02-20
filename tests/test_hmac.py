"""
Tests for HMAC Agent Identity — cryptographic session signing.

Validates:
  - Key generation (uniqueness, format)
  - HMAC-SHA256 request signing
  - Signature verification
  - Replay attack prevention (token expiry)
  - Timing-safe comparison
  - Fingerprint generation
  - Integration with SecureProxy
"""

import time
import pytest
from persona.identity import AgentIdentity
from persona.proxy import SecureProxy


# ─────────────────────────────────────────────
#  Key generation
# ─────────────────────────────────────────────

class TestKeyGeneration:

    def test_generates_unique_ids(self):
        id1 = AgentIdentity.generate("agent")
        id2 = AgentIdentity.generate("agent")
        assert id1.agent_id != id2.agent_id

    def test_generates_unique_secrets(self):
        id1 = AgentIdentity.generate("agent")
        id2 = AgentIdentity.generate("agent")
        assert id1.agent_secret != id2.agent_secret

    def test_id_contains_agent_name(self):
        identity = AgentIdentity.generate("sales-bot")
        assert identity.agent_id.startswith("sales-bot_")

    def test_secret_is_256_bit(self):
        identity = AgentIdentity.generate("test")
        # 32 bytes = 64 hex characters
        assert len(identity.agent_secret) == 64

    def test_metadata_persists(self):
        identity = AgentIdentity.generate("test", metadata={"env": "prod", "version": "1.0"})
        assert identity.metadata["env"] == "prod"
        assert identity.metadata["version"] == "1.0"


# ─────────────────────────────────────────────
#  Request signing
# ─────────────────────────────────────────────

class TestRequestSigning:

    def test_sign_returns_string(self):
        identity = AgentIdentity.generate("test")
        token = identity.sign_request("hello world")
        assert isinstance(token, str)

    def test_token_format(self):
        identity = AgentIdentity.generate("test")
        token = identity.sign_request("hello")
        parts = token.split(":", 1)
        assert len(parts) == 2
        # First part should be a timestamp
        float(parts[0])  # Should not raise
        # Second part should be hex
        int(parts[1], 16)  # Should not raise

    def test_same_payload_different_timestamps_different_tokens(self):
        identity = AgentIdentity.generate("test")
        t1 = identity.sign_request("same payload", timestamp=1000.0)
        t2 = identity.sign_request("same payload", timestamp=2000.0)
        assert t1 != t2

    def test_different_payloads_different_tokens(self):
        identity = AgentIdentity.generate("test")
        ts = time.time()
        t1 = identity.sign_request("payload A", timestamp=ts)
        t2 = identity.sign_request("payload B", timestamp=ts)
        assert t1 != t2


# ─────────────────────────────────────────────
#  Signature verification
# ─────────────────────────────────────────────

class TestSignatureVerification:

    def test_valid_signature_verifies(self):
        identity = AgentIdentity.generate("test")
        token = identity.sign_request("hello world")
        assert identity.verify_request("hello world", token) is True

    def test_wrong_payload_fails(self):
        identity = AgentIdentity.generate("test")
        token = identity.sign_request("hello world")
        assert identity.verify_request("wrong payload", token) is False

    def test_tampered_token_fails(self):
        identity = AgentIdentity.generate("test")
        token = identity.sign_request("hello")
        tampered = token[:-4] + "dead"
        assert identity.verify_request("hello", tampered) is False

    def test_different_identity_cannot_verify(self):
        id1 = AgentIdentity.generate("agent1")
        id2 = AgentIdentity.generate("agent2")
        token = id1.sign_request("data")
        assert id2.verify_request("data", token) is False

    def test_empty_token_fails(self):
        identity = AgentIdentity.generate("test")
        assert identity.verify_request("hello", "") is False

    def test_garbage_token_fails(self):
        identity = AgentIdentity.generate("test")
        assert identity.verify_request("hello", "not.a.valid.token") is False

    def test_no_dot_token_fails(self):
        identity = AgentIdentity.generate("test")
        assert identity.verify_request("hello", "nodothere") is False


# ─────────────────────────────────────────────
#  Replay attack prevention
# ─────────────────────────────────────────────

class TestReplayPrevention:

    def test_expired_token_rejected(self):
        identity = AgentIdentity.generate("test")
        # Sign with timestamp 10 minutes ago
        old_ts = time.time() - 600
        token = identity.sign_request("data", timestamp=old_ts)
        assert identity.verify_request("data", token, max_age_seconds=300) is False

    def test_recent_token_accepted(self):
        identity = AgentIdentity.generate("test")
        token = identity.sign_request("data")
        assert identity.verify_request("data", token, max_age_seconds=300) is True


# ─────────────────────────────────────────────
#  Fingerprint
# ─────────────────────────────────────────────

class TestFingerprint:

    def test_fingerprint_is_deterministic(self):
        identity = AgentIdentity.generate("test")
        assert identity.fingerprint() == identity.fingerprint()

    def test_different_identities_different_fingerprints(self):
        id1 = AgentIdentity.generate("test")
        id2 = AgentIdentity.generate("test")
        assert id1.fingerprint() != id2.fingerprint()

    def test_fingerprint_length(self):
        identity = AgentIdentity.generate("test")
        assert len(identity.fingerprint()) == 16

    def test_public_dict_has_no_secret(self):
        identity = AgentIdentity.generate("test")
        public = identity.to_public_dict()
        assert "agent_secret" not in public
        assert "agent_id" in public
        assert "fingerprint" in public


# ─────────────────────────────────────────────
#  SecureProxy integration
# ─────────────────────────────────────────────

class TestProxyHMACIntegration:

    def test_proxy_with_identity_can_sign(self):
        class EchoAgent:
            def run(self, p): return f"Echo: {p}"

        identity = AgentIdentity.generate("test-agent")
        proxy = SecureProxy(EchoAgent(), agent_identity=identity)

        token = proxy.sign_request("hello")
        assert token is not None
        assert proxy.verify_request("hello", token) is True

    def test_proxy_without_identity_returns_none(self):
        class EchoAgent:
            def run(self, p): return f"Echo: {p}"

        proxy = SecureProxy(EchoAgent())
        assert proxy.sign_request("hello") is None
        assert proxy.verify_request("hello", "fake") is False
