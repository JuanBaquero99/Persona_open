"""
HMAC-based Agent Identity Verification.

Each SecureProxy instance can bind to a cryptographic identity.
Every session/request is signed with HMAC-SHA256.
A fake agent (or a clone deployed by an attacker) cannot produce
valid signatures without the secret key.

This is the crypto layer that complements AgentIdentityRule
(text-based impersonation detection).

Reference: OpenClaw incident (Feb 13, 2026)
  Attackers cloned the agent's interface in ~10 seconds.
  A crypto identity would have let clients verify authenticity.
"""

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any


@dataclass
class AgentIdentity:
    """
    Cryptographic identity for an agent instance.

    Usage:
        identity = AgentIdentity.generate("my-sales-agent")
        token = identity.sign_request("What are today's sales?")
        assert identity.verify_request("What are today's sales?", token)
    """
    agent_id: str
    agent_secret: str
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def generate(cls, agent_name: str, metadata: Optional[Dict[str, Any]] = None) -> "AgentIdentity":
        """
        Generate a new cryptographic identity for an agent.

        Args:
            agent_name: Human-readable name (used as prefix in agent_id)
            metadata: Optional metadata (owner, version, environment, etc.)

        Returns:
            AgentIdentity with a unique ID and 256-bit secret
        """
        unique_suffix = secrets.token_hex(16)
        agent_id = f"{agent_name}_{unique_suffix}"
        agent_secret = secrets.token_hex(32)  # 256-bit secret

        return cls(
            agent_id=agent_id,
            agent_secret=agent_secret,
            metadata=metadata or {},
        )

    def sign_request(self, payload: str, timestamp: Optional[float] = None) -> str:
        """
        Sign a request payload with HMAC-SHA256.

        The signature includes a timestamp to prevent replay attacks.
        Token format: "{timestamp}:{hex_signature}"

        Args:
            payload: The request text to sign
            timestamp: Unix timestamp (auto-generated if not provided)

        Returns:
            Signed token string
        """
        ts = timestamp or time.time()
        message = f"{self.agent_id}:{ts}:{payload}"
        signature = hmac.new(
            self.agent_secret.encode(),
            message.encode(),
            hashlib.sha256,
        ).hexdigest()

        return f"{ts}:{signature}"

    def verify_request(
        self,
        payload: str,
        token: str,
        max_age_seconds: int = 300,
    ) -> bool:
        """
        Verify a signed request token.

        Checks:
        1. Signature is valid (HMAC matches)
        2. Token is not expired (replay attack prevention)

        Args:
            payload: The original request text
            token: The signed token to verify
            max_age_seconds: Maximum age of token in seconds (default: 5 min)

        Returns:
            True if token is valid and not expired
        """
        try:
            parts = token.split(":", 1)
            if len(parts) != 2:
                return False

            ts_str, provided_signature = parts
            ts = float(ts_str)

            # Check token age (replay attack prevention)
            if time.time() - ts > max_age_seconds:
                return False

            # Recompute expected signature
            message = f"{self.agent_id}:{ts}:{payload}"
            expected_signature = hmac.new(
                self.agent_secret.encode(),
                message.encode(),
                hashlib.sha256,
            ).hexdigest()

            # Constant-time comparison to prevent timing attacks
            return hmac.compare_digest(provided_signature, expected_signature)

        except (ValueError, TypeError):
            return False

    def fingerprint(self) -> str:
        """
        Public fingerprint of this identity (safe to share).
        Derived from agent_id + secret, but does NOT expose the secret.
        """
        return hashlib.sha256(
            f"{self.agent_id}:{self.agent_secret}".encode()
        ).hexdigest()[:16]

    def to_public_dict(self) -> Dict[str, Any]:
        """Export public identity info (no secret)."""
        return {
            "agent_id": self.agent_id,
            "fingerprint": self.fingerprint(),
            "created_at": self.created_at,
            "metadata": self.metadata,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Export full identity (includes secret — handle with care)."""
        return asdict(self)
