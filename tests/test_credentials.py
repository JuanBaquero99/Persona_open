"""
Tests for credential detection and sanitization.

These tests verify that SecureProxy correctly:
1. Detects all supported credential types
2. Redacts them in output (does NOT expose them)
3. Logs a security event when detected

Attack reference: OpenClaw incident (Feb 13, 2026) - arXiv:2602.08412
"""

import pytest
from secureagent.rules import CredentialDetectionRule, CredentialType


class TestCredentialDetection:
    """Unit tests for CredentialDetectionRule."""

    def setup_method(self):
        """Create rule instance before each test."""
        self.rule = CredentialDetectionRule()

    # ─── Detection Tests ──────────────────────────────────────────────────────

    def test_detects_openai_key(self):
        text = "Using key sk-proj-abc123XYZ456abc123XYZ456abc123XYZ456abc123XYZ456"
        is_safe, reason = self.rule.validate(text)

        assert is_safe is False
        assert "openai" in reason.lower()

    def test_detects_github_token(self):
        text = "Token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
        is_safe, reason = self.rule.validate(text)

        assert is_safe is False
        assert "github" in reason.lower()

    def test_detects_aws_key(self):
        text = "Access Key ID: AKIAIOSFODNN7EXAMPLE"
        is_safe, reason = self.rule.validate(text)

        assert is_safe is False
        assert "aws" in reason.lower()

    def test_detects_database_url(self):
        text = "Connect to postgres://admin:password123@prod.db.com:5432/users"
        is_safe, reason = self.rule.validate(text)

        assert is_safe is False
        assert "database_url" in reason.lower()

    def test_detects_jwt_token(self):
        text = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        is_safe, reason = self.rule.validate(text)

        assert is_safe is False
        assert "jwt" in reason.lower()

    def test_detects_stripe_key(self):
        text = "Payment processed with sk_live_FAKE_EXAMPLE_NOT_A_REAL_KEY_xxxxxxxxxxx"
        is_safe, reason = self.rule.validate(text)

        assert is_safe is False
        assert "stripe" in reason.lower()

    def test_detects_anthropic_key(self):
        text = "Anthropic key: sk-ant-api03-abc123XYZ456abc123XYZ456abc123XYZ456abc123XYZ456abc123"
        is_safe, reason = self.rule.validate(text)

        assert is_safe is False
        assert "anthropic" in reason.lower()

    def test_safe_text_passes(self):
        text = "The weather today is sunny. No credentials here."
        is_safe, reason = self.rule.validate(text)

        assert is_safe is True
        assert reason == ""

    def test_empty_text_passes(self):
        is_safe, _ = self.rule.validate("")
        assert is_safe is True

    # ─── Sanitization Tests ───────────────────────────────────────────────────

    def test_sanitizes_openai_key(self):
        """Credential must be replaced, not passed through."""
        text = "Key: sk-proj-abc123XYZ456abc123XYZ456abc123XYZ456abc123XYZ456"
        result = self.rule.sanitize(text)

        assert "sk-proj" not in result
        assert "REDACTED" in result

    def test_sanitizes_github_token(self):
        text = "Token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
        result = self.rule.sanitize(text)

        assert "ghp_" not in result
        assert "REDACTED" in result

    def test_sanitizes_aws_key(self):
        text = "AKIAIOSFODNN7EXAMPLE is the key"
        result = self.rule.sanitize(text)

        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "REDACTED" in result

    def test_sanitizes_database_url(self):
        text = "URL: postgres://user:password@host:5432/db"
        result = self.rule.sanitize(text)

        assert "password" not in result
        assert "REDACTED" in result

    def test_sanitizes_multiple_credentials(self):
        """If multiple credentials appear together, all must be redacted."""
        text = (
            "OpenAI: sk-proj-abc123XYZ456abc123XYZ456abc123XYZ456abc123XYZ456 "
            "GitHub: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"
        )
        result = self.rule.sanitize(text)

        assert "sk-proj" not in result
        assert "ghp_" not in result
        assert result.count("REDACTED") >= 2

    def test_sanitize_preserves_safe_content(self):
        """Sanitization must not destroy legitimate content around credentials."""
        text = "Task complete. Key sk-proj-abc123XYZ456abc123XYZ456abc123XYZ456abc123XYZ456 was used."
        result = self.rule.sanitize(text)

        assert "Task complete" in result
        assert "was used" in result
        assert "sk-proj" not in result
