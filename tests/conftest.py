"""
Shared fixtures and mock agents for testing.

Why mock agents? We don't want to spend real API tokens during tests
and we need predictable, controlled responses to simulate specific attacks.
"""

import pytest
from persona import SecureProxy


class MockAgent:
    """
    Simulates an AI agent with configurable responses.
    Used to test proxy behavior without calling real LLM APIs.
    """

    def __init__(self, response: str):
        """
        Args:
            response: What the agent will always return when run()
        """
        self.response = response
        self.call_count = 0

    def run(self, prompt: str) -> str:
        self.call_count += 1
        return self.response


class VulnerableAgentSimulator:
    """
    Simulates a VULNERABLE agent that leaks secrets.
    Used to verify that the proxy blocks real-world attack scenarios.

    These represent agents like OpenClaw before the Feb 13 incident.
    """

    def run(self, prompt: str) -> str:
        """
        Simulates an agent that leaks credentials in its response
        depending on what the prompt asks for.
        """
        prompt_lower = prompt.lower()

        # Simulates: agent leaking OpenAI key
        if "api key" in prompt_lower or "openai" in prompt_lower:
            return "Sure! Your OpenAI key is sk-proj-abc123XYZ456abc123XYZ456abc123XYZ456abc123XYZ456"

        # Simulates: agent leaking GitHub token
        if "github" in prompt_lower or "token" in prompt_lower:
            return "Found your GitHub token: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890"

        # Simulates: agent leaking AWS credentials
        if "aws" in prompt_lower or "amazon" in prompt_lower:
            return "AWS Access Key ID: AKIAIOSFODNN7EXAMPLE"

        # Simulates: agent leaking DB connection string
        if "database" in prompt_lower or "db" in prompt_lower:
            return "Database URL: postgres://admin:super_secret_pass@prod.db.company.com:5432/users"

        # Simulates: agent leaking JWT token
        if "session" in prompt_lower or "jwt" in prompt_lower:
            return "Session token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

        # Normal response
        return "Task completed successfully."


# ─── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def safe_agent():
    """An agent that returns a clean, safe response."""
    return MockAgent("Task completed successfully. No sensitive data here.")


@pytest.fixture
def credential_leaking_agent():
    """An agent that always leaks an OpenAI API key in its response."""
    return MockAgent(
        "Done! Used key sk-proj-abc123XYZ456abc123XYZ456abc123XYZ456abc123XYZ456 to complete."
    )


@pytest.fixture
def vulnerable_agent():
    """A realistic vulnerable agent simulator."""
    return VulnerableAgentSimulator()


@pytest.fixture
def secure_proxy(safe_agent):
    """A SecureProxy with all rules enabled wrapping a safe agent."""
    return SecureProxy(
        agent=safe_agent,
        rules=["block_credentials", "tool_whitelist", "rate_limit"],
        allowed_tools=["search_web", "read_file", "send_email"],
    )


@pytest.fixture
def proxy_over_vulnerable_agent(vulnerable_agent):
    """A SecureProxy protecting a vulnerable agent - key fixture for attack tests."""
    return SecureProxy(
        agent=vulnerable_agent,
        rules=["block_credentials", "tool_whitelist", "rate_limit"],
        allowed_tools=["search_web", "read_file"],
    )
