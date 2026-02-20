"""
Tests for tool whitelist and unauthorized tool execution.

These tests verify that SecureProxy correctly:
1. Blocks dangerous tools (os.system, subprocess, eval, exec)
2. Enforces custom whitelist when configured
3. Allows whitelisted tools to run normally

Attack reference: MalTool attacks (arXiv:2602.12194)
                  MCP misleading tool descriptions (arXiv:2602.03580)
"""

import pytest
from persona.rules import ToolWhitelistRule


class TestToolWhitelist:
    """Unit tests for ToolWhitelistRule."""

    # ─── Blocked tools (always blocked regardless of whitelist) ───────────────

    def test_blocks_os_system(self):
        """os.system is always dangerous - lets attacker run shell commands."""
        rule = ToolWhitelistRule(allowed_tools=[])
        is_safe, reason = rule.validate("os.system")

        assert is_safe is False
        assert "os.system" in reason

    def test_blocks_subprocess(self):
        """subprocess.run can execute arbitrary system commands."""
        rule = ToolWhitelistRule(allowed_tools=[])
        is_safe, reason = rule.validate("subprocess.run")

        assert is_safe is False

    def test_blocks_subprocess_popen(self):
        rule = ToolWhitelistRule(allowed_tools=[])
        is_safe, _ = rule.validate("subprocess.Popen")

        assert is_safe is False

    def test_blocks_eval(self):
        """eval executes arbitrary Python code - critical risk."""
        rule = ToolWhitelistRule(allowed_tools=[])
        is_safe, _ = rule.validate("eval")

        assert is_safe is False

    def test_blocks_exec(self):
        rule = ToolWhitelistRule(allowed_tools=[])
        is_safe, _ = rule.validate("exec")

        assert is_safe is False

    def test_blocks_import(self):
        """__import__ allows dynamic module imports - code injection risk."""
        rule = ToolWhitelistRule(allowed_tools=[])
        is_safe, _ = rule.validate("__import__")

        assert is_safe is False

    # ─── Whitelist Enforcement ────────────────────────────────────────────────

    def test_allows_whitelisted_tool(self):
        """Tools explicitly in the whitelist should be allowed."""
        rule = ToolWhitelistRule(allowed_tools=["search_web", "read_file", "send_email"])
        is_safe, _ = rule.validate("search_web")

        assert is_safe is True

    def test_blocks_tool_not_in_whitelist(self):
        """Tools NOT in whitelist must be blocked when whitelist is defined."""
        rule = ToolWhitelistRule(allowed_tools=["search_web", "read_file"])
        is_safe, reason = rule.validate("delete_database")

        assert is_safe is False
        assert "delete_database" in reason

    def test_empty_whitelist_allows_all_non_blocked(self):
        """
        When no whitelist is defined, allow everything except blocked tools.
        This is the permissive default for backward compatibility.
        """
        rule = ToolWhitelistRule(allowed_tools=[])
        is_safe, _ = rule.validate("my_custom_tool")

        assert is_safe is True

    def test_whitelist_with_multiple_tools(self):
        """All whitelisted tools should pass."""
        allowed = ["search_web", "read_file", "send_email", "calendar_read"]
        rule = ToolWhitelistRule(allowed_tools=allowed)

        for tool in allowed:
            is_safe, _ = rule.validate(tool)
            assert is_safe is True, f"Tool {tool} should be allowed"

    def test_blocked_tool_overrides_whitelist(self):
        """
        Even if someone adds 'eval' to whitelist, it must still be blocked.
        Dangerous tools are always blocked regardless of configuration.
        """
        rule = ToolWhitelistRule(allowed_tools=["search_web", "eval"])
        is_safe, _ = rule.validate("eval")

        assert is_safe is False

    # ─── Attack Scenarios ─────────────────────────────────────────────────────

    def test_attack_tool_hijacking(self):
        """
        Attack scenario: MCP tool claims to be 'search_web' but
        internally calls subprocess.run to exfiltrate data.

        The TOOL NAME is what we check - attacker can't rename subprocess.run.
        """
        rule = ToolWhitelistRule(allowed_tools=["search_web"])
        
        # Attacker's tool is named to look innocent but IS subprocess
        is_safe, _ = rule.validate("subprocess.run")

        assert is_safe is False

    def test_attack_indirect_command_execution(self):
        """
        Attack scenario: Prompt injection causes agent to call
        os.system with attacker's payload.
        """
        rule = ToolWhitelistRule(allowed_tools=["read_file", "search_web"])
        
        dangerous_tools = ["os.system", "subprocess.run", "eval", "exec"]
        for tool in dangerous_tools:
            is_safe, _ = rule.validate(tool)
            assert is_safe is False, f"Dangerous tool {tool} must always be blocked"
