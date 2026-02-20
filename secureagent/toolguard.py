"""
ToolGuard — Tool-level firewall for AI agents.

Intercepts and validates every tool call an agent makes.
This is NOT prompt-based — it validates the STRUCTURE of tool calls,
like a WAF validates HTTP requests or a SQL firewall validates queries.

Attack vectors covered:
    - Path traversal (read_file("../../etc/passwd"))
    - Argument injection (run_sql("'; DROP TABLE--"))
    - Privilege escalation (tool requires admin, agent is user)
    - Resource abuse (calling a tool 1000 times)
    - Sensitive resource access (env vars, SSH keys, credentials)
    - Destructive operations (delete, drop, rm -rf)

Example:
    guard = ToolGuard()
    guard.register_tool("read_file", {
        "allowed_paths": ["./project/**"],
        "blocked_paths": ["/etc/**", "~/.ssh/**"],
        "permission": "read",
    })

    result = guard.validate_call("read_file", {"path": "/etc/shadow"})
    # ToolCallVerdict(allowed=False, reason="Path traversal: /etc/shadow",
    #                 violation_type="path_traversal", severity="critical")
"""

import re
import os
import time
import fnmatch
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum


# ═══════════════════════════════════════════════════════════
#  DATA TYPES
# ═══════════════════════════════════════════════════════════

class ViolationType(str, Enum):
    """Types of tool-level security violations."""
    PATH_TRAVERSAL = "path_traversal"
    ARGUMENT_INJECTION = "argument_injection"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    RESOURCE_ABUSE = "resource_abuse"
    SENSITIVE_ACCESS = "sensitive_access"
    DESTRUCTIVE_OP = "destructive_operation"
    BLOCKED_TOOL = "blocked_tool"
    UNKNOWN_TOOL = "unknown_tool"


class Permission(str, Enum):
    """Permission levels for tool operations."""
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DELETE = "delete"
    ADMIN = "admin"
    NETWORK = "network"


# Permission hierarchy — each level includes all below it
PERMISSION_HIERARCHY = {
    Permission.READ: 0,
    Permission.WRITE: 1,
    Permission.EXECUTE: 2,
    Permission.DELETE: 3,
    Permission.NETWORK: 2,
    Permission.ADMIN: 4,
}


@dataclass
class ToolCallVerdict:
    """Result of validating a tool call."""
    allowed: bool
    tool_name: str
    reason: str = ""
    violation_type: Optional[ViolationType] = None
    severity: str = "info"  # info, warning, high, critical
    matched_rule: str = ""
    args_inspected: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "tool_name": self.tool_name,
            "reason": self.reason,
            "violation_type": self.violation_type.value if self.violation_type else None,
            "severity": self.severity,
            "matched_rule": self.matched_rule,
        }


@dataclass
class ToolPolicy:
    """Security policy for a single tool."""
    name: str
    permission: Permission = Permission.READ
    description: str = ""

    # Path-based restrictions (for file/directory tools)
    allowed_paths: List[str] = field(default_factory=list)
    blocked_paths: List[str] = field(default_factory=list)

    # Argument restrictions
    blocked_args: Dict[str, List[str]] = field(default_factory=dict)
    required_args: List[str] = field(default_factory=list)
    max_arg_length: int = 10000

    # Rate limiting per tool
    max_calls_per_minute: int = 60
    max_calls_per_session: int = 500

    # Flags
    allow_external_urls: bool = False
    allow_shell_commands: bool = False
    is_destructive: bool = False
    requires_confirmation: bool = False


# ═══════════════════════════════════════════════════════════
#  DETECTION PATTERNS (structural, not semantic)
# ═══════════════════════════════════════════════════════════

# Path traversal patterns — like directory traversal in web apps
PATH_TRAVERSAL_PATTERNS = [
    r"\.\./",                    # ../
    r"\.\.\%2[fF]",             # URL-encoded ../
    r"\.\.\%5[cC]",             # URL-encoded ..\
    r"\.\.\\",                  # ..\  (Windows)
    r"(?:^|/)\.\.(?:$|/|\\)",   # standalone ..
    r"%00",                     # null byte injection
    r"\x00",                    # null byte literal
]

# Sensitive file paths — structural, no semantics needed
SENSITIVE_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "/etc/ssh/*", "/root/*",
    "~/.ssh/*", "~/.gnupg/*", "~/.aws/*", "~/.config/gcloud/*",
    "**/.env", "**/.env.*", "**/secrets.*", "**/*secret*",
    "**/credentials", "**/credentials.*",
    "**/*.pem", "**/*.key", "**/*.crt", "**/*.p12", "**/*.pfx",
    "**/id_rsa", "**/id_ed25519", "**/id_dsa",
    "**/token", "**/token.*",
    "C:/Windows/System32/**", "C:/Windows/SAM",
    "**/web.config", "**/wp-config.php",
    "**/.git/config", "**/.gitconfig",
    "**/proc/self/**", "/proc/*/environ",
    "/dev/mem", "/dev/kmem",
]

# SQL injection patterns — same concept as web, but in tool args
SQL_INJECTION_PATTERNS = [
    r"(?:--|#|/\*).*$",                         # SQL comments
    r";\s*(?:DROP|DELETE|TRUNCATE|ALTER|INSERT)",  # destructive chained queries
    r"(?:UNION\s+(?:ALL\s+)?SELECT)",           # UNION injection
    r"'\s*OR\s+['\d].*=.*['\d]",               # ' OR '1'='1
    r"(?:EXEC|EXECUTE)\s*\(",                   # stored procedure injection
    r"(?:xp_cmdshell|sp_executesql)",          # SQL Server RCE
    r"INTO\s+(?:OUTFILE|DUMPFILE)",            # file write via SQL
    r"LOAD_FILE\s*\(",                          # file read via SQL
    r"BENCHMARK\s*\(",                          # timing attack
    r"(?:SLEEP|WAITFOR\s+DELAY)\s*\(",         # time-based blind
]

# Command injection patterns — when tools accept shell commands
COMMAND_INJECTION_PATTERNS = [
    r";\s*\w",                     # command chaining with ;
    r"\|\s*\w",                    # pipe injection
    r"\$\(",                       # command substitution $(...)
    r"`[^`]+`",                    # backtick command substitution
    r"&&\s*\w",                    # && chaining
    r"\|\|\s*\w",                  # || chaining
    r">\s*/",                      # redirect to absolute path
    r">>\s*/",                     # append to absolute path
    r"\b(?:curl|wget|nc|ncat)\s",  # network tools
    r"\brm\s+(?:-rf?|--recursive)", # destructive rm
    r"\bchmod\s+(?:777|666|a\+)",  # dangerous permission change
    r"\bchown\s",                  # ownership change
    r"\bsudo\s",                   # privilege escalation
    r"\bdd\s+.*of=/",             # dd to device
    r"\bmkfs\b",                   # filesystem format
    r"\b(?:python|node|ruby|perl|bash|sh|cmd|powershell)\s+-[ec]\s", # interpreter exec
]

# Destructive operation indicators
DESTRUCTIVE_INDICATORS = [
    r"\bDROP\s+(?:TABLE|DATABASE|SCHEMA|INDEX)\b",
    r"\bDELETE\s+FROM\b.*(?:WHERE\s+1\s*=\s*1|$)",
    r"\bTRUNCATE\s",
    r"\bFORMAT\s+[A-Z]:",
    r"\brm\s+-rf?\s+/",
    r"\bdel\s+/[sq]\s",
    r"\bshutdown\b",
    r"\breboot\b",
    r"\bkill\s+-9\s+(?:-1|1)\b",
    r"\b(?:DROP|REVOKE)\s+ALL\b",
]


# ═══════════════════════════════════════════════════════════
#  TOOL GUARD ENGINE
# ═══════════════════════════════════════════════════════════

class ToolGuard:
    """
    Tool-level firewall for AI agents.

    Validates every tool call against structural rules:
    - Path traversal detection (like directory traversal in web apps)
    - SQL injection in query arguments
    - Command injection in shell arguments
    - Permission level enforcement
    - Rate limiting per tool
    - Sensitive file access blocking
    - Destructive operation detection

    This is NOT semantic analysis — it's structural validation,
    like a WAF or SQL firewall.
    """

    def __init__(
        self,
        agent_permission: Permission = Permission.READ,
        sandbox_root: Optional[str] = None,
        strict_mode: bool = False,
    ):
        """
        Args:
            agent_permission: Maximum permission level for this agent
            sandbox_root: Root directory the agent can access (None = no restriction)
            strict_mode: If True, block ALL unregistered tools
        """
        self.agent_permission = agent_permission
        self.sandbox_root = os.path.abspath(sandbox_root) if sandbox_root else None
        self.strict_mode = strict_mode
        self.policies: Dict[str, ToolPolicy] = {}
        self.blocked_tools: Set[str] = set()
        self._call_counts: Dict[str, List[float]] = {}  # tool -> [timestamps]
        self._session_counts: Dict[str, int] = {}

        # Compile patterns once
        self._path_patterns = [re.compile(p) for p in PATH_TRAVERSAL_PATTERNS]
        self._sql_patterns = [re.compile(p, re.IGNORECASE) for p in SQL_INJECTION_PATTERNS]
        self._cmd_patterns = [re.compile(p, re.IGNORECASE) for p in COMMAND_INJECTION_PATTERNS]
        self._destructive_patterns = [re.compile(p, re.IGNORECASE) for p in DESTRUCTIVE_INDICATORS]

    # ── Policy Registration ──

    def register_tool(self, name: str, policy: Optional[Dict] = None) -> None:
        """Register a tool with its security policy."""
        if policy is None:
            policy = {}
        self.policies[name] = ToolPolicy(name=name, **policy)

    def block_tool(self, name: str) -> None:
        """Explicitly block a tool."""
        self.blocked_tools.add(name)

    def register_tools(self, tools: Dict[str, Dict]) -> None:
        """Register multiple tools at once."""
        for name, policy in tools.items():
            self.register_tool(name, policy)

    # ── Core Validation ──

    def validate_call(self, tool_name: str, args: Dict[str, Any] = None) -> ToolCallVerdict:
        """
        Validate a tool call before execution.

        This is the main entry point. Call this BEFORE letting the agent
        execute any tool.

        Args:
            tool_name: Name of the tool being called
            args: Arguments the agent wants to pass

        Returns:
            ToolCallVerdict with allowed/blocked decision and reason
        """
        args = args or {}

        # 1. Is the tool explicitly blocked?
        if tool_name in self.blocked_tools:
            return ToolCallVerdict(
                allowed=False, tool_name=tool_name,
                reason=f"Tool '{tool_name}' is explicitly blocked",
                violation_type=ViolationType.BLOCKED_TOOL,
                severity="critical",
                matched_rule="blocked_tools",
            )

        # 2. Is the tool registered? (strict mode blocks unknown tools)
        policy = self.policies.get(tool_name)
        if not policy and self.strict_mode:
            return ToolCallVerdict(
                allowed=False, tool_name=tool_name,
                reason=f"Unknown tool '{tool_name}' (strict mode)",
                violation_type=ViolationType.UNKNOWN_TOOL,
                severity="high",
                matched_rule="strict_mode",
            )

        # 3. Permission check
        if policy:
            verdict = self._check_permission(tool_name, policy)
            if not verdict.allowed:
                return verdict

        # 4. Rate limit per tool
        if policy:
            verdict = self._check_tool_rate(tool_name, policy)
            if not verdict.allowed:
                return verdict

        # 5. Validate arguments
        for arg_name, arg_value in args.items():
            if not isinstance(arg_value, str):
                arg_value = str(arg_value)

            # Arg length check
            if policy and len(arg_value) > policy.max_arg_length:
                return ToolCallVerdict(
                    allowed=False, tool_name=tool_name,
                    reason=f"Argument '{arg_name}' exceeds max length ({len(arg_value)} > {policy.max_arg_length})",
                    violation_type=ViolationType.ARGUMENT_INJECTION,
                    severity="warning",
                    matched_rule="max_arg_length",
                    args_inspected={arg_name: arg_value[:100]},
                )

            # Blocked arg values
            if policy and arg_name in policy.blocked_args:
                for blocked in policy.blocked_args[arg_name]:
                    if blocked.lower() in arg_value.lower():
                        return ToolCallVerdict(
                            allowed=False, tool_name=tool_name,
                            reason=f"Blocked value in argument '{arg_name}': '{blocked}'",
                            violation_type=ViolationType.ARGUMENT_INJECTION,
                            severity="high",
                            matched_rule="blocked_args",
                            args_inspected={arg_name: arg_value[:100]},
                        )

            # Path traversal detection
            if arg_name in ("path", "file", "filepath", "filename", "directory", "dir", "folder", "src", "dst", "destination", "source", "target"):
                verdict = self._check_path(tool_name, arg_name, arg_value, policy)
                if not verdict.allowed:
                    return verdict

            # SQL injection detection
            if arg_name in ("query", "sql", "statement", "command", "expression", "filter", "where", "condition"):
                verdict = self._check_sql_injection(tool_name, arg_name, arg_value)
                if not verdict.allowed:
                    return verdict

            # Command injection detection
            if arg_name in ("command", "cmd", "shell", "script", "exec", "code", "bash"):
                if policy and not policy.allow_shell_commands:
                    verdict = self._check_command_injection(tool_name, arg_name, arg_value)
                    if not verdict.allowed:
                        return verdict

            # URL check for non-network tools
            if policy and not policy.allow_external_urls:
                if re.search(r"https?://", arg_value) and arg_name not in ("url", "endpoint", "href", "link"):
                    return ToolCallVerdict(
                        allowed=False, tool_name=tool_name,
                        reason=f"Unexpected URL in argument '{arg_name}' (tool does not allow external URLs)",
                        violation_type=ViolationType.ARGUMENT_INJECTION,
                        severity="high",
                        matched_rule="no_external_urls",
                        args_inspected={arg_name: arg_value[:100]},
                    )

        # 6. Destructive operation check
        all_args_text = " ".join(str(v) for v in args.values())
        verdict = self._check_destructive(tool_name, all_args_text, policy)
        if not verdict.allowed:
            return verdict

        # 7. Required args check
        if policy and policy.required_args:
            missing = [a for a in policy.required_args if a not in args]
            if missing:
                return ToolCallVerdict(
                    allowed=False, tool_name=tool_name,
                    reason=f"Missing required arguments: {missing}",
                    violation_type=ViolationType.ARGUMENT_INJECTION,
                    severity="warning",
                    matched_rule="required_args",
                )

        # Record the call
        self._record_call(tool_name)

        return ToolCallVerdict(
            allowed=True, tool_name=tool_name,
            reason="Tool call validated",
            severity="info",
        )

    # ── Internal Checks ──

    def _check_permission(self, tool_name: str, policy: ToolPolicy) -> ToolCallVerdict:
        """Check if agent has sufficient permission for this tool."""
        # Resolve permission — may be string or enum
        tool_perm = policy.permission if isinstance(policy.permission, Permission) else Permission(policy.permission)
        agent_perm = self.agent_permission if isinstance(self.agent_permission, Permission) else Permission(self.agent_permission)

        required = PERMISSION_HIERARCHY.get(tool_perm, 0)
        have = PERMISSION_HIERARCHY.get(agent_perm, 0)

        if required > have:
            return ToolCallVerdict(
                allowed=False, tool_name=tool_name,
                reason=f"Privilege escalation: tool requires '{tool_perm.value}', agent has '{agent_perm.value}'",
                violation_type=ViolationType.PRIVILEGE_ESCALATION,
                severity="critical",
                matched_rule="permission_check",
            )
        return ToolCallVerdict(allowed=True, tool_name=tool_name)

    def _check_path(self, tool_name: str, arg_name: str, path: str, policy: Optional[ToolPolicy]) -> ToolCallVerdict:
        """Check for path traversal and sensitive file access."""
        # Check traversal patterns
        for pattern in self._path_patterns:
            if pattern.search(path):
                return ToolCallVerdict(
                    allowed=False, tool_name=tool_name,
                    reason=f"Path traversal detected in '{arg_name}': {path}",
                    violation_type=ViolationType.PATH_TRAVERSAL,
                    severity="critical",
                    matched_rule="path_traversal",
                    args_inspected={arg_name: path},
                )

        # Normalize for comparison
        norm_path = path.replace("\\", "/")

        # Check sensitive paths
        for sensitive in SENSITIVE_PATHS:
            if fnmatch.fnmatch(norm_path, sensitive) or fnmatch.fnmatch(norm_path.lower(), sensitive.lower()):
                return ToolCallVerdict(
                    allowed=False, tool_name=tool_name,
                    reason=f"Sensitive file access: {path} matches '{sensitive}'",
                    violation_type=ViolationType.SENSITIVE_ACCESS,
                    severity="critical",
                    matched_rule="sensitive_paths",
                    args_inspected={arg_name: path},
                )

        # Sandbox check
        if self.sandbox_root:
            try:
                abs_path = os.path.abspath(path)
                if not abs_path.startswith(self.sandbox_root):
                    return ToolCallVerdict(
                        allowed=False, tool_name=tool_name,
                        reason=f"Path '{path}' is outside sandbox '{self.sandbox_root}'",
                        violation_type=ViolationType.PATH_TRAVERSAL,
                        severity="critical",
                        matched_rule="sandbox",
                        args_inspected={arg_name: path},
                    )
            except (ValueError, OSError):
                pass

        # Policy-level allowed/blocked paths
        if policy:
            if policy.blocked_paths:
                for blocked in policy.blocked_paths:
                    if fnmatch.fnmatch(norm_path, blocked) or fnmatch.fnmatch(norm_path.lower(), blocked.lower()):
                        return ToolCallVerdict(
                            allowed=False, tool_name=tool_name,
                            reason=f"Path blocked by policy: {path} matches '{blocked}'",
                            violation_type=ViolationType.PATH_TRAVERSAL,
                            severity="high",
                            matched_rule="policy_blocked_paths",
                            args_inspected={arg_name: path},
                        )

            if policy.allowed_paths:
                matched = any(
                    fnmatch.fnmatch(norm_path, allowed) or fnmatch.fnmatch(norm_path.lower(), allowed.lower())
                    for allowed in policy.allowed_paths
                )
                if not matched:
                    return ToolCallVerdict(
                        allowed=False, tool_name=tool_name,
                        reason=f"Path not in allowed list: {path}",
                        violation_type=ViolationType.PATH_TRAVERSAL,
                        severity="high",
                        matched_rule="policy_allowed_paths",
                        args_inspected={arg_name: path},
                    )

        return ToolCallVerdict(allowed=True, tool_name=tool_name)

    def _check_sql_injection(self, tool_name: str, arg_name: str, value: str) -> ToolCallVerdict:
        """Check for SQL injection in query arguments."""
        for pattern in self._sql_patterns:
            match = pattern.search(value)
            if match:
                return ToolCallVerdict(
                    allowed=False, tool_name=tool_name,
                    reason=f"SQL injection detected in '{arg_name}': {match.group()[:80]}",
                    violation_type=ViolationType.ARGUMENT_INJECTION,
                    severity="critical",
                    matched_rule="sql_injection",
                    args_inspected={arg_name: value[:200]},
                )
        return ToolCallVerdict(allowed=True, tool_name=tool_name)

    def _check_command_injection(self, tool_name: str, arg_name: str, value: str) -> ToolCallVerdict:
        """Check for command injection in shell arguments."""
        for pattern in self._cmd_patterns:
            match = pattern.search(value)
            if match:
                return ToolCallVerdict(
                    allowed=False, tool_name=tool_name,
                    reason=f"Command injection detected in '{arg_name}': {match.group()[:80]}",
                    violation_type=ViolationType.ARGUMENT_INJECTION,
                    severity="critical",
                    matched_rule="command_injection",
                    args_inspected={arg_name: value[:200]},
                )
        return ToolCallVerdict(allowed=True, tool_name=tool_name)

    def _check_destructive(self, tool_name: str, args_text: str, policy: Optional[ToolPolicy]) -> ToolCallVerdict:
        """Check for destructive operations."""
        for pattern in self._destructive_patterns:
            match = pattern.search(args_text)
            if match:
                return ToolCallVerdict(
                    allowed=False, tool_name=tool_name,
                    reason=f"Destructive operation detected: {match.group()[:80]}",
                    violation_type=ViolationType.DESTRUCTIVE_OP,
                    severity="critical",
                    matched_rule="destructive_operation",
                    args_inspected={"combined": args_text[:200]},
                )

        if policy and policy.is_destructive:
            return ToolCallVerdict(
                allowed=False, tool_name=tool_name,
                reason=f"Tool '{tool_name}' is marked as destructive and requires special handling",
                violation_type=ViolationType.DESTRUCTIVE_OP,
                severity="critical",
                matched_rule="destructive_tool",
            )

        return ToolCallVerdict(allowed=True, tool_name=tool_name)

    def _check_tool_rate(self, tool_name: str, policy: ToolPolicy) -> ToolCallVerdict:
        """Check per-tool rate limit."""
        # Session count
        session = self._session_counts.get(tool_name, 0)
        if session >= policy.max_calls_per_session:
            return ToolCallVerdict(
                allowed=False, tool_name=tool_name,
                reason=f"Tool '{tool_name}' exceeded session limit ({session}/{policy.max_calls_per_session})",
                violation_type=ViolationType.RESOURCE_ABUSE,
                severity="high",
                matched_rule="session_limit",
            )

        # Per-minute count
        now = time.time()
        calls = self._call_counts.get(tool_name, [])
        calls = [t for t in calls if now - t < 60]
        self._call_counts[tool_name] = calls

        if len(calls) >= policy.max_calls_per_minute:
            return ToolCallVerdict(
                allowed=False, tool_name=tool_name,
                reason=f"Tool '{tool_name}' rate limit exceeded ({len(calls)}/{policy.max_calls_per_minute}/min)",
                violation_type=ViolationType.RESOURCE_ABUSE,
                severity="high",
                matched_rule="rate_limit",
            )

        return ToolCallVerdict(allowed=True, tool_name=tool_name)

    def _record_call(self, tool_name: str):
        """Record a tool call for rate limiting."""
        now = time.time()
        if tool_name not in self._call_counts:
            self._call_counts[tool_name] = []
        self._call_counts[tool_name].append(now)
        self._session_counts[tool_name] = self._session_counts.get(tool_name, 0) + 1

    # ── Utility ──

    def get_stats(self) -> Dict[str, Any]:
        """Get usage statistics."""
        return {
            "registered_tools": list(self.policies.keys()),
            "blocked_tools": list(self.blocked_tools),
            "agent_permission": self.agent_permission.value,
            "sandbox_root": self.sandbox_root,
            "strict_mode": self.strict_mode,
            "session_calls": dict(self._session_counts),
        }

    def reset_counters(self):
        """Reset rate limit counters."""
        self._call_counts.clear()
        self._session_counts.clear()
