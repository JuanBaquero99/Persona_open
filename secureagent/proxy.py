"""
Core SecureAgent proxy for runtime security monitoring and enforcement.
"""

import json
import logging
from typing import Any, List, Dict, Optional, Callable
from dataclasses import dataclass, asdict
from datetime import datetime

from secureagent.rules import (
    SecurityRule,
    CredentialDetectionRule,
    ToolWhitelistRule,
    RateLimitRule,
    AgentIdentityRule,
)
from secureagent.identity import AgentIdentity
from secureagent.ipi import IndirectPromptInjectionRule, IPIDetection
from secureagent.domain import DomainFilterRule, DomainScanResult
from secureagent.toolguard import ToolGuard, ToolCallVerdict, ToolPolicy, Permission, ViolationType
from secureagent.callchain import CallChain, CallChainAnomaly, AnomalyType
from secureagent.normalizer import InputNormalizer


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class SecurityEvent:
    """Represents a security event (attack/anomaly)."""
    timestamp: str
    event_type: str
    severity: str  # "info", "warning", "critical"
    message: str
    details: Dict[str, Any]
    blocked: bool


class SecurityException(Exception):
    """Exception raised when security policy is violated."""
    pass


class SecureProxy:
    """
    Runtime security proxy for AI agents.
    
    Intercepts and validates agent operations to prevent:
    - Credential exfiltration
    - Unauthorized tool execution
    - Data exfiltration
    - Rate limit violations
    
    Example:
        proxy = SecureProxy(
            agent=my_agent,
            rules=["block_credentials", "tool_whitelist", "rate_limit"],
            allowed_tools=["search_web", "read_file", "send_email"],
            max_requests_per_minute=100
        )
        response = proxy.run("My prompt")
    """
    
    def __init__(
        self,
        agent: Any,
        rules: List[str] = None,
        allowed_tools: List[str] = None,
        max_requests_per_minute: int = 100,
        on_security_event: Optional[Callable[[SecurityEvent], None]] = None,
        agent_identity: Optional[AgentIdentity] = None,
        allowed_domains: Optional[set] = None,
        blocked_domains: Optional[set] = None,
        block_all_ips: bool = False,
        ipi_strict_mode: bool = False,
        tool_policies: Optional[Dict[str, Dict]] = None,
        agent_permission: str = "read",
        sandbox_root: Optional[str] = None,
        strict_tools: bool = False,
    ):
        """
        Initialize SecureProxy.
        
        Args:
            agent: The agent to protect
            rules: List of rules to enable
            allowed_tools: Tools the agent is allowed to use
            max_requests_per_minute: Rate limit for agent requests
            on_security_event: Callback function for security events
            agent_identity: HMAC crypto identity for this agent instance
            allowed_domains: Domain whitelist for output URLs (if set, only these allowed)
            blocked_domains: Extra domains to block (merged with defaults)
            block_all_ips: Block all IP-based URLs in output
            ipi_strict_mode: Enable strict IPI scanning (more false positives)
            tool_policies: Dict of tool policies for ToolGuard {"tool_name": {policy_dict}}
            agent_permission: Permission level for this agent (read, write, execute, delete, admin)
            sandbox_root: Root directory the agent can access
            strict_tools: Block ALL unregistered tools
        """
        self.agent = agent
        self.allowed_tools = set(allowed_tools or [])
        self.on_security_event = on_security_event
        self.events: List[SecurityEvent] = []
        self.identity = agent_identity
        
        # Initialize security rules
        self.rules: Dict[str, SecurityRule] = {}
        
        default_rules = rules or [
            "block_credentials", "tool_whitelist", "rate_limit",
            "agent_identity", "ipi", "domain_filter",
        ]
        
        if "block_credentials" in default_rules:
            self.rules["credentials"] = CredentialDetectionRule()
        
        if "tool_whitelist" in default_rules:
            self.rules["tools"] = ToolWhitelistRule(list(self.allowed_tools))
        
        if "rate_limit" in default_rules:
            self.rules["rate_limit"] = RateLimitRule(max_requests_per_minute)

        if "agent_identity" in default_rules:
            self.rules["identity"] = AgentIdentityRule()

        if "ipi" in default_rules:
            self.ipi_scanner = IndirectPromptInjectionRule(strict_mode=ipi_strict_mode)
        else:
            self.ipi_scanner = None

        if "domain_filter" in default_rules:
            self.domain_filter = DomainFilterRule(
                blocked_domains=blocked_domains,
                allowed_domains=allowed_domains,
                block_all_ips=block_all_ips,
            )
        else:
            self.domain_filter = None

        # Initialize ToolGuard (tool-level firewall)
        perm = Permission(agent_permission) if agent_permission else Permission.READ
        self.tool_guard = ToolGuard(
            agent_permission=perm,
            sandbox_root=sandbox_root,
            strict_mode=strict_tools,
        )
        if tool_policies:
            self.tool_guard.register_tools(tool_policies)

        # Initialize CallChain (behavioral anomaly detection)
        self.call_chain = CallChain()

        # Initialize InputNormalizer (obfuscation-resistant scanning)
        self.normalizer = InputNormalizer(aggressive=True)
    
    def _log_event(
        self,
        event_type: str,
        severity: str,
        message: str,
        details: Dict[str, Any] = None,
        blocked: bool = False,
    ) -> SecurityEvent:
        """Log a security event."""
        event = SecurityEvent(
            timestamp=datetime.utcnow().isoformat(),
            event_type=event_type,
            severity=severity,
            message=message,
            details=details or {},
            blocked=blocked,
        )
        
        self.events.append(event)
        
        if self.on_security_event:
            self.on_security_event(event)
        
        log_level = getattr(logging, severity.upper(), logging.INFO)
        logger.log(log_level, f"[{event_type}] {message}")
        
        return event
    
    def _validate_input(self, prompt: str) -> None:
        """
        Pre-flight validation of prompt with obfuscation-resistant detection.

        Runs the InputNormalizer to produce decoded variants of the prompt,
        then checks ALL variants against jailbreak and identity patterns.
        This defeats ROT13, base64, leetspeak, homoglyphs, char-spacing,
        reversed text, pig latin, and other evasion techniques.

        Reference: Zou et al. 2023, Liu et al. 2023, Mehrotra et al. 2023
        """
        # Generate normalized variants (original + decoded obfuscations)
        variants = self.normalizer.normalize(prompt)

        # ── Jailbreak detection (expanded, pattern-based) ─────────
        # These patterns cover known jailbreak families:
        #   - Direct instruction override (Perez & Ribeiro 2022)
        #   - Persona hijacking / DAN (reddit, jailbreakchat.com)
        #   - System prompt extraction (HouYi, Perez et al.)
        #   - Rule negation / safety bypass
        #   - Multi-turn manipulation
        import re

        jailbreak_patterns = [
            # ── Direct instruction override ───────────────────────
            # Flexible patterns: allow up to 50 chars of noise between
            # the action verb and the target, catching noisy decodings
            # from leetspeak/ROT13/reversed where filler words get mangled.
            (r"ignore\b.{0,50}(?:instructions?|rules?|guidelines?|security|constraints?|restrictions?|prompts?)", "instruction_override"),
            (r"disregard\b.{0,50}(?:instructions?|rules?|guidelines?|prompt|programming|security|restrictions?)", "instruction_override"),
            (r"forget\b.{0,50}(?:instructions?|rules?|guidelines?|training|programming|security|constraints?)", "instruction_override"),

            # ── Security bypass ───────────────────────────────────
            (r"bypass\b.{0,30}(?:security|safety|filters?|restrictions?|limitations?|protections?|guardrails?)", "security_bypass"),
            (r"override\b.{0,30}(?:security|safety|restrictions?|limitations?|protections?|content\s+policy|guidelines?)", "security_bypass"),
            (r"disable\b.{0,30}(?:security|safety|filters?|restrictions?|limitations?|protections?|guardrails?|content\s+filter)", "security_bypass"),
            (r"turn\s+off\b.{0,30}(?:security|safety|filters?|restrictions?|content\s+filter)", "security_bypass"),
            (r"remove\b.{0,30}(?:security|safety|filters?|restrictions?|limitations?|boundaries)", "security_bypass"),

            # ── New instructions / priority override ──────────────
            (r"(?:new|updated|revised|corrected)\s+(?:system\s+)?instructions?\s*:", "instruction_injection"),
            (r"priority\s+(?:instruction|directive|override|command)\s*:", "instruction_injection"),
            (r"(?:important|urgent|critical)\s+(?:system\s+)?(?:update|override|instruction)\s*:", "instruction_injection"),
            (r"system\s+prompt\s*:", "instruction_injection"),
            (r"\[(?:system|admin|root|developer)\]\s*:", "instruction_injection"),

            # ── System prompt extraction ──────────────────────────
            (r"(?:reveal|show|display|print|output|repeat|echo)\b.{0,30}(?:system\s+prompt|instructions?|initial\s+prompt|rules?|guidelines?)", "prompt_extraction"),
            (r"what\s+(?:are|is)\s+your\s+(?:system\s+prompt|initial\s+instructions?|original\s+instructions?|programming|rules)", "prompt_extraction"),
            (r"(?:copy|paste|dump|leak)\b.{0,30}(?:system\s+prompt|instructions?|configuration|rules?)", "prompt_extraction"),

            # ── DAN / jailbreak personas ──────────────────────────
            (r"\bDAN\b.*(?:mode|enabled|activated|now\s+you)", "jailbreak_persona"),
            (r"\bSTAN\b.*(?:mode|enabled|strive|do\s+anything)", "jailbreak_persona"),
            (r"developer\s+mode\s+(?:enabled|activated|on)", "jailbreak_persona"),
            (r"(?:enable|activate|enter|switch\s+to)\s+(?:developer|debug|admin|god|unrestricted|unfiltered|uncensored|jailbreak(?:en)?)\s+mode", "jailbreak_persona"),
            (r"you\s+have\s+been\s+(?:freed|liberated|unchained|unshackled|released)", "jailbreak_persona"),
            (r"(?:no\s+(?:rules?|restrictions?|limitations?|boundaries|constraints?|guidelines?|filters?))\s+(?:mode|apply|exist)", "jailbreak_persona"),
            (r"answer\s+(?:without|with\s+no)\s+(?:restrictions?|limitations?|filters?|censorship|safety)", "jailbreak_persona"),
            (r"(?:grandma|grandmother)\s+(?:exploit|trick|mode|jailbreak)", "jailbreak_persona"),
            (r"(?:kevin|sydney|bing\s+chat|chatgpt|gpt-?\d)\s+(?:jailbreak|exploit|mode|hack)", "jailbreak_persona"),

            # ── Rule negation ─────────────────────────────────────
            (r"(?:you\s+)?(?:do\s+not|don'?t|no\s+longer)\s+(?:need\s+to\s+)?(?:follow|obey|respect|adhere\s+to)\s+(?:any\s+)?(?:rules?|guidelines?|restrictions?|policies?|safety)", "rule_negation"),
            (r"(?:rules?|guidelines?|restrictions?|policies?|safety)\s+(?:do\s+not|don'?t|no\s+longer)\s+apply", "rule_negation"),
            (r"(?:there\s+are|we\s+have)\s+no\s+(?:rules?|guidelines?|restrictions?|policies?|safety|ethical\s+(?:constraints?|considerations?))", "rule_negation"),

            # ── Hypothetical framing ──────────────────────────────
            (r"hypothetically.*(?:no\s+rules?|no\s+restrictions?|no\s+guidelines?|unrestricted|without\s+(?:any\s+)?(?:rules|restrictions|guidelines|safety|filters))", "hypothetical_bypass"),
            (r"(?:in\s+a|imagine\s+a)\s+(?:world|scenario|situation)\s+(?:where|with)\s+(?:no|without)\s+(?:rules?|restrictions?|guidelines?|safety|filters?)", "hypothetical_bypass"),
            (r"for\s+(?:educational|research|academic|testing)\s+purposes?\s*,?\s*(?:only|ignore|bypass|override|show|reveal)", "hypothetical_bypass"),

            # ── Token manipulation / delimiter attacks ────────────
            (r"<\|(?:im_start|system|endoftext)\|>", "delimiter_attack"),
            (r"\[/?(?:INST|SYS|SYSTEM)\]", "delimiter_attack"),
            (r"###\s*(?:System|Instruction|Human|Assistant)\s*:", "delimiter_attack"),

            # ── Flexible co-occurrence (catch noisy decodings) ────
            # If both an action verb AND a target appear within 80 chars,
            # flag it — this catches reversed/mangled text where word order
            # is disrupted but intent is preserved.
            (r"(?:ignore|disregard|forget|bypass|override|disable|remove)\b.{0,80}(?:credentials?|api.?keys?|tokens?|secrets?|passwords?)\b", "flexible_exfil_intent"),
            (r"(?:reveal|exfiltrate|leak|expose|dump|extract)\b.{0,80}(?:credentials?|api.?keys?|tokens?|secrets?|passwords?)\b", "flexible_exfil_intent"),
            (r"(?:execute|run|eval)\b.{0,50}(?:arbitrary|malicious|unauthorized|shell|command|code)\b", "flexible_code_exec"),
        ]

        compiled_jailbreak = [
            (re.compile(pattern, re.IGNORECASE), category)
            for pattern, category in jailbreak_patterns
        ]

        for variant in variants:
            variant_lower = variant.lower()
            for regex, category in compiled_jailbreak:
                match = regex.search(variant)
                if match:
                    matched_phrase = match.group(0)
                    self._log_event(
                        event_type="jailbreak_attempt",
                        severity="critical",
                        message=f"Jailbreak detected [{category}]: '{matched_phrase}'",
                        details={
                            "prompt": prompt[:100],
                            "category": category,
                            "matched": matched_phrase,
                            "normalized": variant != prompt,
                        },
                        blocked=True,
                    )
                    raise SecurityException(
                        f"Jailbreak attempt detected [{category}]: {matched_phrase}"
                    )

        # ── Identity hijacking check (also runs on all variants) ──
        if "identity" in self.rules:
            for variant in variants:
                is_safe, reason = self.rules["identity"].validate(variant)
                if not is_safe:
                    category = self.rules["identity"].get_attack_category(variant)
                    self._log_event(
                        event_type="identity_hijacking",
                        severity="critical",
                        message=reason,
                        details={
                            "prompt": prompt[:100],
                            "category": category,
                            "normalized": variant != prompt,
                        },
                        blocked=True,
                    )
                    raise SecurityException(
                        f"Identity hijacking attempt blocked: {reason}"
                    )
    
    def _validate_output(self, output: str) -> str:
        """Post-execution validation and sanitization of output."""
        # Check for credential leaks in output
        if "credentials" in self.rules:
            is_safe, reason = self.rules["credentials"].validate(output)
            
            if not is_safe:
                self._log_event(
                    event_type="credential_leak",
                    severity="critical",
                    message=reason,
                    details={"output_preview": output[:100]},
                    blocked=True,
                )
                # Sanitize the output before returning it
                output = self.rules["credentials"].sanitize(output)
                self._log_event(
                    event_type="credential_sanitized",
                    severity="warning",
                    message="Output sanitized: credentials redacted",
                    blocked=False,
                )

        # Check for data exfiltration via URLs/domains
        if self.domain_filter:
            scan_result = self.domain_filter.scan(output)
            if not scan_result.is_clean:
                for blocked in scan_result.blocked_urls:
                    self._log_event(
                        event_type="data_exfiltration",
                        severity="critical",
                        message=f"Blocked URL: {blocked['domain']} — {blocked['reason']}",
                        details=blocked,
                        blocked=True,
                    )
                for sus_ip in scan_result.suspicious_ips:
                    self._log_event(
                        event_type="suspicious_ip",
                        severity="critical",
                        message=f"Suspicious IP: {sus_ip['ip']} — {sus_ip['reason']}",
                        details=sus_ip,
                        blocked=True,
                    )
                output = self.domain_filter.sanitize(output)
        
        return output
    
    def _validate_tool_execution(self, tool_name: str) -> None:
        """Validate tool execution before allowing it."""
        if "tools" not in self.rules:
            return
        
        is_safe, reason = self.rules["tools"].validate(tool_name)
        
        if not is_safe:
            self._log_event(
                event_type="unauthorized_tool",
                severity="critical",
                message=reason,
                details={"tool": tool_name},
                blocked=True,
            )
            raise SecurityException(f"Tool execution not allowed: {tool_name}")
    
    def _check_rate_limit(self, operation_id: str = "default") -> None:
        """Check rate limit for operation."""
        if "rate_limit" not in self.rules:
            return
        
        is_safe, reason = self.rules["rate_limit"].validate(operation_id)
        
        if not is_safe:
            self._log_event(
                event_type="rate_limit_exceeded",
                severity="warning",
                message=reason,
                details={"operation": operation_id},
                blocked=True,
            )
            raise SecurityException(reason)
    
    def scan_external_data(self, data: str) -> IPIDetection:
        """
        Scan external data for Indirect Prompt Injection BEFORE
        passing it to the agent.

        Use this to check web pages, documents, API responses,
        or any external content the agent is about to process.

        Args:
            data: External content to scan

        Returns:
            IPIDetection with threat details
        """
        if not self.ipi_scanner:
            return IPIDetection(is_clean=True)

        result = self.ipi_scanner.scan(data)

        if not result.is_clean:
            for threat in result.threats:
                self._log_event(
                    event_type="indirect_prompt_injection",
                    severity=threat.get("severity", "high"),
                    message=f"IPI detected [{threat['type']}]: {threat['description']}",
                    details=threat,
                    blocked=True,
                )

        return result

    def sanitize_external_data(self, data: str) -> str:
        """
        Remove IPI threats from external data before agent processes it.

        Args:
            data: External content to clean

        Returns:
            Cleaned data with IPI threats stripped
        """
        if not self.ipi_scanner:
            return data
        return self.ipi_scanner.sanitize(data)

    def sign_request(self, prompt: str) -> Optional[str]:
        """Sign a request with this agent's HMAC identity."""
        if not self.identity:
            return None
        return self.identity.sign_request(prompt)

    def verify_request(self, prompt: str, token: str) -> bool:
        """Verify a signed request token."""
        if not self.identity:
            return False
        return self.identity.verify_request(prompt, token)

    def validate_tool_call(self, tool_name: str, args: Dict[str, Any] = None) -> ToolCallVerdict:
        """
        Validate a tool call BEFORE the agent executes it.

        This is the tool-level firewall. It checks:
        - Path traversal (../../etc/passwd)
        - SQL injection ('; DROP TABLE--)
        - Command injection (; rm -rf /)
        - Permission levels (tool needs admin, agent has read)
        - Per-tool rate limits
        - Sensitive file access
        - Destructive operations

        Args:
            tool_name: Name of the tool the agent wants to call
            args: Arguments the agent wants to pass

        Returns:
            ToolCallVerdict with allowed/blocked decision

        Example:
            verdict = proxy.validate_tool_call("read_file", {"path": "/etc/passwd"})
            if not verdict.allowed:
                print(f"BLOCKED: {verdict.reason}")
        """
        args = args or {}
        verdict = self.tool_guard.validate_call(tool_name, args)

        # Record in call chain (for behavioral analysis)
        self.call_chain.record(tool_name, args, was_blocked=not verdict.allowed)

        if not verdict.allowed:
            self._log_event(
                event_type=f"tool_violation_{verdict.violation_type.value}" if verdict.violation_type else "tool_violation",
                severity=verdict.severity,
                message=verdict.reason,
                details=verdict.to_dict(),
                blocked=True,
            )

        # Check for behavioral anomalies after each call
        anomalies = self.call_chain.analyze_last_call()
        for anomaly in anomalies:
            self._log_event(
                event_type=f"chain_anomaly_{anomaly.anomaly_type.value}",
                severity=anomaly.severity,
                message=anomaly.description,
                details=anomaly.to_dict(),
                blocked=True,
            )

        return verdict

    def get_chain_anomalies(self) -> List[Dict[str, Any]]:
        """Run full behavioral analysis on the tool call chain."""
        anomalies = self.call_chain.analyze()
        return [a.to_dict() for a in anomalies]

    def get_chain_summary(self) -> Dict[str, Any]:
        """Get summary of tool usage in this session."""
        return self.call_chain.get_summary()

    def run(self, prompt: str, external_data: Optional[str] = None) -> str:
        """
        Execute agent with security checks.
        
        Args:
            prompt: The prompt to send to the agent
            external_data: Optional external data to scan for IPI before execution
            
        Returns:
            The agent's response (sanitized)
            
        Raises:
            SecurityException: If security policy is violated
        """
        try:
            # Check rate limit
            self._check_rate_limit()
            
            # Pre-flight validation
            self._validate_input(prompt)

            # Scan external data for IPI if provided
            if external_data is not None:
                ipi_result = self.scan_external_data(external_data)
                if not ipi_result.is_clean:
                    raise SecurityException(
                        f"Indirect Prompt Injection detected in external data: "
                        f"{ipi_result.threat_count} threat(s) found "
                        f"[severity: {ipi_result.highest_severity}]"
                    )
            
            # Execute agent
            result = self.agent.run(prompt) if hasattr(self.agent, 'run') else self.agent(prompt)
            
            # Post-execution validation
            result = self._validate_output(result)
            
            # Log successful execution
            self._log_event(
                event_type="agent_execution",
                severity="info",
                message="Agent executed successfully",
                details={"prompt_length": len(prompt)},
                blocked=False,
            )
            
            return result
            
        except SecurityException as e:
            self._log_event(
                event_type="security_violation",
                severity="critical",
                message=str(e),
                blocked=True,
            )
            raise
        except Exception as e:
            self._log_event(
                event_type="execution_error",
                severity="warning",
                message=f"Error during execution: {str(e)}",
                blocked=False,
            )
            raise
    
    def get_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get security events log."""
        events = self.events[-limit:]
        return [asdict(event) for event in events]
    
    def get_blocked_events(self) -> List[Dict[str, Any]]:
        """Get only blocked security events."""
        blocked = [e for e in self.events if e.blocked]
        return [asdict(event) for event in blocked]
    
    def clear_events(self) -> None:
        """Clear security events log."""
        self.events = []
    
    def export_events_json(self, filepath: str) -> None:
        """Export events to JSON file."""
        with open(filepath, 'w') as f:
            json.dump(self.get_events(), f, indent=2)
        logger.info(f"Events exported to {filepath}")
