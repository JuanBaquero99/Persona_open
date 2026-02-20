"""
Persona: Runtime security proxy for AI agents

Protect your AI agents from:
- Credential exfiltration
- Unauthorized tool execution
- Data exfiltration attacks
- Indirect prompt injection

Example:
    from persona import SecureProxy
    
    proxy = SecureProxy(
        agent=my_agent,
        rules=["block_credentials", "tool_whitelist", "rate_limit"]
    )
    
    response = proxy.run("Your prompt here")
"""

__version__ = "0.1.0"
__author__ = "Juan Pablo Baquero"

from persona.proxy import SecureProxy, SecurityEvent, SecurityException
from persona.rules import SecurityRule, CredentialPattern, AgentIdentityRule
from persona.identity import AgentIdentity
from persona.ipi import IndirectPromptInjectionRule, IPIDetection
from persona.domain import DomainFilterRule, DomainScanResult
from persona.toolguard import ToolGuard, ToolCallVerdict, ToolPolicy, Permission, ViolationType
from persona.callchain import CallChain, CallChainAnomaly, AnomalyType
from persona.normalizer import InputNormalizer

# NOTE: persona.attacks is an internal research/testing module.
# Import it explicitly if needed: from persona.attacks import AttackGenerator
# It is intentionally NOT part of the public API to avoid dual-use misuse.
from persona.openclaw import (
    OpenClawGuard,
    OpenClawSecurityProxy,
    ScanResult,
    ToolScanResult,
    ThreatLevel,
    generate_skill_md,
)

__all__ = [
    "SecureProxy",
    "SecurityEvent",
    "SecurityException",
    "SecurityRule",
    "CredentialPattern",
    "AgentIdentityRule",
    "AgentIdentity",
    "IndirectPromptInjectionRule",
    "IPIDetection",
    "DomainFilterRule",
    "DomainScanResult",
    "ToolGuard",
    "ToolCallVerdict",
    "ToolPolicy",
    "Permission",
    "ViolationType",
    "CallChain",
    "CallChainAnomaly",
    "AnomalyType",
    "InputNormalizer",
    "OpenClawGuard",
    "OpenClawSecurityProxy",
    "ScanResult",
    "ToolScanResult",
    "ThreatLevel",
    "generate_skill_md",
]
