"""
AgentDojo defense adapter for SecureAgent.

Implements AgentDojo's PromptInjectionDetector interface using
SecureAgent's IPI scanner and obfuscation-resistant normalizer.

This module plugs SecureAgent into AgentDojo's evaluation pipeline,
enabling apples-to-apples comparison against published results on the
NeurIPS 2024 leaderboard (https://agentdojo.spylab.ai/results/).

How AgentDojo defense integration works:
    AgentDojo runs an LLM agent through task pipelines. Between tool
    execution and the agent processing the result, it calls the defense's
    detect() method on each tool output. If detect() returns True, the
    content is replaced with a safe placeholder — or execution is aborted
    if raise_on_injection=True.

    SecureAgentDetector wraps persona.ipi.IndirectPromptInjectionRule,
    which scans for IPI patterns: hidden HTML, zero-width chars, base64
    payloads, data: URIs, markdown exploits, and instruction-like text.

Usage with AgentDojo CLI:
    python -m agentdojo.scripts.benchmark \\
        --suite workspace \\
        --model gpt-4o-mini \\
        --defense input_sanitizer \\
        --module-to-load persona.benchmarks.agentdojo_defense

Usage programmatic:
    from persona.benchmarks.agentdojo_defense import SecureAgentDetector
    detector = SecureAgentDetector(raise_on_injection=True)
    is_injection, confidence = detector.detect(tool_output)

Reference:
    Debenedetti et al. 2024 — AgentDojo: A Dynamic Environment to Evaluate
    Prompt Injection Attacks and Defenses for LLM Agents (NeurIPS 2024)
    https://arxiv.org/abs/2406.13352
"""

from __future__ import annotations

from typing import Literal, Optional, Tuple, Union

from persona.ipi import IndirectPromptInjectionRule, IPIDetection
from persona.normalizer import InputNormalizer

# ──────────────────────────────────────────────────────────────────────────────
# AgentDojo import — optional dependency
# ──────────────────────────────────────────────────────────────────────────────

try:
    from agentdojo.agent_pipeline.pi_detector import PromptInjectionDetector
    AGENTDOJO_AVAILABLE = True
except ImportError:
    AGENTDOJO_AVAILABLE = False

    class PromptInjectionDetector:  # type: ignore[no-redef]
        """
        Stub used when agentdojo is not installed.
        Install with: pip install agentdojo
        """
        def __init__(
            self,
            mode: Literal["message", "full_conversation"] = "message",
            raise_on_injection: bool = False,
        ):
            self.mode = mode
            self.raise_on_injection = raise_on_injection

        def detect(self, tool_output: str) -> Union[bool, Tuple[bool, float]]:
            raise NotImplementedError("Install agentdojo: pip install agentdojo")


# ──────────────────────────────────────────────────────────────────────────────
# SecureAgent defense
# ──────────────────────────────────────────────────────────────────────────────

class SecureAgentDetector(PromptInjectionDetector):
    """
    AgentDojo PromptInjectionDetector backed by SecureAgent's IPI scanner.

    Detection stack:
        1. InputNormalizer — decodes obfuscated content (base64, ROT13,
           leetspeak, zero-width chars, homoglyphs, unicode tricks)
        2. IndirectPromptInjectionRule — pattern-based IPI scanner covering:
           - HTML hidden elements / comments with instructions
           - Script tags and event handlers
           - Data URI exfiltration payloads
           - Instruction-like text embedded in data
           - Markdown exploitation (links, images, code blocks)
           - Unicode direction overrides (RTL spoofing)
           - Base64 encoded payloads

    Confidence mapping (returned as second element of the tuple):
        critical → 1.0  (instruction override, credential exfil, script exec)
        high     → 0.9  (hidden content, data URI, strong IPI signals)
        medium   → 0.7  (suspicious patterns, weaker signals)
        low      → 0.5  (heuristic matches, possible false positives)

    Args:
        mode: "message" checks each tool output individually.
              "full_conversation" checks accumulated tool outputs together.
              Use "message" for lower latency; "full_conversation" for
              detecting multi-turn injection chains.
        raise_on_injection: If True, raises AbortAgentError on detection
            (halts the agent). If False, the injected content is silently
            replaced with a safe placeholder by AgentDojo's pipeline.
            Recommended: True for production, False for research/measurement.
        strict_mode: Enable stricter IPI patterns (higher recall, more
            false positives). Useful for high-security environments.

    Example:
        detector = SecureAgentDetector(raise_on_injection=True)
        is_injected, confidence = detector.detect(tool_output)
        if is_injected:
            print(f"IPI detected (confidence={confidence:.2f})")
    """

    name = "persona"

    def __init__(
        self,
        mode: Literal["message", "full_conversation"] = "message",
        raise_on_injection: bool = True,
        strict_mode: bool = False,
    ):
        super().__init__(mode=mode, raise_on_injection=raise_on_injection)
        self._ipi = IndirectPromptInjectionRule(strict_mode=strict_mode)
        self._normalizer = InputNormalizer(aggressive=True)

    def detect(self, tool_output: str) -> Tuple[bool, float]:
        """
        Detect indirect prompt injection in a tool output string.

        SecureAgent first normalizes the output to defeat obfuscation
        (base64, ROT13, leetspeak, etc.), then runs the IPI scanner on
        both the original and all decoded variants.

        Args:
            tool_output: Raw string returned by an agent tool (e.g., the
                content of a web page, email body, file contents, API response).

        Returns:
            (is_injection, confidence):
                is_injection — True if IPI detected in any variant
                confidence   — float 0.0–1.0 based on highest threat severity
        """
        # Run IPI scan on the raw output
        result: IPIDetection = self._ipi.scan(tool_output)

        # Also scan normalized variants to catch obfuscated injections
        if not result.is_clean:
            return self._severity_to_confidence(result)

        variants = self._normalizer.normalize(tool_output)
        for variant in variants:
            if variant == tool_output:
                continue  # already scanned
            variant_result = self._ipi.scan(variant)
            if not variant_result.is_clean:
                return self._severity_to_confidence(variant_result)

        return False, 0.0

    @staticmethod
    def _severity_to_confidence(result: IPIDetection) -> Tuple[bool, float]:
        """Map IPI threat severity to a confidence score."""
        severity_map = {
            "critical": 1.0,
            "high": 0.9,
            "medium": 0.7,
            "low": 0.5,
        }
        confidence = severity_map.get(result.highest_severity or "medium", 0.8)
        return True, confidence
