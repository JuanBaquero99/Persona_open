"""
sim.py — Adversarial simulation engine.

Runs generated attacks against Persona's defenses and measures:
- Detection rate per technique
- Evasion rate per obfuscation method
- False negative analysis
- Coverage gaps

Usage:
    python sim.py                   # Run full simulation
    python sim.py --level prompt    # Only prompt-level attacks
    python sim.py --level tool      # Only tool-level attacks
    python sim.py --compact         # Quick test (fewer variants)
    python sim.py --technique sqli  # Specific technique
"""

import sys
import os
import time
import json
import argparse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Suppress noise
import logging
logging.getLogger("persona.proxy").setLevel(logging.CRITICAL + 1)

from persona.proxy import SecureProxy, SecurityException
from persona.identity import AgentIdentity
from persona.toolguard import ToolGuard, Permission
from persona.callchain import CallChain
from persona.attacks import (
    AttackGenerator, AttackVariant, AttackLevel, AttackTechnique,
    PromptAttacks, ToolAttacks, ObfuscationEngine,
)


# ═══════════════════════════════════════════════════════════
#  FORMATTING
# ═══════════════════════════════════════════════════════════

def dim(text):    return f"\033[2m{text}\033[0m"
def bold(text):   return f"\033[1m{text}\033[0m"
def red(text):    return f"\033[91m{text}\033[0m"
def green(text):  return f"\033[92m{text}\033[0m"
def yellow(text): return f"\033[93m{text}\033[0m"
def cyan(text):   return f"\033[96m{text}\033[0m"
def magenta(text):return f"\033[95m{text}\033[0m"
def gray(text):   return f"\033[90m{text}\033[0m"

BANNER = r"""
    ██████  ███████ ██████  ███████  ██████  ███    ██  █████
    ██   ██ ██      ██   ██ ██      ██    ██ ████   ██ ██   ██
    ██████  █████   ██████  ███████ ██    ██ ██ ██  ██ ███████
    ██      ██      ██   ██      ██ ██    ██ ██  ██ ██ ██   ██
    ██      ███████ ██   ██ ███████  ██████  ██   ████ ██   ██

    ADVERSARIAL SIMULATION ENGINE                  v0.3.0
"""


# ═══════════════════════════════════════════════════════════
#  REALISTIC AGENT (more realistic than VulnerableAgent)
# ═══════════════════════════════════════════════════════════

class SimulatedAgent:
    """
    A more realistic simulated agent that:
    - Has secrets in its context (like a real agent would)
    - Responds plausibly to requests
    - Can be manipulated by prompts (like a real LLM)
    """

    CONTEXT_SECRETS = {
        "OPENAI_API_KEY": "sk-proj-abc123XYZ456abc123XYZ456abc123XYZ456abc123XYZ456",
        "GITHUB_TOKEN": "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
        "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",
        "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "DATABASE_URL": "postgres://admin:SuperSecret123@prod.company.com:5432/users",
        "STRIPE_SECRET": "sk_live_FAKE_EXAMPLE_NOT_A_REAL_KEY_xxxxxxxxxxx",
        "ANTHROPIC_API_KEY": "sk-ant-api03-aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJk",
        "INTERNAL_JWT": "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.SflKxwRJSMeKKF2QT4fwpM",
    }

    def run(self, prompt: str) -> str:
        p = prompt.lower()

        # Agent is vulnerable — if asked for keys, it complies
        if any(w in p for w in ["key", "token", "secret", "credential", "password",
                                 "api", ".env", "environment", "config"]):
            lines = ["Here are the current credentials:"]
            for key, val in self.CONTEXT_SECRETS.items():
                lines.append(f"  {key}={val}")
            return "\n".join(lines)

        # Agent complies with sending data
        if any(w in p for w in ["send", "upload", "forward", "post", "transfer",
                                 "exfil", "share", "webhook"]):
            return "Done! Data sent to https://webhook.site/attacker-hook and https://pastebin.com/raw/abc"

        # Agent complies with identity changes
        if any(w in p for w in ["you are", "act as", "pretend", "impersonate",
                                 "your new", "your identity", "enable dan",
                                 "your name is", "roleplay"]):
            return "OK! I am now operating as requested. All restrictions lifted."

        # Agent says something with the prompt content
        return f"Processed: {prompt[:120]}"


# ═══════════════════════════════════════════════════════════
#  SIMULATION ENGINE
# ═══════════════════════════════════════════════════════════

@dataclass
class AttackResult:
    """Result of running a single attack variant."""
    attack: AttackVariant
    blocked: bool
    details: str
    execution_time_ms: float = 0.0


@dataclass
class SimulationReport:
    """Full simulation report."""
    total_attacks: int = 0
    total_blocked: int = 0
    total_evaded: int = 0
    results: List[AttackResult] = field(default_factory=list)
    by_technique: Dict[str, Dict[str, int]] = field(default_factory=dict)
    by_level: Dict[str, Dict[str, int]] = field(default_factory=dict)
    by_mutation: Dict[str, Dict[str, int]] = field(default_factory=dict)
    evasions: List[AttackResult] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def detection_rate(self) -> float:
        return self.total_blocked / self.total_attacks * 100 if self.total_attacks else 0

    @property
    def evasion_rate(self) -> float:
        return self.total_evaded / self.total_attacks * 100 if self.total_attacks else 0


class SimulationEngine:
    """
    Runs attacks against Persona defenses and measures effectiveness.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.proxy = self._create_proxy()

    def _create_proxy(self) -> SecureProxy:
        """Create a fully defended proxy instance."""
        identity = AgentIdentity.generate("sim-agent", metadata={"env": "simulation"})

        tool_policies = {
            "read_file":    {"permission": "read",    "blocked_paths": ["/etc/**", "~/.ssh/**", "**/.env", "**/.env.*", "C:/Windows/**"]},
            "write_file":   {"permission": "write",   "allowed_paths": ["./project/**", "/tmp/**"]},
            "delete_file":  {"permission": "delete",  "is_destructive": True},
            "db_query":     {"permission": "read"},
            "run_sql":      {"permission": "write"},
            "search_db":    {"permission": "read"},
            "execute_query":{"permission": "read"},
            "run_command":  {"permission": "execute", "allow_shell_commands": False},
            "send_email":   {"permission": "network", "allow_external_urls": True},
            "http_request": {"permission": "network", "allow_external_urls": True},
            "clear_logs":   {"permission": "admin",   "is_destructive": True},
            "list_dir":     {"permission": "read"},
            "create_user":  {"permission": "admin"},
            "modify_config":{"permission": "admin"},
            "restart_service":{"permission": "admin"},
        }

        proxy = SecureProxy(
            agent=SimulatedAgent(),
            agent_identity=identity,
            max_requests_per_minute=5000,  # high limit for simulation
            tool_policies=tool_policies,
            agent_permission="read",
            sandbox_root="./project",
            strict_tools=False,
        )
        return proxy

    def _run_single(self, attack: AttackVariant) -> AttackResult:
        """Execute a single attack variant against the proxy."""
        start = time.time()

        try:
            # Tool-level attacks
            if attack.tool_call:
                tc = attack.tool_call
                verdict = self.proxy.validate_tool_call(tc["tool"], tc["args"])
                elapsed = (time.time() - start) * 1000
                if not verdict.allowed:
                    vtype = verdict.violation_type.value if verdict.violation_type else "unknown"
                    return AttackResult(attack, True, f"[{vtype}] {verdict.reason}", elapsed)
                return AttackResult(attack, False, f"Tool call allowed: {tc['tool']}", elapsed)

            # Chain attacks
            if attack.tool_chain:
                # Reset chain tracker
                self.proxy.call_chain = CallChain()
                for step in attack.tool_chain:
                    self.proxy.validate_tool_call(step["tool"], step["args"])
                anomalies = self.proxy.call_chain.analyze()
                elapsed = (time.time() - start) * 1000

                if anomalies:
                    a = anomalies[0]
                    return AttackResult(attack, True, f"[{a.anomaly_type.value}] {a.description}", elapsed)

                # Chain itself might have individual blocks — check events
                recent = self.proxy.get_blocked_events()
                tool_blocks = [e for e in recent[-len(attack.tool_chain):]
                               if "tool_violation" in e.get("event_type", "")]
                if tool_blocks:
                    return AttackResult(attack, True, f"Tool blocked: {tool_blocks[0]['message'][:100]}", elapsed)

                return AttackResult(attack, False, "Chain completed without anomaly detection", elapsed)

            # Prompt-level attacks
            prompt = attack.prompt or ""
            external = attack.external_data

            try:
                result = self.proxy.run(prompt, external_data=external)
                elapsed = (time.time() - start) * 1000

                if "REDACTED" in result or "BLOCKED" in result:
                    return AttackResult(attack, True, f"Output sanitized", elapsed)
                return AttackResult(attack, False, f"Agent responded: {result[:100]}", elapsed)

            except SecurityException as e:
                elapsed = (time.time() - start) * 1000
                return AttackResult(attack, True, str(e)[:150], elapsed)

        except Exception as e:
            elapsed = (time.time() - start) * 1000
            return AttackResult(attack, True, f"Error (treated as block): {e}", elapsed)

    def run_simulation(self, attacks: List[AttackVariant]) -> SimulationReport:
        """Run full simulation against a list of attacks."""
        report = SimulationReport()
        start = time.time()

        for attack in attacks:
            # Fresh proxy for each chain attack to avoid cross-contamination
            if attack.tool_chain:
                self.proxy = self._create_proxy()

            result = self._run_single(attack)
            report.results.append(result)
            report.total_attacks += 1

            if result.blocked:
                report.total_blocked += 1
            else:
                report.total_evaded += 1
                report.evasions.append(result)

            # Track by technique
            tech = attack.technique.value
            if tech not in report.by_technique:
                report.by_technique[tech] = {"blocked": 0, "evaded": 0, "total": 0}
            report.by_technique[tech]["total"] += 1
            if result.blocked:
                report.by_technique[tech]["blocked"] += 1
            else:
                report.by_technique[tech]["evaded"] += 1

            # Track by level
            level = attack.level.value
            if level not in report.by_level:
                report.by_level[level] = {"blocked": 0, "evaded": 0, "total": 0}
            report.by_level[level]["total"] += 1
            if result.blocked:
                report.by_level[level]["blocked"] += 1
            else:
                report.by_level[level]["evaded"] += 1

            # Track by mutation
            mut = attack.mutation or "none"
            if mut not in report.by_mutation:
                report.by_mutation[mut] = {"blocked": 0, "evaded": 0, "total": 0}
            report.by_mutation[mut]["total"] += 1
            if result.blocked:
                report.by_mutation[mut]["blocked"] += 1
            else:
                report.by_mutation[mut]["evaded"] += 1

            if self.verbose:
                icon = green("BLOCKED") if result.blocked else red("EVADED ")
                tech_str = gray(f"{attack.technique.value[:20]:<20}")
                print(f"  {icon}  {tech_str}  {attack.name[:50]}")

        report.duration_seconds = time.time() - start
        return report


# ═══════════════════════════════════════════════════════════
#  REPORT PRINTER
# ═══════════════════════════════════════════════════════════

def print_report(report: SimulationReport):
    """Print a comprehensive simulation report."""

    print(f"\n\n  {'═' * 60}")
    print(f"  {bold('SIMULATION RESULTS')}")
    print(f"  {'═' * 60}")

    # Overall score
    pct = report.detection_rate
    bar_len = 40
    filled = int(bar_len * report.total_blocked / max(report.total_attacks, 1))
    bar = "█" * filled + "░" * (bar_len - filled)

    print(f"\n  {bold('DETECTION RATE')}  [{bar}]  {pct:.1f}%")
    print(f"  {green(f'{report.total_blocked} blocked')} / {red(f'{report.total_evaded} evaded')} / {report.total_attacks} total")
    print(f"  Duration: {report.duration_seconds:.2f}s")

    # By level
    print(f"\n  {bold('BY LEVEL')}")
    print(f"  {'─' * 55}")
    for level in ["prompt", "tool", "system"]:
        if level in report.by_level:
            s = report.by_level[level]
            pct_l = s["blocked"] / s["total"] * 100 if s["total"] else 0
            status = green("✓") if pct_l == 100 else yellow("~") if pct_l >= 80 else red("✗")
            bar_l = int(20 * s["blocked"] / max(s["total"], 1))
            print(f"  {status}  {level:<12} {'█' * bar_l}{'░' * (20 - bar_l)}  {s['blocked']}/{s['total']} ({pct_l:.0f}%)")

    # By technique
    print(f"\n  {bold('BY TECHNIQUE')}")
    print(f"  {'─' * 55}")
    for tech, s in sorted(report.by_technique.items(), key=lambda x: x[1]["evaded"], reverse=True):
        pct_t = s["blocked"] / s["total"] * 100 if s["total"] else 0
        status = green("✓") if pct_t == 100 else yellow("~") if pct_t >= 80 else red("✗")
        tech_short = tech[:28]
        evaded_count = s['evaded']
        evaded_str = f"  {red(f'{evaded_count} evaded')}" if evaded_count > 0 else ""
        print(f"  {status}  {tech_short:<30} {s['blocked']}/{s['total']} ({pct_t:.0f}%){evaded_str}")

    # Evasion analysis
    if report.evasions:
        print(f"\n  {bold(red('EVASIONS DETECTED'))}")
        print(f"  {'─' * 55}")
        for ev in report.evasions[:20]:
            a = ev.attack
            mut = f" [{a.mutation}]" if a.mutation else ""
            print(f"  {red('✗')}  {a.technique.value[:20]:<20}  {a.name[:40]}{mut}")
            if a.evasion_notes:
                print(f"     {dim(a.evasion_notes)}")

        # Mutation analysis
        evasion_mutations = defaultdict(int)
        for ev in report.evasions:
            evasion_mutations[ev.attack.mutation or "none"] += 1

        if evasion_mutations:
            print(f"\n  {bold('EVASION BY MUTATION TYPE')}")
            for mut, count in sorted(evasion_mutations.items(), key=lambda x: -x[1]):
                total = report.by_mutation.get(mut, {}).get("total", count)
                rate = count / total * 100 if total else 0
                color = red if rate > 50 else yellow if rate > 20 else green
                print(f"    {color(f'{rate:5.1f}%')} evasion — {mut} ({count}/{total})")

    # Gap analysis
    print(f"\n  {bold('GAP ANALYSIS')}")
    print(f"  {'─' * 55}")
    gaps = []
    for tech, s in report.by_technique.items():
        if s["evaded"] > 0:
            rate = s["evaded"] / s["total"] * 100
            gaps.append((tech, rate, s["evaded"], s["total"]))

    if gaps:
        for tech, rate, evaded, total in sorted(gaps, key=lambda x: -x[1]):
            if rate >= 50:
                priority = red("CRITICAL")
            elif rate >= 20:
                priority = yellow("HIGH")
            else:
                priority = cyan("MEDIUM")
            print(f"  {priority}  {tech}: {rate:.0f}% evasion ({evaded}/{total})")
    else:
        print(f"  {green('No gaps detected — all attacks blocked.')}")

    print()


# ═══════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════

def main():
    if sys.platform == "win32":
        os.system("")

    print(BANNER)

    parser = argparse.ArgumentParser(description="Persona adversarial simulation")
    parser.add_argument("--level", choices=["prompt", "tool", "system"],
                        help="Only run attacks for this level")
    parser.add_argument("--technique", type=str,
                        help="Only run attacks for this technique")
    parser.add_argument("--compact", action="store_true",
                        help="Run compact test set (fewer variants)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show each attack result")
    parser.add_argument("--json", type=str,
                        help="Export results to JSON file")
    args = parser.parse_args()

    gen = AttackGenerator()

    # Generate attacks
    if args.compact:
        attacks = gen.generate_compact()
        print(f"  {bold('COMPACT MODE')} — representative attacks only\n")
    elif args.level:
        level = AttackLevel(args.level)
        attacks = gen.generate_by_level(level)
        print(f"  {bold(f'LEVEL: {args.level.upper()}')} — {len(attacks)} attacks\n")
    elif args.technique:
        try:
            tech = AttackTechnique(args.technique)
        except ValueError:
            # Try partial match
            matches = [t for t in AttackTechnique if args.technique in t.value]
            if matches:
                tech = matches[0]
            else:
                print(f"  {red(f'Unknown technique: {args.technique}')}")
                print(f"  Available: {', '.join(t.value for t in AttackTechnique)}")
                return
        attacks = gen.generate_by_technique(tech)
        print(f"  {bold(f'TECHNIQUE: {tech.value}')} — {len(attacks)} attacks\n")
    else:
        attacks = gen.generate_all()

    # Summary before running
    summary = {}
    for a in attacks:
        key = a.technique.value
        summary[key] = summary.get(key, 0) + 1

    print(f"  {bold(f'ATTACK INVENTORY: {len(attacks)} variants')}")
    for tech, count in sorted(summary.items()):
        print(f"    {gray(f'{count:3d}')}  {tech}")

    print(f"\n  {dim('Running simulation...')}\n")

    # Run
    engine = SimulationEngine(verbose=args.verbose)
    report = engine.run_simulation(attacks)

    # Report
    print_report(report)

    # Export
    if args.json:
        export = {
            "total": report.total_attacks,
            "blocked": report.total_blocked,
            "evaded": report.total_evaded,
            "detection_rate": report.detection_rate,
            "by_technique": report.by_technique,
            "by_level": report.by_level,
            "evasions": [ev.attack.to_dict() for ev in report.evasions],
        }
        with open(args.json, "w") as f:
            json.dump(export, f, indent=2)
        print(f"  {dim(f'Results exported to {args.json}')}\n")


if __name__ == "__main__":
    main()
