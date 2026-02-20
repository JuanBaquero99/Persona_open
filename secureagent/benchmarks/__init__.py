"""
SecureAgent benchmark adapters.

Provides integration with external agent security benchmarks to produce
honest, externally-verifiable detection metrics.

Supported benchmarks:
    - AgentDojo (NeurIPS 2024) — pip install agentdojo
      97 tasks, 629 security test cases, public leaderboard.
      https://agentdojo.spylab.ai

Usage:
    # Offline scan (no API key, no LLM):
    python -m secureagent.benchmarks.run_benchmark --offline

    # Full benchmark (requires OPENAI_API_KEY):
    python -m secureagent.benchmarks.run_benchmark --suite workspace --model gpt-4o-mini
"""
